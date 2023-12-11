import argparse, os, math, glob, logging, time
import lumina.analyzer.checker.integrity_check as integrity_check
import lumina.analyzer.checker.host_check as host_check
import lumina.analyzer.checker.gbn_check as gbn_check
import lumina.analyzer.checker.read_gbn_check as read_gbn_check
import lumina.orchestrator.host as host
import lumina.orchestrator.switch as switch
from lumina.analyzer.main import get_qp_info_list
from lumina.orchestrator.main import Orchestrator
from lumina.analyzer.counter.switch_counter import SwitchCounter
from lumina.analyzer.counter.host_counter import MLNXHostCounter, IntelHostCounter
from lumina.analyzer.pcap_processor.pcap_process import get_packet_list
from lumina.analyzer.measurer.latency_measure import LatencyMeasure
from lumina.utils.config_loggers import config_stream_handler, config_file_handler
from lumina.analyzer.packet_parser.roce_packet import TRIGGER_OOS, TRIGGER_TIMEOUT

## All logs will be logged into file LOG_FILENAME
LOG_FILENAME = "test_gbn.log"
## Results (checkers and measurements) will also be dumped into file RESULT_FILENAME
RESULT_FILENAME = "result.log"
## Max # of retries for each experiment iteration
MAX_NB_EXP_RETRIES = 3

def setup_root_logger(orchestrator):
    """ Setup the root logger for the test

    Args:
        orchestrator (Orchestrator object): Orchestrator object that contains all the configurations

    Returns:
        N/A
    """
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    config_stream_handler(root_logger)
    config_file_handler(logger=root_logger,
                        log_file=os.path.join(orchestrator.result_path, LOG_FILENAME),
                        no_format=False)

def run_traffic(orchestrator):
    """ Run the traffic and collect the results

    Args:
        orchestrator (Orchestrator object): Orchestrator object that contains all the configurations

    Returns:
        bool: True if the experiment is successful, False otherwise
    """
    orchestrator.rm_old_files()
    if orchestrator.sync_and_compile() == False:
        logging.error("Failed to sync and compile the code")
        sys.exit(-1)
    logging.info("Sync and compile completed")

    if orchestrator.generate_switch_config_file() == False:
        logging.error("Failed to generate switch configuration file")
        sys.exit(-1)

    num_repeats = orchestrator.get_num_repeats()

    for i in range(num_repeats):
        logging.info("=" * 100)
        nb_retry = 0
        iter_result = False

        while nb_retry < MAX_NB_EXP_RETRIES:
            if orchestrator.run_experiment() == False:
                logging.error("Iteration %d: Failed to complete experiment" % i)
                logging.error("Iteration %d: Rerun experiment (retry: %d)" % i, nb_retry)
                nb_retry += 1
                orchestrator.clean_up()
                time.sleep(5)
                continue

            logging.info("Iteration %d: Completed experiment" % i)
            try:
                orchestrator.clean_up()
                orchestrator.fetch_results(i)
                logging.info("Iteration %d: Fetch experiment results" % i)
                orchestrator.merge_traces(i)
                logging.info("Iteration %d: Merge the pcap files" % i)

            except:
                logging.error("Iteration %d: Result collection failed" % (i))
                logging.error("Iteration %d: Rerun experiment (retry: %d)" % (i, nb_retry))
                nb_retry += 1
                time.sleep(5)
                continue

            if orchestrator.check_integrity(i) == False:
                logging.error("Iteration %d: Integrity check failed" % (i))
                logging.error("Iteration %d: Rerun experiment (retry: %d)" % (i, nb_retry))
                nb_retry += 1
                time.sleep(5)
                continue

            iter_result = True
            break

        if iter_result is False:
            logging.error("Iteration %d: Still failed after %d retries" % (i, nb_retry))
            return False

    return True

def analyze_retrans_latency(pkt, latency_measurement, is_read, logger):
    """ Analyze the retransmission latency breakdown for an undelivered packet

    Args:
        pkt (Packet object): The undelivered packet
        latency_measurement (LatencyMeasure object): A LatencyMeasure object that can compute latency breakdown
        is_read (bool): If we use RDMA READ in this experiment
        logger (logging.Logger): A logger object

    Returns:
        N/A
    """
    # All the undelivered packets should be retransmitted in our test cases
    if latency_measurement.get_retransmit_pkt(pkt) == None:
        logger.error("\t\t No retransmit packet found for this packet")
        logger.error("\t\t It is possible that this undelivered packet is a redundant transmission")
        return

    retrans_latency = latency_measurement.get_retransmit_latency(pkt)
    if is_read == True:
        # For RDMA READ, we should always find a NACK READ request that triggers retransmission
        nack = latency_measurement.get_nack(pkt)
        if nack is not None:
            trigger = nack.get_trigger()
            if trigger == TRIGGER_OOS:
                next_delivered_pkt_delay = latency_measurement.get_qp_next_delivered_pkt_latency(pkt)
                nack_gen_latency = latency_measurement.get_nack_gen_latency(pkt)
                nack_resp_latency = latency_measurement.get_nack_resp_latency(pkt)
                logger.info("\t\t Out of sequence (OOS) triggered retransmission")
                logger.info("\t\t Retransmission latency: %fus" % (retrans_latency * 1e6))
                logger.info('\t\t Next delivered packet delay: %fus' % (next_delivered_pkt_delay * 1e6))
                logger.info("\t\t NACK READ request generation latency: %fus" % (nack_gen_latency * 1e6))
                logger.info('\t\t NACK READ request response latency: %fus' % (nack_resp_latency * 1e6))

            elif trigger == TRIGGER_TIMEOUT:
                nack_resp_latency = latency_measurement.get_nack_resp_latency(pkt)
                logger.info("\t\t Timeout triggered retransmission")
                logger.info("\t\t Retransmission latency: %fus" % (retrans_latency * 1e6))
                logger.info('\t\t NACK READ request response latency: %fus' % (nack_resp_latency * 1e6))

            else:
                logger.error("\t\t NACK READ request should be triggered by either OOS or timeout")

        else:
            nack = latency_measurement.get_qp_first_nack_before_retrans(pkt)
            if nack is None:
                logger.error("\t\t Cannot find the NACK READ request to recover this lost packet")
                return

            trigger = nack.get_trigger()
            if trigger == TRIGGER_OOS:
                logger.info("\t\t Out of sequence (OOS) triggered retransmission")
                logger.info("\t\t But the NACK READ request indicates a loss (%d) before this packet (%d)" %\
                            (nack.get_roce_pkt_seq(), pkt.get_roce_pkt_seq()))
                logger.info("\t\t Retransmission latency: %fus" % (retrans_latency * 1e6))

            elif trigger == TRIGGER_TIMEOUT:
                logger.info("\t\t Timeout triggered retransmission")
                logger.info("\t\t But the NACK READ request indicates a loss (%d) before this packet (%d)" %\
                            (nack.get_roce_pkt_seq(), pkt.get_roce_pkt_seq()))
                logger.info("\t\t Retransmission latency: %fus" % (retrans_latency * 1e6))

            else:
                logger.error("\t\t NACK READ request should be triggered by either OOS or timeout")

    else:
        # For other verbs, we can only find a NACK in case of out of sequence arriving packets
        if latency_measurement.get_nack(pkt) != None:
            # Out of sequence/NACK triggered retransmission
            next_delivered_pkt_delay = latency_measurement.get_qp_next_delivered_pkt_latency(pkt)
            nack_gen_latency = latency_measurement.get_nack_gen_latency(pkt)
            nack_resp_latency = latency_measurement.get_nack_resp_latency(pkt)

            logger.info("\t\t Out of sequence (OOS) triggered retransmission")
            logger.info("\t\t Retransmission latency: %fus" % (retrans_latency * 1e6))
            logger.info('\t\t Next delivered packet delay: %fus' % (next_delivered_pkt_delay * 1e6))
            logger.info("\t\t NACK generation latency: %fus" % (nack_gen_latency * 1e6))
            logger.info('\t\t NACK response latency: %fus' % (nack_resp_latency * 1e6))

        elif latency_measurement.get_qp_first_nack_before_retrans(pkt) != None:
            logger.info("\t\t Out of sequence (OOS) triggered retransmission")
            logger.info("\t\t But the NACK indicates a loss (%d) before this packet (%d)")
            logger.info("\t\t Retransmission latency: %fus" % (retrans_latency * 1e6))

        else:
            logger.info("\t\t Timeout triggered retransmission")
            logger.info("\t\t Retransmission latency: %fus" % (retrans_latency * 1e6))

def verify_results(orchestrator):
    """ Verify the experiment results

    Args:
        orchestrator (Orchestrator object): Orchestrator object that contains all the configurations

    Returns:
        N/A
    """
    result_dir = orchestrator.result_path
    num_repeats = orchestrator.num_repeats
    mtu = orchestrator.traffic_conf['mtu']
    msg_size = orchestrator.traffic_conf['message-size']
    num_msgs_per_qp = orchestrator.traffic_conf['num-msgs-per-qp']
    aggregate_pcap_filename = orchestrator.aggregate_pcap_filename
    port_map = {'requester': orchestrator.requester.conf['nic']['switch-port'],
                'responder': orchestrator.responder.conf['nic']['switch-port'],
                'requester-mirror': orchestrator.requester_mirror.conf['nic']['switch-port'],
                'responder-mirror': orchestrator.responder_mirror.conf['nic']['switch-port']}

    requester_ip_list = orchestrator.get_requester_ip_list()
    responder_ip_list = orchestrator.get_responder_ip_list()

    for iter in range(num_repeats):
        iter = str(iter)
        result_logger = logging.getLogger('Analysis iter %s' % (iter))
        result_logger.handlers.clear()
        config_file_handler(logger=result_logger,
                            log_file=os.path.join(result_dir, iter, RESULT_FILENAME),
                            no_format=True)
        result_logger.info("=" * 100)
        result_logger.info("Iteration %s" % iter)

        switch_msg_snapshot = os.path.join(result_dir,
                                          iter,
                                          switch.SWITCH_RESULT_DIR,
                                          switch.SWITCH_MESSAGE_SNAPSHOT)
        switch_state_snapshot = os.path.join(result_dir,
                                             iter,
                                             switch.SWITCH_RESULT_DIR,
                                             switch.SWITCH_STATE_SNAPSHOT)
        pcap_filename = os.path.join(result_dir,
                                     iter,
                                     host.PCAP_RESULT_DIR,
                                     aggregate_pcap_filename)
        requester_counter_start = os.path.join(result_dir,
                                               iter,
                                               host.RDMA_RESULT_DIR,
                                               host.REQ_START_COUNTER_FILE_NAME)
        requester_counter_finish = os.path.join(result_dir,
                                                iter,
                                                host.RDMA_RESULT_DIR,
                                                host.REQ_FINISH_COUNTER_FILE_NAME)
        responder_counter_start = os.path.join(result_dir,
                                               iter,
                                               host.RDMA_RESULT_DIR,
                                               host.RSP_START_COUNTER_FILE_NAME)
        responder_counter_finish = os.path.join(result_dir,
                                                iter,
                                                host.RDMA_RESULT_DIR,
                                                host.RSP_FINISH_COUNTER_FILE_NAME)

        switch_counter = SwitchCounter(switch_state_snapshot, port_map)

        if orchestrator.requester.is_mlnx_nic():
            requester_counter = MLNXHostCounter(requester_counter_start, requester_counter_finish)
        elif orchestrator.requester.is_intel_nic():
            requester_counter = IntelHostCounter(requester_counter_start, requester_counter_finish)
        else:
            logging.error("Unkown NIC Vendor for rdma requester.")
            requester_counter = None

        if orchestrator.responder.is_mlnx_nic():
            responder_counter = MLNXHostCounter(responder_counter_start, responder_counter_finish)
        elif orchestrator.responder.is_intel_nic():
            responder_counter = IntelHostCounter(responder_counter_start, responder_counter_finish)
        else:
            logging.error("Unkown NIC Vendor for rdma responder.")
            responder_counter = None

        qp_info_list = get_qp_info_list(switch_msg_snapshot)
        packet_list = get_packet_list(pcap_filename)

        packet_list.sort(key=lambda x:x.get_switch_seqnum())
        result_logger.info("Packet trace sorted by switch sequence number.")

        ## Do integrity check to make sure there is nothing wrong with traces and counters
        integrity_checker = integrity_check.IntegrityCheck(packet_list=packet_list,
                                                           switch_counter=switch_counter,
                                                           requester_ip_list=requester_ip_list,
                                                           responder_ip_list=responder_ip_list)
        if integrity_checker.check():
            result_logger.info("Integrity check passed")
        else:
            result_logger.error("Integrity check failed")
            continue

        ## Check host counters
        host_counter_checker = host_check.HostCounterCheck()
        if host_counter_checker.check_no_packet_loss(requester_counter, responder_counter):
            result_logger.info("Host packet discard counter check passed")
        else:
            result_logger.error("Host packet discard counter check failed")
            continue

        rdma_verb = orchestrator.traffic_conf['rdma-verb'].lower().strip()
        if rdma_verb not in host.VALID_IB_VERB_LIST_LOWER:
            logging.error("Invalid RDMA verb: %s" % rdma_verb)
            continue

        ## RDMA READ
        if rdma_verb == 'read':
            read_gbn_checker = read_gbn_check.ReadGBNCheck(packet_list=packet_list,
                                                           qp_info_list=qp_info_list,
                                                           num_msgs_per_qp=num_msgs_per_qp,
                                                           msg_size=msg_size,
                                                           mtu=mtu)
            if read_gbn_checker.check_all_qps() == True:
                result_logger.info("READ Go-Back-N state machine check passed for all qps.")
            else:
                result_logger.error("READ Go-Back-N state machine check failed")
                continue

            gbn_counter_check = read_gbn_checker.check_counters(sender_counter=responder_counter,
                                                                receiver_counter=requester_counter)
            if gbn_counter_check == True:
                result_logger.info("READ Go-Back-N counter check passed.")
            else:
                result_logger.error("READ Go-Back-N counter check failed")
                continue

        ## A mix of RDMA SEND and READ
        elif rdma_verb == 'send_read':
            num_qps_send, num_qps_read = [int(x) for x in orchestrator.traffic_conf['num-qps'].split(',')]
            send_qp_info_list = qp_info_list[0:num_qps_send]
            read_qp_info_list = qp_info_list[num_qps_send:]

            send_gbn_checker = gbn_check.GBNCheck(packet_list=packet_list,
                                                  qp_info_list=send_qp_info_list,
                                                  num_data_pkts=math.ceil(msg_size/mtu) * num_msgs_per_qp)
            read_gbn_checker = read_gbn_check.ReadGBNCheck(packet_list=packet_list,
                                                           qp_info_list=read_qp_info_list,
                                                           num_msgs_per_qp=num_msgs_per_qp,
                                                           msg_size=msg_size,
                                                           mtu=mtu)

            if send_gbn_checker.check_all_qps() == True and read_gbn_checker.check_all_qps() == True:
                result_logger.info("Go-Back-N state machine check passed for all qps.")
            else:
                result_logger.error("Go-Back-N state machine check failed")
                continue

            send_gbn_counter_check = send_gbn_checker.check_counters(sender_counter=requester_counter,
                                                                     receiver_counter=responder_counter)
            read_gbn_counter_check = read_gbn_checker.check_counters(sender_counter=responder_counter,
                                                                     receiver_counter=requester_counter)

            if send_gbn_counter_check == True and read_gbn_counter_check == True:
                result_logger.info("Go-Back-N counter check passed for all qps.")
            else:
                result_logger.error("Go-Back-N counter check failed")
                continue

        else:
            ## Check the traces and counters against the GBN state machine
            gbn_checker = gbn_check.GBNCheck(packet_list=packet_list,
                                             qp_info_list=qp_info_list,
                                             num_data_pkts=math.ceil(msg_size/mtu) * num_msgs_per_qp)
            if gbn_checker.check_all_qps() == True:
                result_logger.info("Go-Back-N state machine check passed for all qps.")
            else:
                result_logger.error("Go-Back-N state machine check failed")
                continue

            gbn_counter_check = gbn_checker.check_counters(sender_counter=requester_counter,
                                                           receiver_counter=responder_counter)
            if gbn_counter_check == True:
                result_logger.info("Go-Back-N counter check passed.")
            else:
                result_logger.error("Go-Back-N counter check failed")
                continue

        ## Output the latency for undelivered packets
        num_qps = len(qp_info_list)
        for qp_index in range(num_qps):
            is_read = (rdma_verb == 'read') or (rdma_verb == 'send_read' and qp_index >= num_qps_send)
            latency_measurement = LatencyMeasure(packet_list=packet_list,
                                                 qp_info_list=[qp_info_list[qp_index]],
                                                 is_read=is_read)

            undelivered_pkts = latency_measurement.get_undelivered_pkts(0)
            dropped_pkts = latency_measurement.get_dropped_pkts(0)
            bit_error_pkts = latency_measurement.get_bit_error_pkts(0)

            num_undelivered_pkts = len(undelivered_pkts)
            num_dropped_pkts = len(dropped_pkts)
            num_bit_error_pkts = len(bit_error_pkts)

            if num_undelivered_pkts <= 1:
                result_logger.info("There is %s undelivered packet for QP %d:"\
                                   % (num_undelivered_pkts, qp_index))
            else:
                result_logger.info("There are %s undelivered packets for QP %d:"\
                                   % (num_undelivered_pkts, qp_index))
            result_logger.info("\t\t Number of dropped packets: %d" % num_dropped_pkts)
            result_logger.info("\t\t Number of bit error packets: %d" % num_bit_error_pkts)

            for i in range(len(undelivered_pkts)):
                undelivered_pkt = undelivered_pkts[i]
                result_logger.info("[Packet %2d] dest_qpn:%d, psn:%d"\
                                   % (i, undelivered_pkt.get_roce_dest_qp(), undelivered_pkt.get_roce_pkt_seq()))
                result_logger.info("\t\t Injected event: %s" % undelivered_pkt.get_event_str())

                analyze_retrans_latency(pkt=undelivered_pkt,
                                        latency_measurement=latency_measurement,
                                        is_read=is_read,
                                        logger=result_logger)

def parse_args():
    """ Parse the command line arguments """
    parser = argparse.ArgumentParser(description = 'Test Go-Back-N')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--config_file', type=str, help='config file')
    group.add_argument('-d', '--config_dir',  type=str, help='config dir')
    parser.add_argument('-v', '--verify', action='store_true', help='only verify the experiment results')
    args = parser.parse_args()
    return args

def main(args):
    """ Main function

    Args:
        args (argparse.Namespace): Command line arguments

    Returns:
        N/A
    """
    if args.config_file != None:
        config_file = args.config_file
        orchestrator = Orchestrator(config_file)
        setup_root_logger(orchestrator)

        if args.verify == False:
            run_traffic_ret = run_traffic(orchestrator)
            if run_traffic_ret == True:
                verify_results(orchestrator)
        else:
            verify_results(orchestrator)

    elif args.config_dir != None:
        file_path_mask = os.path.join(args.config_dir, "*.yml")

        for config_file in glob.glob(file_path_mask):
            orchestrator = Orchestrator(config_file)
            setup_root_logger(orchestrator)

            if args.verify == False:
                run_traffic_ret = run_traffic(orchestrator)
                if run_traffic_ret == True:
                    verify_results(orchestrator)
            else:
                verify_results(orchestrator)

if __name__ == "__main__":
    args = parse_args()
    main(args)
