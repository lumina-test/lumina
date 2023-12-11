import argparse, os, glob, logging, time
import lumina.analyzer.checker.integrity_check as integrity_check
import lumina.analyzer.checker.host_check as host_check
import lumina.analyzer.checker.cnp_check as cnp_check
import lumina.orchestrator.host as host
import lumina.orchestrator.switch as switch
from lumina.analyzer.main import get_qp_info_list, get_packet_list
from lumina.orchestrator.main import Orchestrator
from lumina.analyzer.counter.switch_counter import SwitchCounter
from lumina.analyzer.counter.host_counter import MLNXHostCounter, IntelHostCounter
from lumina.analyzer.pcap_processor.pcap_process import get_packet_list
from lumina.utils.config_loggers import config_stream_handler, config_file_handler

## All logs will be logged into file LOG_FILENAME
LOG_FILENAME = "test_cnp.log"
## Results (checkers and measurements) will also be dumped into file RESULT_FILENAME
RESULT_FILENAME = "result.log"
## Max # of retries for each experiment iteration
MAX_NB_EXP_RETRIES = 3

def setup_root_logger(orchestrator):
    """ Setup the root logger

    Args:
        orchestrator (Orchestrator object): Orchestrator object that contains all the configurations
    """
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    config_stream_handler(root_logger)
    config_file_handler(logger=root_logger,
                        log_file=os.path.join(orchestrator.result_path, LOG_FILENAME),
                        no_format=False)

def run_traffic(orchestrator):
    """ Run the traffic and collect results

    Args:
        orchestrator (Orchestrator object): Orchestrator object that contains all the configurations

    Returns:
        bool: True if successful, False otherwise
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

def verify_results(orchestrator, rdma_verb=None, qp_index_list=None):
    """ Verify experiment results

    Args:
        orchestrator (Orchestrator object): Orchestrator object that contains all the configurations
        rdma_verb (str): RDMA verb to verify (default: None)
        qp_index_list (list): List of QP indices to verify (default: None)

    Returns:
        N/A
    """

    result_dir = orchestrator.result_path
    num_repeats = orchestrator.num_repeats
    aggregate_pcap_filename = orchestrator.aggregate_pcap_filename

    if rdma_verb == None:
        rdma_verb = orchestrator.traffic_conf['rdma-verb'].lower().strip()

    if rdma_verb not in host.VALID_IB_VERB_LIST_LOWER:
        logging.error("Invalid RDMA verb: %s" % rdma_verb)
        return

    ## A mix of RDMA SEND and READ. Need to verify both SEND and READ
    if rdma_verb == 'send_read':
        num_qps_send, num_qps_read = [int(x) for x in orchestrator.traffic_conf['num-qps'].split(',')]
        verify_results(orchestrator=orchestrator,
                       rdma_verb='send',
                       qp_index_list=list(range(num_qps_send)))

        verify_results(orchestrator=orchestrator,
                       rdma_verb='read',
                       qp_index_list=list(range(num_qps_send, num_qps_send+num_qps_read)))
        return

    elif rdma_verb == "read":
        receiver_nic_type = orchestrator.requester.conf['nic']['type']
        if orchestrator.requester.is_intel_nic():
            receiver_np_enable = orchestrator.requester.conf['roce-parameters']['dcqcn-enable']
            receiver_slow_restart = False
            min_time_between_cnps_us = 0
        elif orchestrator.requester.is_mlnx_nic():
            receiver_np_enable = orchestrator.requester.conf['roce-parameters']['dcqcn-np-enable']
            receiver_slow_restart = orchestrator.requester.conf['roce-parameters']['slow-restart']
            min_time_between_cnps_us = orchestrator.requester.conf['roce-parameters']['min-time-between-cnps']
        else:
            receiver_np_enable = False
            receiver_slow_restart = False
            min_time_between_cnps_us = 0

    else:
        receiver_nic_type = orchestrator.responder.conf['nic']['type']
        if orchestrator.responder.is_intel_nic():
            receiver_np_enable = orchestrator.responder.conf['roce-parameters']['dcqcn-enable']
            receiver_slow_restart = False
            min_time_between_cnps_us = 0
        elif orchestrator.responder.is_mlnx_nic():
            receiver_np_enable = orchestrator.responder.conf['roce-parameters']['dcqcn-np-enable']
            receiver_slow_restart = orchestrator.responder.conf['roce-parameters']['slow-restart']
            min_time_between_cnps_us = orchestrator.responder.conf['roce-parameters']['min-time-between-cnps']
        else:
            receiver_np_enable = False
            receiver_slow_restart = False
            min_time_between_cnps_us = 0

    nack_trigger_cnp = cnp_check.check_nack_trigger_cnp(receiver_nic_type,
                                                        receiver_np_enable,
                                                        receiver_slow_restart)

    port_map = {'requester': orchestrator.requester.conf['nic']['switch-port'],
                'responder': orchestrator.responder.conf['nic']['switch-port'],
                'requester-mirror': orchestrator.requester_mirror.conf['nic']['switch-port'],
                'responder-mirror': orchestrator.responder_mirror.conf['nic']['switch-port']}

    requester_ip_list = orchestrator.get_requester_ip_list()
    responder_ip_list = orchestrator.get_responder_ip_list()

    for iter in range(num_repeats):
        iter = str(iter)
        result_logger = logging.getLogger('Iter %s Verb %s' % (iter, rdma_verb))
        result_logger.handlers.clear()
        config_file_handler(logger=result_logger,
                            log_file=os.path.join(result_dir, iter, RESULT_FILENAME),
                            no_format=True)
        result_logger.info("=" * 100)
        result_logger.info("Iteration %s Verb %s" % (iter, rdma_verb))

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
            requester_counter = None
        if orchestrator.responder.is_mlnx_nic():
            responder_counter = MLNXHostCounter(responder_counter_start, responder_counter_finish)
        elif orchestrator.responder.is_intel_nic():
            responder_counter = IntelHostCounter(responder_counter_start, responder_counter_finish)
        else:
            responder_counter = None

        qp_info_list = get_qp_info_list(switch_msg_snapshot)
        if qp_index_list != None:
            qp_info_list = [qp_info_list[index] for index in qp_index_list]

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

        ## Check ECN and CNP behaviors
        cnp_checker = cnp_check.CNPCheck(packet_list, qp_info_list)
        check = cnp_checker.check_cnp_behavior(cnp_check.CNP_PACING_MODE.PER_PORT,
                                               nack_trigger_cnp,
                                               min_time_between_cnps_us)
        if check == True:
            result_logger.info("CNP check (per NIC port limiting) passed.")
        else:
            result_logger.error("CNP check (per NIC port limiting) failed")

        check = cnp_checker.check_cnp_behavior(cnp_check.CNP_PACING_MODE.PER_IP_PAIR,
                                               nack_trigger_cnp,
                                               min_time_between_cnps_us)
        if check == True:
            result_logger.info("CNP check (per IP pair limiting) passed.")
        else:
            result_logger.error("CNP check (per IP pair limiting) failed")

        check = cnp_checker.check_cnp_behavior(cnp_check.CNP_PACING_MODE.PER_DEST_IP,
                                               nack_trigger_cnp,
                                               min_time_between_cnps_us)
        if check == True:
            result_logger.info("CNP check (per destination IP) passed.")
        else:
            result_logger.error("CNP check (per destination IP) failed")

        receiver_counter = responder_counter
        if rdma_verb == "read":
            receiver_counter = requester_counter

        if cnp_checker.check_counters(receiver_counter) == True:
            result_logger.info("CNP counter check passed.")
        else:
            result_logger.error("CNP counter check failed")

def parse_args():
    """ Parse command line arguments

    Returns:
        argparse.Namespace: command line arguments
    """
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
        args (argparse.Namespace): command line arguments

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
