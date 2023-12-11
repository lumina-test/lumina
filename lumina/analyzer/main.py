"""
This is the main entry point for the offline analyzer. It takes a config file as input and
performs the following tasks:
1. Check the integrity of the trace according to pcap files, and timestamps
2. Check the host counters
3. Check the traces and counters according to Go-Back-N (GBN) and Congestion Notification Packet (CNP) checkers
"""
import argparse, sys, yaml, os, math, logging
import lumina.analyzer.checker.integrity_check as integrity_check
import lumina.analyzer.checker.host_check as host_check
import lumina.analyzer.checker.gbn_check as gbn_check
import lumina.analyzer.checker.read_gbn_check as read_gbn_check
import lumina.analyzer.checker.cnp_check as cnp_check
import lumina.orchestrator.host as host
import lumina.orchestrator.switch as switch
from lumina.analyzer.counter.switch_counter import SwitchCounter
from lumina.analyzer.counter.host_counter import MLNXHostCounter, IntelHostCounter
from lumina.analyzer.pcap_processor.pcap_process import get_packet_list
from lumina.utils.config_loggers import config_stream_handler, config_file_handler

## All logs will be logged into file LOG_FILENAME
LOG_FILENAME = "analysis.log"
## Results (checkers and measurements) will also be dumped into file RESULT_FILENAME
RESULT_FILENAME = "result.out"

def get_qp_info_list(switch_msg_snapshot):
    """ Get the list of QP info from the switch message snapshot

    Args:
        switch_msg_snapshot (str): The path to the switch message snapshot

    Returns:
        list of dict: The list of queue pair (QP) information if successful or None otherwise.
                      The list of QP information is in the following format:
                        [{'psn_rcv': initial packet sequence number from the receiver qp,
                          'psn_snd': initial packet sequence number from the sender qp,
                          'qpn_rcv': receiver qp number,
                          'qpn_snd': sender qp number,
                          'ip_rcv' : receiver IP
                          'ip_snd' : sender IP}]
    """
    try:
        with open(switch_msg_snapshot, 'r') as stream:
            qp_info_list = yaml.safe_load(stream)
    except:
        logging.error("Read switch message snapshot %s error." % switch_msg_snapshot)
        return None

    logging.info("Read switch message snapshot %s." % switch_msg_snapshot)
    return qp_info_list

def main(args):
    """ Main function of the offline analyzer

    Args:
        args (argparser.Namespace): The parsed arguments

    Returns:
        N/A
    """
    with open(args.config_file, "r") as stream:
        conf = yaml.safe_load(stream)
        try:
            result_dir      = conf['result-path']
            num_repeats     = conf['num-repeats']
            mtu             = conf['traffic']['mtu']
            msg_size        = conf['traffic']['message-size']
            num_msgs_per_qp = conf['traffic']['num-msgs-per-qp']

            port_map = {'requester':        conf['requester']['nic']['switch-port'],
                        'responder':        conf['responder']['nic']['switch-port'],
                        'requester-mirror': conf['requester-mirror']['nic']['switch-port'],
                        'responder-mirror': conf['responder-mirror']['nic']['switch-port']}
            requester_nic_type = conf['requester']['nic']['type']
            responder_nic_type = conf['responder']['nic']['type']
            requester_nic_vendor = host.NIC_TYPE2VENDOR_MAP[requester_nic_type] \
                                    if requester_nic_type in host.NIC_TYPE2VENDOR_MAP.keys() \
                                    else host.NICVendor.Unkown
            responder_nic_vendor = host.NIC_TYPE2VENDOR_MAP[responder_nic_type] \
                                    if responder_nic_type in host.NIC_TYPE2VENDOR_MAP.keys() \
                                    else host.NICVendor.Unkown
            nic_vendor_map = {'requester': requester_nic_vendor, 'responder': responder_nic_vendor}

        except KeyError as e:
            print("Config file %s has a bad yaml format (key error: %s)" % (args.config_file, e))
            sys.exit(1)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    config_stream_handler(root_logger)
    config_file_handler(logger=root_logger,
                        log_file=os.path.join(result_dir, LOG_FILENAME),
                        no_format=False)

    for iter in range(num_repeats):
        iter = str(iter)
        result_logger = logging.getLogger('Analyze iter %s' % iter)
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
                                     conf['aggregate-pcap-filename'])
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

        if nic_vendor_map["requester"] == host.NICVendor.MLNX:
            requester_counter = MLNXHostCounter(requester_counter_start, requester_counter_finish)
        elif nic_vendor_map["requester"] == host.NICVendor.Intel:
            requester_counter = IntelHostCounter(requester_counter_start, requester_counter_finish)
        else:
            logging.error("Unkown NIC Vendor for rdma requester.")
            requester_counter = None

        if nic_vendor_map["responder"] == host.NICVendor.MLNX:
            responder_counter = MLNXHostCounter(responder_counter_start, responder_counter_finish)
        elif nic_vendor_map["responder"] == host.NICVendor.Intel:
            responder_counter = IntelHostCounter(responder_counter_start, responder_counter_finish)
        else:
            logging.error("Unkown NIC Vendor for rdma responder.")
            responder_counter = None

        qp_info_list = get_qp_info_list(switch_msg_snapshot)
        packet_list = get_packet_list(pcap_filename)

        packet_list.sort(key=lambda x:x.get_switch_seqnum())
        result_logger.info("Packet trace sorted by switch sequence number")

        ## Do integrity check to make sure there is nothing wrong with traces and counters
        requester_ip_list = [x.split('/')[0] for x in conf['requester']['nic']['ip-list']]
        responder_ip_list = [x.split('/')[0] for x in conf['responder']['nic']['ip-list']]

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
            result_logger.info("Host discard counter check passed")
        else:
            result_logger.error("Host discard counter check failed")
            continue

        rdma_verb = conf['traffic']['rdma-verb'].lower().strip()
        if rdma_verb not in host.VALID_IB_VERB_LIST_LOWER:
            logging.error("Invalid RDMA verb: %s" % rdma_verb)
            return

        if hasattr(args, 'checker_list') == False or args.checker_list == None:
            continue

        result_logger.info("Checker list: %s" % args.checker_list)
        is_read = (rdma_verb == "read")

        ## Use Go-Back-N checker to check traces and counters
        if 'gbn' in args.checker_list:
            if is_read:
                gbn_checker = read_gbn_check.ReadGBNCheck(packet_list=packet_list,
                                                          qp_info_list=qp_info_list,
                                                          num_msgs_per_qp=num_msgs_per_qp,
                                                          msg_size=msg_size,
                                                          mtu=mtu)
            else:
                gbn_checker = gbn_check.GBNCheck(packet_list=packet_list,
                                                 qp_info_list=qp_info_list,
                                                 num_data_pkts=math.ceil(msg_size/mtu) * num_msgs_per_qp)

            if args.relative_dest_qpn == None:
                if gbn_checker.check_all_qps() == True:
                    result_logger.info("Go-Back-N check passed")
                else:
                    result_logger.error("Go-Back-N check failed")

            elif args.relative_dest_qpn >= 0 and args.relative_dest_qpn < len(qp_info_list):
                if gbn_checker.check_single_qp(args.relative_dest_qpn) == True:
                    result_logger.info("Go-Back-N check passed")
                else:
                    result_logger.error("Go-Back-N check failed")

            else:
                result_logger.error("Illegal relative QP number")

        ## Use CNP checker to check counters
        if 'cnp' in args.checker_list:
            cnp_checker = cnp_check.CNPCheck(packet_list=packet_list, qp_info_list=qp_info_list)
            if is_read:
                receiver_counter = requester_counter
            else:
                receiver_counter = responder_counter

            if cnp_checker.check_counters(receiver_counter) == True:
                result_logger.info("CNP counter check passed")
            else:
                result_logger.error("CNP counter check failed")


def parse_args():
    """ Parse command line arguments

    Returns:
        argparser.Namespace: The parsed arguments
    """
    parser = argparse.ArgumentParser(description = 'Offline analyzer')
    parser.add_argument('-f', '--config_file', type=str, help='config file', required=True)
    parser.add_argument('-q', '--relative_dest_qpn', type=int, help='The relative destination QP number')
    parser.add_argument('-c', '--checker_list', nargs='+', help='The list of checker to enforce (gbn, cnp)')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()
    main(args)
