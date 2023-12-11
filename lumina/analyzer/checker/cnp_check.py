"""
    Verify if the host replied a CNP for each ecn for queue pair (receiver_qpn, sender_qpn)
    #####  sender_qp (receiver_qpn, psn) ----------->  receiver_qp  #####
    For RDMA write and send, the sender_qp is the qp that sends the RDMA write or read request
    For RDMA read, the sender_qp is the qp that sends the RDMA read response
"""
import logging
import enum

# How NIC paces outgoing CNP packets, per NIC port, per IP pair, or per destination IP
class CNP_PACING_MODE(enum.IntEnum):
    PER_PORT = 1
    PER_IP_PAIR = 2
    PER_DEST_IP = 3

# Some NICs send a CNP along with a NACK once detecting a packet loss
# NACK_TRIGGER_CNP_DIC indicates whether a NIC sends a CNP along with a NACK
NACK_TRIGGER_CNP_DIC = {
    "E810": False,
    "CX4": False,
    "CX5": True,
    "CX6": True,
}

# This feature is only supported when np_enable is enabled and slow_restart is enabled
def check_nack_trigger_cnp(nic_type, np_enable, slow_restart):
    return NACK_TRIGGER_CNP_DIC[nic_type] and np_enable and slow_restart

class CNPCheck:
    """ Class for checking CNP behaviors """
    def __init__(self, packet_list, qp_info_list):
        """ Constructor

        Args:
            packet_list (list): The list of packets to check
            qp_info_list (list): The list of qp info to with the following format
                                    [{'psn_rcv': initial packet sequence number from the receiver qp,
                                      'psn_snd': initial packet sequence number from the sender qp,
                                      'qpn_rcv': receiver QP number,
                                      'qpn_snd': sender QP number,
                                      'ip_rcv' : receiver IP
                                      'ip_snd' : sender IP}]

        Returns:
            N/A
        """

        self.packet_list = packet_list
        self.qp_info_list = qp_info_list

        """
        ip_pairs: list of IP pairs
        sender_ip_list: list of sender IP addresses

        num_ecns_ip_pair: # of ECN marked packets for each IP pair
        num_expected_cnps_ip_pair: # of expected CNPs (according to spec) for each IP pair
        num_cnps_ip_pair: actual # of CNPs for each IP pair
        num_nacks_ip_pair: actual # of NACKs for each IP pair
        last_cnp_time_ip_pair: time of last CNP for each IP pair

        num_ecns_ip: # of ECN marked packets from each sender IP
        num_expected_cnps_ip: # of expected CNPs (according to spec) for each sender IP
        num_cnps_ip: actual # of CNPs for each sender IP
        num_nacks_ip: actual # of NACKs for each sender IP
        last_cnp_time_ip: time of last CNP for each sender IP

        num_ecns_port: # of ECN marked packets on a NIC port
        num_expected_cnps_port: # of expected CNPs (according to spec) on a NIC port
        num_cnps_port: actual # of CNPs on a NIC port
        num_nacks_port: actual # of NACKs on a NIC port
        last_cnp_time_port: time of last CNP sent on a NIC port
        """
        self.ip_pairs = []
        self.sender_ip_list = []

        self.num_ecns_ip_pair = {}
        self.num_expected_cnps_ip_pair = {}
        self.num_cnps_ip_pair = {}
        self.num_nacks_ip_pair = {}
        self.last_cnp_time_ip_pair = {}

        self.num_ecns_ip = {}
        self.num_expected_cnps_ip = {}
        self.num_cnps_ip = {}
        self.num_nacks_ip = {}
        self.last_cnp_time_ip = {}

        self.num_ecns_port = 0
        self.num_expected_cnps_port = 0
        self.num_cnps_port = 0
        self.num_nacks_port = 0
        self.last_cnp_time_port = None

    def get_ip_pairs(self):
        """ Return a list of IP pairs

        Returns:
            list of tuple of str: A list of IP pairs
        """
        ip_pairs = [(qp_info['ip_snd'], qp_info['ip_rcv']) for qp_info in self.qp_info_list]
        return list(set(ip_pairs))

    def get_sender_ip_list(self):
        """ Return a list of sender IP addresses

        Returns:
            list of str: A list of sender IP addresses
        """
        return list(set([qp_info['ip_snd'] for qp_info in self.qp_info_list]))

    def check_cnp_behavior(self,
                           cnp_pacing_mode,
                           nack_trigger_cnp=False,
                           min_time_between_cnps_us=0):

        """ Check if CNP behaviors are correct

        Args:
            cnp_pacing_mode (CNP_PACING_MODE): How NIC paces outgoing CNP packets
            nack_trigger_cnp (bool): Whether a NIC sends a CNP along with a NACK
            min_time_between_cnps_us (int): Minimum time between two CNPs in microseconds

        Returns:
            bool: True if CNP behaviors are correct, False otherwise
        """

        # Check if cnp_pacing_mode is valid
        if cnp_pacing_mode not in list(CNP_PACING_MODE):
            logging.error("Unknown cnp_pacing_mode %s" % str(cnp_pacing_mode))
            return False

        self.ip_pairs = self.get_ip_pairs()
        self.sender_ip_list = self.get_sender_ip_list()

        # Initialize class variables
        self.num_ecns_port = 0
        self.num_expected_cnps_port = 0
        self.num_cnps_port = 0
        self.num_nacks_port = 0
        self.last_cnp_time_port = None

        for ip_pair in self.ip_pairs:
            self.num_ecns_ip_pair[ip_pair] = 0
            self.num_expected_cnps_ip_pair[ip_pair] = 0
            self.num_cnps_ip_pair[ip_pair] = 0
            self.num_nacks_ip_pair[ip_pair] = 0
            self.last_cnp_time_ip_pair[ip_pair] = None

        for ip in self.sender_ip_list:
            self.num_ecns_ip[ip] = 0
            self.num_expected_cnps_ip[ip] = 0
            self.num_cnps_ip[ip] = 0
            self.num_nacks_ip[ip] = 0
            self.last_cnp_time_ip[ip] = None

        # Process each packet
        packet_list  = self.packet_list
        for ppacket in packet_list:
            # Skip non-ROCE packets
            if ppacket.is_roce_pkt() == False:
                continue

            src_ip = ppacket.get_src_ip()
            dst_ip = ppacket.get_dst_ip()
            is_roce_data = ppacket.is_roce_data_pkt()
            ecn_flag  = ppacket.is_ecn()
            cnp_flag  = ppacket.is_roce_cnp()
            nack_flag = ppacket.is_roce_nack()
            tstamp_sec = ppacket.get_switch_timestamp()

            trigger_cnp = False
            sender_ip = None

            # ECN marked packets can trigger CNPs. Sender's IP is the source IP of data packets
            if is_roce_data == True and ecn_flag == True:
                sender_ip = src_ip
                ip_pair = (src_ip, dst_ip)
                if ip_pair in self.ip_pairs:
                    self.num_ecns_ip_pair[ip_pair] += 1
                    self.num_ecns_ip[sender_ip] += 1
                    self.num_ecns_port += 1
                    trigger_cnp = True

            # Some NICs send a CNP once detecting a packet loss.
            # Sender's IP is the destination IP of NACKs and CNPs
            if nack_flag == True:
                sender_ip = dst_ip
                ip_pair = (dst_ip, src_ip)
                if ip_pair in self.ip_pairs:
                    self.num_nacks_ip_pair[ip_pair] += 1
                    self.num_nacks_ip[sender_ip] += 1
                    self.num_nacks_port += 1
                    trigger_cnp = (nack_trigger_cnp == True)

            if cnp_flag == True:
                sender_ip = dst_ip
                ip_pair = (dst_ip, src_ip)
                if ip_pair in self.ip_pairs:
                    self.num_cnps_ip_pair[ip_pair] += 1
                    self.num_cnps_ip[sender_ip] += 1
                    self.num_cnps_port += 1

            if trigger_cnp == True:
                # Update the expected number of CNPs based on the CNP pacing mode
                if cnp_pacing_mode == CNP_PACING_MODE.PER_PORT:
                    if self.last_cnp_time_port == None or \
                       tstamp_sec - self.last_cnp_time_port > min_time_between_cnps_us * 1e-6:
                        self.last_cnp_time_port = tstamp_sec
                        self.num_expected_cnps_port += 1

                elif cnp_pacing_mode == CNP_PACING_MODE.PER_IP_PAIR:
                    if self.last_cnp_time_ip_pair[ip_pair] == None or \
                       tstamp_sec - self.last_cnp_time_ip_pair[ip_pair] > min_time_between_cnps_us * 1e-6:
                        self.last_cnp_time_ip_pair[ip_pair] = tstamp_sec
                        self.num_expected_cnps_ip_pair[ip_pair] += 1

                elif cnp_pacing_mode == CNP_PACING_MODE.PER_DEST_IP:
                    if self.last_cnp_time_ip[sender_ip] == None or \
                       tstamp_sec - self.last_cnp_time_ip[sender_ip] > min_time_between_cnps_us * 1e-6:
                        self.last_cnp_time_ip[sender_ip] = tstamp_sec
                        self.num_expected_cnps_ip[sender_ip] += 1

                else:
                    pass

        ret_flag = True

        # Check if the actual number of CNPs matches the expected number of CNPs
        if cnp_pacing_mode == CNP_PACING_MODE.PER_PORT:
            logging.info("Checking CNP behaviors based on per NIC port rate limting")
            if self.num_cnps_port != self.num_expected_cnps_port:
                logging.error("Numbers of actual CNPs (%d) and expected CNPs (%d) do not match for NIC port "\
                              "having %d ECN marked packets and %d NACKs" %\
                              (self.num_cnps_port, self.num_expected_cnps_port, self.num_ecns_port,\
                               self.num_nacks_port))
                ret_flag = False
            else:
                logging.info("Numbers of actual CNPs (%d) and expected CNPs (%d) match for NIC port "\
                             "having %d ECN marked packets and %d NACKs" %\
                             (self.num_cnps_port, self.num_expected_cnps_port, self.num_ecns_port,\
                              self.num_nacks_port))

        elif cnp_pacing_mode == CNP_PACING_MODE.PER_IP_PAIR:
            logging.info("Checking CNP behaviors based on per IP pair rate limting")
            for ip_pair in self.ip_pairs:
                if self.num_cnps_ip_pair[ip_pair] != self.num_expected_cnps_ip_pair[ip_pair]:
                    logging.error("Numbers of actual CNPs (%d) and expected CNPs (%d) do not match for IP pair %s "\
                                  "having %d ECN marked packets and %d NACKs" %\
                                  (self.num_cnps_ip_pair[ip_pair], self.num_expected_cnps_ip_pair[ip_pair],\
                                   ip_pair, self.num_ecns_ip_pair[ip_pair], self.num_nacks_ip_pair[ip_pair]))
                    ret_flag = False
                else:
                    logging.info("Numbers of actual CNPs (%d) and expected CNPs (%d) match for IP pair %s "\
                                 "having %d ECN marked packets and %d NACKs" %\
                                 (self.num_cnps_ip_pair[ip_pair], self.num_expected_cnps_ip_pair[ip_pair],\
                                  ip_pair, self.num_ecns_ip_pair[ip_pair], self.num_nacks_ip_pair[ip_pair]))

        elif cnp_pacing_mode == CNP_PACING_MODE.PER_DEST_IP:
            logging.info("Checking CNP behaviors based on per destination IP rate limting")
            for ip in self.sender_ip_list:
                if self.num_cnps_ip[ip] != self.num_expected_cnps_ip[ip]:
                    logging.error("Numbers of actual CNPs (%d) and expected CNPs (%d) do not match for IP %s "\
                                  "having %d ECN marked packets and %d NACKs" %\
                                  (self.num_cnps_ip[ip], self.num_expected_cnps_ip[ip], ip,
                                   self.num_ecns_ip[ip], self.num_nacks_ip[ip]))
                    ret_flag = False
                else:
                    logging.info("Numbers of actual CNPs (%d) and expected CNPs (%d) match for IP %s "\
                                 "having %d ECN marked packets and %d NACKs" %\
                                 (self.num_cnps_ip[ip], self.num_expected_cnps_ip[ip], ip,
                                  self.num_ecns_ip[ip], self.num_nacks_ip[ip]))

        else:
            pass

        return ret_flag

    def check_counters(self, receiver_counter=None):
        """ Check if host counters match the counters derived from the packet trace

        Args:
            receiver_counter (HostCounter): The host counter of the receiver

        Returns:
            bool: True if host counters match the counters derived from the packet trace, False otherwise
        """
        result = True

        if receiver_counter is None:
            logging.info("Skip counter check as receiver_counter is missing")
            return result

        logging.info("Checking np_cnp_sent counter")
        total_num_cnps = self.get_total_num_cnps()
        if total_num_cnps != receiver_counter.get_num_cnp_sent():
            logging.error("The number of CNPs derived from rdma receiver (%d) does not match"\
                          " the number of CNPs found in the pcap (%d)"
                          % (receiver_counter.get_num_cnp_sent(), total_num_cnps))
            result = False

        logging.info("Checking np_ecn_marked_roce_packets counter")
        total_num_ecns = self.get_total_num_ecns()
        if total_num_ecns != receiver_counter.get_num_ecn_marked_packets():
            logging.error("The number of ECN marked packets derived from rdma receiver (%d) does not match"\
                          " the number of ECN marked packets found in the pcap (%d)"
                          % (receiver_counter.get_num_ecn_marked_packets(), total_num_ecns))
            result = False

        return result

    def get_total_num_cnps(self):
        """ Return the total number of CNPs derived from the packet trace """
        result = 0

        packet_list  = self.packet_list
        for ppacket in packet_list:
            if ppacket.is_roce_pkt() == False:
                continue

            if ppacket.is_roce_cnp():
                src_ip = ppacket.get_src_ip()
                dst_ip = ppacket.get_dst_ip()
                # Only count CNPs from the 'legal' IP pairs
                result += int((dst_ip, src_ip) in self.ip_pairs)

        return result

    def get_total_num_ecns(self):
        """ Return the total number of ECN marked packets derived from the packet trace """
        result = 0

        packet_list  = self.packet_list
        for ppacket in packet_list:
            if ppacket.is_roce_pkt() == False:
                continue

            if ppacket.is_ecn() and ppacket.is_roce_data_pkt():
                src_ip = ppacket.get_src_ip()
                dst_ip = ppacket.get_dst_ip()
                # Only count ECN marked packets from the 'legal' IP pairs
                result += int((src_ip, dst_ip) in self.ip_pairs)

        return result
