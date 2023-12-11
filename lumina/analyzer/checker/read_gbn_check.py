"""
    Verify if the trace is legal with go-back-n rules for queue pairs carrying RDMA READ traffic
    Note that READ requester is the receiver while the responder is the sender.
    RDMA response packets are regarded as data packets in this scenario.

    When data packets are dropped, the receiver (READ requester) will send a READ request packet
    to start reading from the out of sequence address.

    When the sender (RDMA responder) receives a READ request packet with PSN N, it will send data
    packets (READ response packets) using PSN N, N+1, ...
"""
import logging
import math
from lumina.analyzer.packet_parser.roce_packet import TRIGGER_OOS, TRIGGER_TIMEOUT
from lumina.analyzer.counter.host_counter import MLNXHostCounter, IntelHostCounter

class ReadGBNCheck:
    """ Class for checking go-back-n behavior for RDMA read

    Attributes:
        packet_list (list of RRoCEPacket objects): list of packets
        qp_info_list (list of dictionaries): The list of queue pair information with the following format:
                                            [{'psn_rcv': initial packet sequence number from the receiver qp,
                                              'psn_snd': initial packet sequence number from the sender qp,
                                              'qpn_rcv': receiver qp number,
                                              'qpn_snd': sender qp number,
                                              'ip_rcv' : receiver IP
                                              'ip_snd' : sender IP}]
        num_msgs_per_qp (int): The number of messages on each QP
        msg_size (int): The size of each message (in bytes)
        mtu (int): The MTU of the network (in bytes)
        num_oos_data_pkts (list of int): The number of out of sequence data packets for each QP
        num_error_data_pkts (list of int): The number of data packets with (injected) bit-error for each QP
        num_timeouts (list of int): The number of timeouts for each QP
    """

    def __init__(self, packet_list, qp_info_list, num_msgs_per_qp, msg_size, mtu):
        """ Constructor

        Args:
            packet_list (list of RRoCEPacket objects): list of packets
            qp_info_list (list of dictionaries): The list of queue pair information with the following format:
                                                [{'psn_rcv': initial packet sequence number from the receiver qp,
                                                  'psn_snd': initial packet sequence number from the sender qp,
                                                  'qpn_rcv': receiver qp number,
                                                  'qpn_snd': sender qp number,
                                                  'ip_rcv' : receiver IP
                                                  'ip_snd' : sender IP}]
            num_msgs_per_qp (int): The number of messages on each QP
            msg_size (int): The size of each message
            mtu (int): The MTU of the network (in bytes)
        """
        self.packet_list  = packet_list
        self.qp_info_list = qp_info_list
        self.num_msgs_per_qp = num_msgs_per_qp
        self.msg_size = msg_size
        self.mtu = mtu

        num_qps = len(qp_info_list)
        self.num_oos_data_pkts = [None] * num_qps
        self.num_error_data_pkts = [None] * num_qps
        self.num_timeouts = [None] * num_qps

    def check_sender(self, relative_dest_qpn):
        """ Check go-back-N behavior at sender side

        Args:
            relative_dest_qpn (int): the relative QP number starting from 0

        Returns:
            bool: True if the sender obeys the go-back-n state machine, False otherwise
        """
        logging.info("Checking the Go-Back-N behavior at the sender (READ responder) side")

        packet_list     = self.packet_list
        psn             = self.qp_info_list[relative_dest_qpn]['psn_snd']
        sender_qpn      = self.qp_info_list[relative_dest_qpn]['qpn_snd']
        receiver_qpn    = self.qp_info_list[relative_dest_qpn]['qpn_rcv']
        sender_ip       = self.qp_info_list[relative_dest_qpn]['ip_snd']
        receiver_ip     = self.qp_info_list[relative_dest_qpn]['ip_rcv']
        sender_qp       = (sender_qpn, sender_ip)
        receiver_qp     = (receiver_qpn, receiver_ip)
        num_data_pkts   = math.ceil(self.msg_size/self.mtu) * self.num_msgs_per_qp

        current_state   = {'send': None, 'rsp_start': None, 'rsp_end': None}
        testing         = False

        for ppacket in packet_list:
            if ppacket.is_roce_pkt() == False or ppacket.is_roce_read() == False:
                continue

            current_dst_ip    = ppacket.get_dst_ip()
            current_dest_qpn  = ppacket.get_roce_dest_qp()
            current_pkt_seq   = ppacket.get_roce_pkt_seq()
            current_delivered = ppacket.is_delivered()
            current_dst_qp    = (current_dest_qpn, current_dst_ip)

            # We only consider the packets between (sender_qp, receiver_qp)
            if current_dst_qp != receiver_qp and current_dst_qp != sender_qp:
                continue

            # We start testing upon seeing the first packet sent from the receiver (requester) to the sender
            if testing == False and current_dst_qp == sender_qp and current_pkt_seq == psn:
                testing = True

            if testing == False:
                continue

            if current_dst_qp == sender_qp:
                # Packets received by the sender
                if current_delivered == False:
                    # Ignore the undelivered packet
                    continue

                if ppacket.is_roce_read_req():
                    rsp_start = current_pkt_seq
                    rsp_end = math.ceil(ppacket.get_roce_dma_length()/self.mtu) + rsp_start - 1

                    # Assuming there is only one outstanding READ request per connection
                    current_state['rsp_start'] = rsp_start
                    current_state['rsp_end'] = rsp_end

                else:
                    logging.error("The sender should only receive RDMA READ request packets")
                    return False

            elif current_dst_qp == receiver_qp:
                ## Packets sent by the sender
                if ppacket.is_roce_read_rsp():
                    if current_state['rsp_start'] == None:
                        logging.error("The sender should not send READ response packets before any requests")
                        return False

                    if current_state['send'] is not None and current_pkt_seq == current_state['send'] + 1:
                        ## In-order transmission in current round
                        current_state['send'] = current_pkt_seq

                    elif current_pkt_seq == current_state['rsp_start']:
                        ## The request triggers a new round of (re)transmission
                        current_state['send'] = current_pkt_seq

                    else:
                        ## Unexpected out-of-order packet
                        logging.error("Unexpected out-of-order packet")
                        logging.info("current_pkt_seq: %d, current_state[\'send\']: %d", current_pkt_seq, current_state['send'])
                        return False

                else:
                    logging.error("The sender should only send RDMA READ response packets")
                    return False


        return (current_state['send'] == psn + num_data_pkts - 1) and \
               (current_state['rsp_end'] == current_state['send'])


    def check_receiver(self, relative_dest_qpn):
        """ Check go-back-N behavior at receiver side

        Args:
            relative_dest_qpn (int): the relative QP number starting from 0

        Returns:
            bool: True if the receiver obeys the go-back-n state machine, False otherwise
        """
        logging.info("Checking the Go-Back-N behavior at the receiver side")

        packet_list     = self.packet_list
        psn             = self.qp_info_list[relative_dest_qpn]['psn_snd']
        sender_qpn      = self.qp_info_list[relative_dest_qpn]['qpn_snd']
        receiver_qpn    = self.qp_info_list[relative_dest_qpn]['qpn_rcv']
        sender_ip       = self.qp_info_list[relative_dest_qpn]['ip_snd']
        receiver_ip     = self.qp_info_list[relative_dest_qpn]['ip_rcv']
        sender_qp       = (sender_qpn, sender_ip)
        receiver_qp     = (receiver_qpn, receiver_ip)
        num_data_pkts   = math.ceil(self.msg_size/self.mtu) * self.num_msgs_per_qp

        current_state   = {'recv': psn-1, 'oos': None, 'rsp_start': None, 'rsp_end': None}
        testing         = False

        self.num_error_data_pkts[relative_dest_qpn] = 0
        self.num_oos_data_pkts[relative_dest_qpn] = 0
        self.num_timeouts[relative_dest_qpn] = 0

        testing = False
        for ppacket in packet_list:
            if ppacket.is_roce_pkt() == False or ppacket.is_roce_cnp() == True:
                continue

            current_dst_ip      = ppacket.get_dst_ip()
            current_dest_qpn    = ppacket.get_roce_dest_qp()
            current_pkt_seq     = ppacket.get_roce_pkt_seq()
            current_delivered   = ppacket.is_delivered()
            current_icrc_error  = ppacket.is_bit_error()
            current_dst_qp      = (current_dest_qpn, current_dst_ip)

            # We only consider the packets between (sender_qp, receiver_qp)
            if current_dst_qp != receiver_qp and current_dst_qp != sender_qp:
                continue

            # We start testing upon seeing the first packet sent from the receiver (requester) to the sender
            if testing == False and current_dst_qp == sender_qp and current_pkt_seq == psn:
                testing = True

            if testing == False:
                continue

            if current_dst_qp == receiver_qp:
                ## Packets received by the receiver
                if ppacket.is_roce_read_rsp() == False:
                    logging.error("The receiver should only receive RDMA READ response packets")
                    return False

                if current_icrc_error == True:
                    # Increase ICRC error counters
                    self.num_error_data_pkts[relative_dest_qpn] += 1

                if current_delivered == False:
                    ## Ignore the undelivered (dropped or bit errors) packet from sender
                    continue

                if current_pkt_seq == current_state['recv'] + 1:
                    ## In-order arrival
                    current_state['recv'] = current_pkt_seq
                    ## if this packet fixes a out of sequence lost
                    if current_pkt_seq == current_state['oos']:
                        current_state['oos'] = None

                elif current_pkt_seq < current_state['recv'] + 1:
                    ## Ignore an out of order redundant transmission
                    logging.error("Unexpected redundant transmission")
                    return False

                elif current_state['oos'] == None:
                    current_state['oos'] = current_state['recv'] + 1
                    self.num_oos_data_pkts[relative_dest_qpn] += 1

            elif current_dst_qp == sender_qp:
                ## Packets sent by the receiver
                if ppacket.is_roce_read_req() == False:
                    logging.error("The receiver should only send RDMA READ request packets")
                    return False

                ## Assume only one in-flight READ message here
                rsp_start = current_pkt_seq
                rsp_end = math.ceil(ppacket.get_roce_dma_length()/self.mtu) + rsp_start - 1
                old_rsp_start = current_state['rsp_start']
                old_rsp_end = current_state['rsp_end']

                if rsp_end == old_rsp_end:
                    if rsp_start != current_state['recv'] + 1:
                        ## This duplicated READ request should exactly fix the loss
                        logging.error("The duplicated request should request data in (%d %d) to fix loss at %d"\
                                      % (current_state['recv']+1, rsp_end, current_state['recv']+1))
                        return False

                    if  current_state['oos'] == None:
                        ## No out of sequence packet detected, this READ request is triggered by timer
                        self.num_timeouts[relative_dest_qpn] += 1
                        ppacket.set_trigger(TRIGGER_TIMEOUT)
                    else:
                        ppacket.set_trigger(TRIGGER_OOS)

                current_state['rsp_start'] = rsp_start
                current_state['rsp_end'] = rsp_end

        return (current_state['recv'] == psn + num_data_pkts - 1) and \
               (current_state['oos'] == None) and \
               (current_state['rsp_end'] == current_state['recv'])

    def check_single_qp(self, relative_dest_qpn):
        """ Check if a single QP obeys the go-back-n state machine

        Args:
            relative_dest_qpn (int): the relative QP number starting from 0

        Returns:
            bool: True if the qp obeys the go-back-n state machine, False otherwise
        """
        result = True
        if self.check_sender(relative_dest_qpn) == False:
            logging.error("Go back N sender state machine check failed for qpn %d: %s" % \
                          (relative_dest_qpn, self.qp_info_list[relative_dest_qpn]))
            result = False

        if self.check_receiver(relative_dest_qpn) == False:
            logging.error("Go back N receiver state machine check failed for qpn %d: %s" % \
                          (relative_dest_qpn, self.qp_info_list[relative_dest_qpn]))
            result = False

        return result

    def check_all_qps(self):
        """ Check if all the QPs obey the go-back-n state machine

        Returns:
            bool: True if all the QPs obey the go-back-n state machine, False otherwise
        """
        num_qps = len(self.qp_info_list)
        result = True

        for relative_dest_qpn in range(num_qps):
            if self.check_sender(relative_dest_qpn) == False:
                logging.error("Go back N sender state machine check failed for qpn %d: %s" %\
                              (relative_dest_qpn, self.qp_info_list[relative_dest_qpn]))
                result = False

            if self.check_receiver(relative_dest_qpn) == False:
                logging.error("Go back N receiver state machine check failed for qpn %d %s" %\
                              (relative_dest_qpn, self.qp_info_list[relative_dest_qpn]))
                result = False

        return result

    def get_total_num_oos_data_pkts(self):
        """ Return the total number of out of sequence (OOS) data packets in pcap """
        num_qps = len(self.qp_info_list)
        total_num_oos_data_pkts = 0

        for relative_dest_qpn in range(num_qps):
            if self.num_oos_data_pkts[relative_dest_qpn] == None:
                logging.error("Num of nacks not initialized for qpn %d" % relative_dest_qpn)
                return None
            total_num_oos_data_pkts += self.num_oos_data_pkts[relative_dest_qpn]

        return total_num_oos_data_pkts

    def get_total_num_error_data_pkts(self):
        """ Return the total number of data packets with bit errors in pcap """
        num_qps = len(self.qp_info_list)
        total_num_error_data_pkts = 0

        for relative_dest_qpn in range(num_qps):
            if self.num_error_data_pkts[relative_dest_qpn] == None:
                logging.error("Num of error data packets not initialized for qpn %d" % relative_dest_qpn)
                return None
            total_num_error_data_pkts += self.num_error_data_pkts[relative_dest_qpn]

        return total_num_error_data_pkts

    def get_total_num_timeouts(self):
        """ Return the total number of timeouts in pcap """
        num_qps = len(self.qp_info_list)
        total_num_timeouts = 0

        for relative_dest_qpn in range(num_qps):
            if self.num_timeouts[relative_dest_qpn] == None:
                logging.error("Num of timeouts not initialized for qpn %d" % relative_dest_qpn)
                return None
            total_num_timeouts += self.num_timeouts[relative_dest_qpn]

        return total_num_timeouts

    def check_intel_sender_counters(self, sender_counter=None):
        """ Check if the counters from Intel rdma sender match the pcap file """
        result = True
        # No available counters for Intel.
        logging.info("No available counters from rdma sender, skip counters checking.")
        return result

    def check_intel_receiver_counters(self, receiver_counter=None):
        """ Check if the counters from Intel rdma receiver match the pcap file """
        result = True
        # No available counters for Intel.
        logging.info("No available counters from rdma receiver, skip counters checking.")
        return result

    def check_mlnx_sender_counters(self, sender_counter=None):
        """ Check if the counters from MLNX rdma sender match the pcap file

        Args:
            sender_counter (MLNXHostCounter): Counters of a Mellanox sender host

        Returns:
            bool: True if the counters from MLNX rdma sender match the pcap file, False otherwise
        """
        result = True

        if sender_counter == None:
            logging.info("No available counters from rdma sender, skip counters checking.")
            return result

        logging.info("Checking duplicate_request counter")
        total_num_retrans = self.get_total_num_timeouts() + self.get_total_num_oos_data_pkts()
        if sender_counter != None and sender_counter.get_num_dup_requests() != total_num_retrans:
            logging.error("The number of duplicated requests derived from rdma sender (%d) does not match"\
                          " the number of retransmissions found in the pcap (%d)"
                          % (sender_counter.get_num_dup_requests(), total_num_retrans))
            result = False

        return result

    def check_mlnx_receiver_counters(self, receiver_counter=None):
        """ Check if the counters from MLNX rdma receiver match the pcap file

        Args:
            receiver_counter (MLNXHostCounter): Counters of a Mellanox receiver host

        Returns:
            bool: True if the counters from MLNX rdma receiver match the pcap file, False otherwise
        """
        result = True

        if receiver_counter == None:
            logging.info("No available counters from rdma receiver, skip counters checking.")
            return result

        ## implied_nak_seq_err counter
        logging.info("Checking implied_nak_seq_err counter")
        total_num_oos_data_pkts = self.get_total_num_oos_data_pkts()

        if receiver_counter.implied_nak_seq_err() != total_num_oos_data_pkts:
            logging.error("implied_nak_seq_err derived from rdma receiver (%d) does not match"\
                          " the number of out-of-sequence packets found in the pcap (%d)"
                          % (receiver_counter.get_num_out_of_sequence(), total_num_oos_data_pkts))
            result = False

        ## local-ack-timeout-err counter.
        ## Note that timeouts happen at the RDMA READ requester (receiver) side
        logging.info("Checking local_ack_timeout_err counter")
        total_num_timeouts = self.get_total_num_timeouts()
        if receiver_counter.get_num_timeout_err() != total_num_timeouts:
            logging.error("The number of timeouts derived from rdma receiver (%d) does not match"\
                          " the number of timeouts found in the pcap (%d)"
                          % (receiver_counter.get_num_timeout_err(), total_num_timeouts))
            result = False

        ## ICRC error counter
        logging.info("Checking icrc_error counter")
        total_num_error_data_pkts = self.get_total_num_error_data_pkts()
        if receiver_counter.get_num_icrc_errors() != total_num_error_data_pkts:
            logging.error("The numbers of ICRC error packets derived from rdma host (%d) and pcap (%d) do not match"
                          % (receiver_counter.get_num_icrc_errors(), total_num_error_data_pkts))
            result = False

        return result

    def check_counters(self, sender_counter=None, receiver_counter=None):
        """ Check if the counters from rdma sender and receiver match the pcap file

        Args:
            sender_counter (HostCounter): Counters of a sender host
            receiver_counter (HostCounter): Counters of a receiver host

        Returns:
            bool: True if the counters from rdma sender and receiver match the pcap file, False otherwise
        """
        result = True
        if sender_counter == None:
            logging.info("No available counters from rdma sender, skip counters checking.")
        else:
            if isinstance(sender_counter, MLNXHostCounter):
                result &= self.check_mlnx_sender_counters(sender_counter)
            elif isinstance(sender_counter, IntelHostCounter):
                result &= self.check_intel_sender_counters(sender_counter)
            else:
                logging.error("Invalid counter type, skip counters checking.")

        if receiver_counter == None:
            logging.info("No available counters from rdma receiver, skip counters checking.")
        else:
            if isinstance(receiver_counter, MLNXHostCounter):
                result &= self.check_mlnx_receiver_counters(receiver_counter)
            elif isinstance(receiver_counter, IntelHostCounter):
                result &= self.check_intel_receiver_counters(receiver_counter)
            else:
                logging.error("Invalid counter type, skip counters checking.")

        return result
