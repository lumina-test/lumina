import logging
from lumina.analyzer.counter.host_counter import MLNXHostCounter, IntelHostCounter

class GBNCheck:
    """ Class for checking go-back-n behavior for RDMA send and write

    Attributes:
        packet_list (list of RRoCEPacket): The list of packets to check
        qp_info_list (list of dictionaries): The list of queue pair information with the following format:
                                            [{'psn_rcv': initial packet sequence number from the receiver qp,
                                              'psn_snd': initial packet sequence number from the sender qp,
                                              'qpn_rcv': receiver qp number,
                                              'qpn_snd': sender qp number,
                                              'ip_rcv' : receiver IP
                                              'ip_snd' : sender IP}]
        num_data_pkts (int): The number of data packets (excluding losses and retransmissions) on each QP
        num_nacks (list of int): The number of NACK packets on each QP
        num_error_data_pkts (list of int): The number of data packets with (injected) bit-error on each QP
        num_timeouts (list of int): The number of timeouts on each QP
    """
    def __init__(self, packet_list, qp_info_list, num_data_pkts):
        """ Constructor

        Args:
            packet_list (list of RRoCEPacket): The list of packets to check
            qp_info_list (list of dictionaries): The list of queue pair information with the following format:
                                                [{'psn_rcv': initial packet sequence number from the receiver qp,
                                                  'psn_snd': initial packet sequence number from the sender qp,
                                                  'qpn_rcv': receiver qp number,
                                                  'qpn_snd': sender qp number,
                                                  'ip_rcv' : receiver IP
                                                  'ip_snd' : sender IP}]
            num_data_pkts (int): The number of data packets (excluding losses and retransmissions) on each QP

        Returns:
            N/A
        """
        self.packet_list  = packet_list
        self.qp_info_list = qp_info_list
        self.num_data_pkts = num_data_pkts

        num_qps = len(qp_info_list)
        self.num_nacks = [None] * num_qps
        self.num_error_data_pkts = [None] * num_qps
        self.num_timeouts = [None] * num_qps

    def check_sender(self, relative_dest_qpn):
        """ Check go-back-N behavior at sender side

        Args:
            relative_dest_qpn (int): the relative QP number starting from 0

        Returns:
            bool: True if the sender obeys the go-back-n state machine, False otherwise
        """
        logging.info("Checking the Go-Back-N behavior at the sender side")
        packet_list     = self.packet_list
        psn             = self.qp_info_list[relative_dest_qpn]['psn_snd']
        sender_qpn      = self.qp_info_list[relative_dest_qpn]['qpn_snd']
        receiver_qpn    = self.qp_info_list[relative_dest_qpn]['qpn_rcv']
        sender_ip       = self.qp_info_list[relative_dest_qpn]['ip_snd']
        receiver_ip     = self.qp_info_list[relative_dest_qpn]['ip_rcv']
        sender_qp       = (sender_qpn, sender_ip)
        receiver_qp     = (receiver_qpn, receiver_ip)
        num_data_pkts   = self.num_data_pkts
        testing         = False

        self.num_nacks[relative_dest_qpn] = 0
        self.num_timeouts[relative_dest_qpn] = 0

        """
        Sender states:
        - send  : The largest seqnum among packets consecutively sent *in current iteration*
        - ack   : The largest sequence that has been (accumulatively) acknowledged
        - nack  : Pending NACK that has not triggered retransmission yet
        """
        current_state   = {'send': None, 'ack': None, 'nack': None}

        for ppacket in packet_list:
            if ppacket.is_roce_pkt() == False:
                continue

            current_dst_ip    = ppacket.get_dst_ip()
            current_dest_qpn  = ppacket.get_roce_dest_qp()
            current_pkt_seq   = ppacket.get_roce_pkt_seq()
            current_delivered = ppacket.is_delivered()
            current_dst_qp   = (current_dest_qpn, current_dst_ip)

            # We only consider the packets between (sender_qp, receiver_qp)
            if current_dst_qp != receiver_qp and current_dst_qp != sender_qp:
                continue

            # We start testing upon seeting the first packet sent from the sender to the receiver
            if testing == False and current_dst_qp == receiver_qp and current_pkt_seq == psn:
                testing = True

            if testing == False:
                continue

            if current_dst_qp == sender_qp:
                ## Packets received by the sender
                if current_delivered == False:
                    ## Ignore the undelivered packet from the receiver
                    continue

                if ppacket.is_roce_data_pkt():
                    logging.error("The sender should not receive a data packet")
                    return False

                elif ppacket.is_roce_ack() == True:
                    ## ACK
                    if (current_state['ack'] == None) or (current_pkt_seq >= current_state['ack']):
                        current_state['ack'] = current_pkt_seq
                    else:
                        logging.error("[Potential receiver ERROR] ACK with smaller seqnum than already ACKed packets")
                        return False

                elif ppacket.is_roce_nack() == True:
                    ## NACK
                    if current_state['nack'] == None:
                        current_state['nack'] = current_pkt_seq
                    else:
                        logging.error("[Potential receiver ERROR] More than one in-flight NACK")
                        return False

                else:
                    ## Unknown type of packet received by the sender
                    continue

            elif current_dst_qp == receiver_qp:
                ## Packets sent by the sender
                if ppacket.is_roce_data_pkt():
                    ## Data packets from sender
                    if (current_state['send'] == None) or (current_pkt_seq == current_state['send'] + 1):
                        ## In-order packet
                        current_state['send'] = current_pkt_seq
                    elif current_pkt_seq == current_state['nack']:
                        ## Retransmission, reset nack as None
                        current_state['send'] = current_pkt_seq
                        current_state['nack'] = None
                        ## Mark out-of-sequence
                        self.num_nacks[relative_dest_qpn] += 1
                    elif current_state['nack'] == None:
                        ## Retransmission packet because of timeout
                        current_state['send'] = current_pkt_seq
                        self.num_timeouts[relative_dest_qpn] += 1
                    else:
                        ## Unexpected out-of-order packet
                        ## Either no loss-detected or the out-of-order packet is not
                        ## a retransmission packet
                        logging.error("Unexpected out-of-order packet")
                        self.num_nacks[relative_dest_qpn] += 1
                        return False
                else:
                    logging.error("The sender should not send a non-data packet")
                    return False

        return (current_state['send'] == psn + num_data_pkts - 1) and \
               (current_state['ack']  == psn + num_data_pkts - 1) and \
               (current_state['nack'] == None)

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
        num_data_pkts   = self.num_data_pkts
        testing         = False
        self.num_error_data_pkts[relative_dest_qpn] = 0

        """
        Receiver states:
        - recv  : The largest seqnum of in-order packets
        - lost  : The first lost packet (has not recovered yet)
        - nack  : The recent nack (has not recovered yet)
        - ack   : The largest sequence that is (accumulatively) acknowledged
        """
        current_state = {'recv': psn - 1, 'lost': None, 'ack': None, 'nack': None}

        for ppacket in packet_list:
            if ppacket.is_roce_pkt() == False:
                continue

            current_dst_ip      = ppacket.get_dst_ip()
            current_dest_qpn    = ppacket.get_roce_dest_qp()
            current_pkt_seq     = ppacket.get_roce_pkt_seq()
            current_delivered   = ppacket.is_delivered()
            current_icrc_error  = ppacket.is_bit_error()
            current_dst_qp      = (current_dest_qpn, current_dst_ip)

            # We only consider the packets between (sender_qp, receiver_qp) after psn
            if not ((current_dst_qp == receiver_qp) or (current_dst_qp == sender_qp)):
                continue
            if not testing:
                if current_pkt_seq != psn:
                    continue
                else:
                    testing = True

            if current_dst_qp == receiver_qp:
                ## Packets received by the receiver
                if current_icrc_error == True:
                    # Increase ICRC error counters
                    self.num_error_data_pkts[relative_dest_qpn] += 1

                if current_delivered == False:
                    ## Ignore the undelivered (dropped or bit errors) packet from sender
                    continue

                if current_pkt_seq == current_state['recv'] + 1:
                    ## In-order arrival
                    current_state['recv'] = current_pkt_seq
                    ## if this packet fixes a loss
                    if current_pkt_seq == current_state['lost']:
                        current_state['lost'] = None
                        current_state['nack'] = None

                elif current_pkt_seq < current_state['recv'] + 1:
                    ## Ignore an out of order redundant transmission
                    pass

                elif current_state['lost'] == None:
                    current_state['lost'] = current_state['recv'] + 1

            elif current_dst_qp == sender_qp:
                ## Packets sent by the receiver
                if ppacket.is_roce_data_pkt():
                    logging.error("The receiver should not send a data packet")
                    return False

                if ppacket.is_roce_ack() == True:
                    ## An ACK packet
                    if (current_state['ack'] == None) or (current_pkt_seq >= current_state['ack']):
                        current_state['ack'] = current_pkt_seq
                    else:
                        ## ACK with smaller seqnum than already ACKed packets
                        logging.error("ACK with smaller seqnum than already ACKed packets")
                        return False

                elif ppacket.is_roce_nack() == True:
                    ## A NACK packet
                    if current_state['nack'] == None:
                        if current_pkt_seq == current_state['lost']:
                            current_state['nack'] = current_pkt_seq
                        else:
                            ## NACK a wrong packet
                            logging.error("NACK a wrong packet")
                            return False
                    else:
                        ## Only one in-flight NACK
                        logging.error("More than one in-flight NACK")
                        return False
                else:
                    ## Unknown type of packet sent by the receiver
                    continue

        return (current_state['recv'] == psn + num_data_pkts - 1) and \
               (current_state['lost'] == None) and \
               (current_state['nack'] == None) and \
               (current_state['ack']  == psn + num_data_pkts - 1)

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
                logging.error("Go back N sender state machine check failed for qpn %d: %s" % \
                              (relative_dest_qpn, self.qp_info_list[relative_dest_qpn]))
                result = False

            if self.check_receiver(relative_dest_qpn) == False:
                logging.error("Go back N receiver state machine check failed for qpn %d: %s" % \
                              (relative_dest_qpn, self.qp_info_list[relative_dest_qpn]))
                result = False

        return result

    def get_total_num_nacks(self):
        """ Return the total number of NACK packets in pcap """
        num_qps = len(self.qp_info_list)
        total_num_nacks = 0

        for relative_dest_qpn in range(num_qps):
            if self.num_nacks[relative_dest_qpn] == None:
                logging.error("Num of NACKs not initialized for qpn %d" % relative_dest_qpn)
                return None
            total_num_nacks += self.num_nacks[relative_dest_qpn]

        return total_num_nacks

    def get_total_num_error_data_pkts(self):
        """ Return the total number of data packets with (injected) bit-error in pcap """
        num_qps = len(self.qp_info_list)
        total_num_error_data_pkts = 0

        for relative_dest_qpn in range(num_qps):
            if self.num_error_data_pkts[relative_dest_qpn] == None:
                logging.error("Num of error data packets not initialized for qpn %d" % relative_dest_qpn)
                return None
            total_num_error_data_pkts += self.num_error_data_pkts[relative_dest_qpn]

        return total_num_error_data_pkts

    def get_total_num_timeouts(self):
        """ Return the total number of timeouts """
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
        # No available counters for Intel.
        logging.info("No available counters from Intel rdma sender, skip counters checking.")
        return True

    def check_intel_receiver_counters(self, receiver_counter=None):
        """ Check if the counters from Intel rdma receiver match the pcap file """
        # No available counters for Intel.
        logging.info("No available counters from Intel rdma receiver, skip counters checking.")
        return True

    def check_mlnx_sender_counters(self, sender_counter=None):
        """ Check if the counters from MLNX rdma sender match the pcap file

        Args:
            sender_counter (MLNXHostCounter): Counters of Mellanox rdma sender

        Returns:
            bool: True if the counters from MLNX rdma sender match the pcap file, False otherwise
        """
        result = True

        if sender_counter == None:
            logging.info("No available counters from rdma sender, skip counters checking.")
            return result

        ## packet-seq-error counter
        logging.info("Checking packet_seq_error counter")
        total_num_nacks = self.get_total_num_nacks()
        if sender_counter.get_num_packet_seq_err() != total_num_nacks:
            logging.error("The numbers of NACK packets derived from rdma sender (%d) does not match "\
                          "the number of NACK packets found in the pcap (%d)"
                          % (sender_counter.get_num_packet_seq_err(), total_num_nacks))
            result = False

        ## local-ack-timeout-err counter
        logging.info("Checking local_ack_timeout_err counter")
        total_num_timeouts = self.get_total_num_timeouts()
        if sender_counter.get_num_timeout_err() != total_num_timeouts:
            logging.error("The numbers of timeout derived from rdma sender (%d) does not match "\
                          "the number of timeout found in the pcap (%d)"
                          % (sender_counter.get_num_timeout_err(), total_num_timeouts))
            result = False

        return result

    def check_mlnx_receiver_counters(self, receiver_counter=None):
        """ Check if the counters from MLNX rdma receiver match the pcap file

        Args:
            receiver_counter (MLNXHostCounter): Counters of a Mellanox rdma receiver

        Returns:
            bool: True if the counters from MLNX rdma receiver match the pcap file, False otherwise
        """
        result = True

        if receiver_counter == None:
            logging.info("No available counters from rdma receiver, skip counters checking.")
            return result

        ## out-of-sequence counter
        logging.info("Checking out_of_sequence counter")
        total_num_nacks = self.get_total_num_nacks()
        if receiver_counter.get_num_out_of_sequence() != total_num_nacks:
            logging.error("The numbers of out-of-sequence packets derived from rdma receiver (%d) does not match "\
                          "the number of NACK packets found in the pcap (%d)"
                          % (receiver_counter.get_num_out_of_sequence(), total_num_nacks))
            result = False

        ## ICRC error counter
        logging.info("Checking icrc_error counter")
        total_num_error_data_pkts = self.get_total_num_error_data_pkts()
        if receiver_counter.get_num_icrc_errors() != total_num_error_data_pkts:
            logging.error("The numbers of ICRC error packets derived from rdma host (%d) and pcap (%d) are not consistent"
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
