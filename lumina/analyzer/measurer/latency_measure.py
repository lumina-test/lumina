import logging

class LatencyMeasure:
    """ Class to measure the latency between packets for some events,
        e.g., NACK latency, Retransmission latency, CNP latency

    Attributes:
        packet_list (list of RRoCEPacket objects): list of packets
        qp_info_list (list of dict): list of QP info with the following format:
              [{'psn_rcv': initial packet sequence number from the receiver qp,
                'psn_snd': initial packet sequence number from the sender qp,
                'qpn_rcv': receiver qp number,
                'qpn_snd': sender qp number,
                'ip_rcv' : receiver IP
                'ip_snd' : sender IP}]
        is_read (bool): if the QPs use RDMA read verb
    """
    def __init__(self, packet_list, qp_info_list, is_read=False):
        """ Constructor

        Args:
            packet_list (list of RRoCEPacket objects): list of packets
            qp_info_list (list of dict): list of QP info with the following format:
                  [{'psn_rcv': initial packet sequence number from the receiver qp,
                    'psn_snd': initial packet sequence number from the sender qp,
                    'qpn_rcv': receiver qp number,
                    'qpn_snd': sender qp number,
                    'ip_rcv' : receiver IP
                    'ip_snd' : sender IP}]
            is_read (bool): if the QPs use RDMA read verb (default: False)

        Returns:
            N/A
        """
        self.packet_list = packet_list
        self.qp_info_list = qp_info_list
        self.is_read = is_read

    def get_peer_qp_info(self, dest_qpn, dest_ip):
        """ Get the info of the peer QP (qpn, ip) of a given qp (qpn, ip)

        Args:
            dest_qpn (int): destination QP number
            dest_ip (str): destination IP

        Returns:
            int: peer QP number (None if not found)
            str: peer IP (None if not found)
        """
        for qp_info in self.qp_info_list:
            if qp_info['qpn_snd'] == dest_qpn and qp_info['ip_snd'] == dest_ip:
                return qp_info['qpn_rcv'], qp_info['ip_rcv']
            elif qp_info['qpn_rcv'] == dest_qpn and qp_info['ip_rcv'] == dest_ip:
                return qp_info['qpn_snd'], qp_info['ip_snd']

        return None, None

    def get_bit_error_pkts(self, relative_dest_qpn=None):
        """ Get the packets marked with bit error flag

        Args:
            relative_dest_qpn (int): the relative destination QP number (None if not specified)

        Returns:
            list of RRoCEPacket objects: the list of packets marked with bit error flag
        """
        error_pkt_list = []

        if relative_dest_qpn != None:
            dest_qpn = self.qp_info_list[relative_dest_qpn]['qpn_rcv']
            dest_ip = self.qp_info_list[relative_dest_qpn]['ip_rcv']

        for packet in self.packet_list:
            if packet.is_bit_error() == False:
                continue

            if relative_dest_qpn == None or \
               (packet.get_roce_dest_qp() == dest_qpn and packet.get_dst_ip() == dest_ip):
                error_pkt_list.append(packet)

        return error_pkt_list

    def get_dropped_pkts(self, relative_dest_qpn=None):
        """ Get the packets marked with drop flag

        Args:
            relative_dest_qpn (int): the relative destination QP number (None if not specified)

        Returns:
            list of RRoCEPacket objects: the list of packets marked with drop flag
        """
        dropped_pkt_list = []

        if relative_dest_qpn != None:
            dest_qpn = self.qp_info_list[relative_dest_qpn]['qpn_rcv']
            dest_ip = self.qp_info_list[relative_dest_qpn]['ip_rcv']

        for packet in self.packet_list:
            if packet.is_dropped() == False:
                continue

            if relative_dest_qpn == None or \
               (packet.get_roce_dest_qp() == dest_qpn and packet.get_dst_ip() == dest_ip):
                dropped_pkt_list.append(packet)

        return dropped_pkt_list

    def get_ecn_pkts(self):
        """ Get the packets marked with ECN

        Returns:
            list of RRoCEPacket objects: the list of packets marked with ECN
        """
        ecn_pkt_list = []

        for packet in self.packet_list:
            if packet.is_ecn():
                ecn_pkt_list.append(packet)

        return ecn_pkt_list

    def get_cnp_pkts(self):
        """ Get the congestion notification packets

        Returns:
            list of RRoCEPacket objects: the list of congestion notification packets
        """
        cnp_pkt_list = []

        for packet in self.packet_list:
            if packet.is_cnp():
                cnp_pkt_list.append(packet)

        return cnp_pkt_list

    def get_undelivered_pkts(self, relative_dest_qpn = None):
        """ Get the undelivered packets (dropped or marked with bit error)

        Args:
            relative_dest_qpn (int): the relative destination QP number (None if not specified)

        Returns:
            list of RRoCEPacket objects: the list of undelivered packets
        """
        undelivered_pkt_list = []

        if relative_dest_qpn != None:
            dest_qpn = self.qp_info_list[relative_dest_qpn]['qpn_rcv']
            dest_ip = self.qp_info_list[relative_dest_qpn]['ip_rcv']

        for packet in self.packet_list:
            if packet.is_delivered() == True:
                continue

            if relative_dest_qpn == None or \
               (packet.get_roce_dest_qp() == dest_qpn and packet.get_dst_ip() == dest_ip):
                undelivered_pkt_list.append(packet)

        return undelivered_pkt_list

    def get_nack(self, undelivered_pkt):
        """ Given an undelivered packet, return the NACK packet that triggers its retransmission.
            If there's no NACK packet found for the undelivered packet, return None.
            Note that for RDMA READ, NACK is essentially a READ request packet that triggers retransmission

        Args:
            undelivered_pkt (RRoCEPacket object): the undelivered packet

        Returns:
            RRoCEPacket object: the NACK packet that triggers the retransmission of the undelivered packet
                                (None if not found)
        """
        undelivered_pkt_dest_qpn = undelivered_pkt.get_roce_dest_qp()
        undelivered_pkt_dst_ip  = undelivered_pkt.get_dst_ip()
        undelivered_pkt_psn = undelivered_pkt.get_roce_pkt_seq()
        undelivered_pkt_switch_seqnum = undelivered_pkt.get_switch_seqnum()
        matched_dest_qpn, matched_dst_ip = self.get_peer_qp_info(undelivered_pkt_dest_qpn, undelivered_pkt_dst_ip)

        if matched_dest_qpn == None or matched_dst_ip == None:
            logging.error("QP info of the undelivered packet not found in qp_info_list dumped by switch")
            return None

        for packet in self.packet_list:
            if self.is_same_roce_data_pkt(packet, undelivered_pkt) and \
               packet.get_switch_seqnum() > undelivered_pkt_switch_seqnum:
                return None

            if ((self.is_read and packet.is_roce_read_req()) or packet.is_roce_nack()) and \
               packet.get_dst_ip() == matched_dst_ip and \
               packet.get_roce_dest_qp() == matched_dest_qpn and \
               packet.get_roce_pkt_seq() == undelivered_pkt_psn and \
               packet.get_switch_seqnum() > undelivered_pkt_switch_seqnum:
                ## We return the first packet appears after the undelivered packet and matches the undelivered packet
                return packet

        return None

    def get_qp_first_nack_before_retrans(self, undelivered_pkt):
        """ For an undelivered packet, return the first NACK packet on its QP between it and its retransmission.
            If there's no NACK packet found before the retransmission, return None.
            Note that for RDMA READ, NACK is essentially a READ request packet

        Args:
            undelivered_pkt (RRoCEPacket object): the undelivered packet

        Returns:
            RRoCEPacket object: the first NACK packet on the QP between the undelivered packet and its retransmission
                                (None if not found)
        """
        undelivered_pkt_dest_qpn = undelivered_pkt.get_roce_dest_qp()
        undelivered_pkt_dst_ip  = undelivered_pkt.get_dst_ip()
        undelivered_pkt_psn = undelivered_pkt.get_roce_pkt_seq()
        undelivered_pkt_switch_seqnum = undelivered_pkt.get_switch_seqnum()
        matched_dest_qpn, matched_dst_ip = self.get_peer_qp_info(undelivered_pkt_dest_qpn, undelivered_pkt_dst_ip)

        if matched_dest_qpn == None or matched_dst_ip == None:
            logging.error("QP info of the undelivered packet not found in qp_info_list dumped by switch")
            return None

        for packet in self.packet_list:
            if self.is_same_roce_data_pkt(packet, undelivered_pkt) and \
               packet.get_switch_seqnum() > undelivered_pkt_switch_seqnum:
                return None

            if ((self.is_read and packet.is_roce_read_req()) or packet.is_roce_nack()) and \
               packet.get_dst_ip() == matched_dst_ip and \
               packet.get_roce_dest_qp() == matched_dest_qpn and \
               packet.get_roce_pkt_seq() <= undelivered_pkt_psn and \
               packet.get_switch_seqnum() > undelivered_pkt_switch_seqnum:
                return packet

        return None

    def get_qp_next_delivered_pkt(self, current_pkt):
        """ For a packet, return the next delivered packet on the same QP.

        Args:
            current_pkt (RRoCEPacket object): the current packet

        Returns:
            RRoCEPacket object: the next delivered packet on the same QP (None if not found)
        """
        switch_seqnum = current_pkt.get_switch_seqnum()

        for packet in self.packet_list:
            if self.is_same_qp_roce_data_pkt(packet, current_pkt) and \
               packet.get_switch_seqnum() > switch_seqnum and \
               packet.is_delivered():
                return packet

        return None

    def get_retransmit_pkt(self, undelivered_pkt):
        """ Given an undelivered packet, return its retransmission packet.

        Args:
            undelivered_pkt (RRoCEPacket object): the undelivered packet

        Returns:
            RRoCEPacket object: the retransmission packet of the undelivered packet (None if not found)
        """
        undelivered_pkt_switch_seqnum = undelivered_pkt.get_switch_seqnum()

        for packet in self.packet_list:
            if self.is_same_roce_data_pkt(packet, undelivered_pkt) and \
               packet.get_switch_seqnum() > undelivered_pkt_switch_seqnum:
                ## We return the first packet appears after the undelivered packet and matches the undelivered packet
                return packet

        return None

    def get_latency_between_pkts(self, packet_alpha, packet_beta):
        """ Return the time of packet_beta - time of packet_alpha in seconds

        Args:
            packet_alpha (RRoCEPacket object): the first packet
            packet_beta (RRoCEPacket object): the second packet

        Returns:
            float: the time difference between two packets in seconds
        """
        return packet_beta.get_switch_timestamp() - packet_alpha.get_switch_timestamp()

    def is_same_roce_data_pkt(self, packet_alpha, packet_beta):
        """ Return if two packets are the same RoCE data packet (same src ip, dst ip, dest qp, and psn)

        Args:
            packet_alpha (RRoCEPacket object): the first packet
            packet_beta (RRoCEPacket object): the second packet

        Returns:
            bool: True if two packets are the same RoCE data packet, False otherwise
        """
        return packet_alpha.get_src_ip() == packet_beta.get_src_ip() and \
               packet_alpha.get_dst_ip() == packet_beta.get_dst_ip() and \
               packet_alpha.get_roce_dest_qp() == packet_beta.get_roce_dest_qp() and \
               packet_alpha.get_roce_pkt_seq() == packet_beta.get_roce_pkt_seq()

    def is_same_qp_roce_data_pkt(self, packet_alpha, packet_beta):
        """ Return if two packets are RoCE data packets on the same QP (same src ip, dst ip, and dest qp)

        Args:
            packet_alpha (RRoCEPacket object): the first packet
            packet_beta (RRoCEPacket object): the second packet

        Returns:
            bool: True if two packets are RoCE data packets on the same QP, False otherwise
        """
        return packet_alpha.get_src_ip() == packet_beta.get_src_ip() and \
               packet_alpha.get_dst_ip() == packet_beta.get_dst_ip() and \
               packet_alpha.get_roce_dest_qp() == packet_beta.get_roce_dest_qp()

    def get_qp_next_delivered_pkt_latency(self, pkt):
        """ Get the latency between 'pkt' and next 'delivered' packet on the same QP

        Args:
            pkt (RRoCEPacket object): the packet

        Returns:
            float: the latency between 'pkt' and next 'delivered' packet on the same QP
                   (None if not found)
        """

        next_pkt = self.get_qp_next_delivered_pkt(pkt)
        if next_pkt is None:
            return None

        return self.get_latency_between_pkts(pkt, next_pkt)

    def get_nack_gen_latency(self, undelivered_pkt):
        """ For an undelivered packet, return the NACK generation latency, i.e., the duration from the detection of
            the undelivered packet to the generation of the NACK packet that triggers its retransmission.

        Args:
            undelivered_pkt (RRoCEPacket object): the undelivered packet

        Returns:
            float: the NACK generation latency for the undelivered packet (None if not found)
        """
        nack_pkt = self.get_nack(undelivered_pkt)
        if nack_pkt == None:
            return None

        # NACK should be triggered by the next delivered packet on the same QP
        next_delivered_pkt = self.get_qp_next_delivered_pkt(undelivered_pkt)
        if self.is_same_roce_data_pkt(next_delivered_pkt, undelivered_pkt):
            # We should never reach here
            return None

        nack_gen_latency = self.get_latency_between_pkts(next_delivered_pkt, nack_pkt)
        return nack_gen_latency

    def get_nack_resp_latency(self, undelivered_pkt):
        """ For an undelivered packet, return the NACK response latency, i.e., the duration from the generation of
            the NACK packet to the retransmission of this undelivered packet.

        Args:
            undelivered_pkt (RRoCEPacket object): the undelivered packet

        Returns:
            float: the NACK response latency for the undelivered packet (None if not found)
        """
        nack_pkt = self.get_nack(undelivered_pkt)
        if nack_pkt == None:
            return None

        retransmit_pkt = self.get_retransmit_pkt(undelivered_pkt)
        if retransmit_pkt == None:
            return None

        nack_resp_latency = self.get_latency_between_pkts(nack_pkt, retransmit_pkt)
        return nack_resp_latency

    def get_retransmit_latency(self, undelivered_pkt):
        """ For an undelivered packet, return the retransmission latency, i.e., the duration from the packet
            to its retransmission.

        Args:
            undelivered_pkt (RRoCEPacket object): the undelivered packet

        Returns:
            float: the retransmission latency for the undelivered packet (None if not found)
        """
        retransmit_pkt = self.get_retransmit_pkt(undelivered_pkt)
        if retransmit_pkt == None:
            return None

        retransmit_latency = self.get_latency_between_pkts(undelivered_pkt, retransmit_pkt)
        return retransmit_latency

    def get_nack_gen_latency_list(self, relative_dest_qpn=None):
        """ Return a list of NACK generation latency for all undelivered packets with relative_dest_qpn

        Args:
            relative_dest_qpn (int): the relative destination QP number (None if not specified)

        Returns:
            list of float: a list of NACK generation latency for all undelivered packets with relative_dest_qpn
        """
        undelivered_pkts = self.get_undelivered_pkts(relative_dest_qpn)
        nack_latency_list = []

        for undelivered_pkt in undelivered_pkts:
            nack_pkt = self.get_nack(undelivered_pkt)
            if nack_pkt == None:
                nack_latency_list.append(None)
            else:
                nack_latency = self.get_latency_between_pkts(undelivered_pkt, nack_pkt)
                nack_latency_list.append(nack_latency)

        return nack_latency_list

    def get_retransmit_latency_list(self, relative_dest_qpn):
        """ Return a list of retransmission latency for all undelivered packets with relative_dest_qpn

        Args:
            relative_dest_qpn (int): the relative destination QP number (None if not specified)

        Returns:
            list of float: a list of retransmission latency for all undelivered packets with relative_dest_qpn
        """
        undelivered_pkts = self.get_undelivered_pkts(relative_dest_qpn)
        retransmit_latency_list = []

        for undelivered_pkt in undelivered_pkts:
            retransmit_pkt = self.get_retransmit_pkt(undelivered_pkt)
            if retransmit_pkt == None:
                retransmit_latency_list.append(None)
            else:
                retransmit_latency = self.get_latency_between_pkts(undelivered_pkt, retransmit_pkt)
                retransmit_latency_list.append(retransmit_latency)

        return retransmit_latency_list
