import logging

class IntegrityCheck:
    """ Class to check the integrity of the trace according to pcap files, and timestamps

    Attributes:
        packet_list (list of RRoCEPacket objects): list of packets
        switch_counter (SwitchCounter object): switch counter
        requester_ip_list (list of str): IP addresses of the requester
        responder_ip_list (list of str): IP addresses of the responder
    """
    def __init__(self, packet_list, switch_counter, requester_ip_list, responder_ip_list):
        """ Constructor

        Args:
            packet_list (list of RRoCEPacket objects): list of packets
            switch_counter (SwitchCounter object): switch counter
            requester_ip_list (list of str): IP addresses of the requester
            responder_ip_list (list of str): IP addresses of the responder

        Returns:
            N/A
        """
        self.packet_list = packet_list
        self.switch_counter = switch_counter
        self.requester_ip_list = requester_ip_list
        self.responder_ip_list = responder_ip_list

    def check_no_packet_loss(self):
        """ Check if there is any packet loss

        Returns:
            bool: True if there is no packet loss
        """
        result = True
        switch_port_counter = self.switch_counter.get_counter()

        num_requester_ingress_pkts = switch_port_counter['requester']['ingress']
        num_responder_ingress_pkts = switch_port_counter['responder']['ingress']
        num_total_ingress_pkts = num_requester_ingress_pkts + num_responder_ingress_pkts

        num_mirror_requester_pkts = switch_port_counter['requester-mirror']['egress']
        num_mirror_responder_pkts = switch_port_counter['responder-mirror']['egress']
        num_mirror_pkts = num_mirror_requester_pkts + num_mirror_responder_pkts

        if num_total_ingress_pkts != num_mirror_pkts:
            # Check if the switch has mirrored all the ingress packets
            logging.error("The total number of ingress packets is %d, "\
                          "while we only mirror %d packets"\
                          % (num_total_ingress_pkts, num_mirror_pkts))
            result = False

        if num_mirror_pkts != len(self.packet_list):
            # Check if we have captured all the mirrored packets
            logging.error("The total number of mirrored packets is %d, "\
                          "while we only capture %d packets"\
                          % (num_mirror_pkts, len(self.packet_list)))
            result = False
        return result

    def check_seqnum_consecutive(self):
        """ Check if sequence numbers of packets are consecutive

        Returns:
            bool: True if sequence numbers of packets are consecutive
        """
        packet_list = self.packet_list
        num_pkts = len(packet_list)
        expect_switch_seqnum = packet_list[0].get_switch_seqnum()

        for i in range(num_pkts):
            current_switch_seqnum = packet_list[i].get_switch_seqnum()
            if current_switch_seqnum != expect_switch_seqnum:
                logging.error("For packet %d: expected sequence number %d,"\
                              "but get sequence number %d."\
                              % (i, expect_switch_seqnum, current_switch_seqnum))
                return False
            expect_switch_seqnum += 1

        return True

    def __check_tstamp_increasing(self, pkt_list, max_deviation_sec):
        """ Check if timestamps of packets keep increasing

        Args:
            pkt_list (list of RRoCEPacket objets): list of packets
            max_deviation_sec (float): maximum deviation in second

        Returns:
            bool: True if timestamps of packets keep increasing
        """
        last_pkt_tstamp = 0

        for i in range(len(pkt_list)):
            current_pkt_tstamp = pkt_list[i].get_switch_timestamp()
            # In theory, the condition should be "current_ts >= last_ts".
            # However, we do see hardware has nanosecond-level deviations somtimes.
            if current_pkt_tstamp >= last_pkt_tstamp:
                last_pkt_tstamp = current_pkt_tstamp
                continue

            tstamp_delta = last_pkt_tstamp - current_pkt_tstamp
            # Tolerate some hardware deviations or timestamp wraparound
            if tstamp_delta <= max_deviation_sec or tstamp_delta >= (1<<47):
                last_pkt_tstamp = current_pkt_tstamp
                continue

            logging.error("Packet %d's timestamp (%.9f) < last one's timestamp (%.9f)" %\
                          (i, current_pkt_tstamp, last_pkt_tstamp))
            return False

        return True

    def check_tstamp(self):
        """ Check if timestamps of packets satisfy the following requirements:

        1. Timestamps of all the packets should keep increasing within a deviation
        2. Timestamps of packets of a single direction should keep *strictly* increasing.

        Returns:
            bool: True if timestamps of packets satisfy the requirements
        """
        # Up to 50ns deviation
        max_deviation_sec = 50e-9
        if self.__check_tstamp_increasing(self.packet_list, max_deviation_sec) == False:
            logging.error("Timestamps of all the packets do not keep increasing within %.9f sec" %\
                          (max_deviation_sec))
            return False

        # Packets sent by the requester and responder, respectively
        requester_pkt_list = []
        responder_pkt_list = []

        for pkt in self.packet_list:
            src_ip = pkt.get_src_ip()
            if src_ip in self.requester_ip_list:
                requester_pkt_list.append(pkt)
            elif src_ip in self.responder_ip_list:
                responder_pkt_list.append(pkt)

        #logging.info("%d requester packets, %d responder packets, %d packets in total" %\
        #             (len(requester_pkt_list), len(responder_pkt_list), len(self.packet_list)))

        if self.__check_tstamp_increasing(requester_pkt_list, 0) == False:
            logging.error("Timestamps of packets sent by the requester do not keep strictly increasing")
            return False

        if self.__check_tstamp_increasing(responder_pkt_list, 0) == False:
            logging.error("Timestamps of packets sent by the responder do not keep strictly increasing")
            return False

        return True

    def check(self):
        """ Check the integrity of the trace according to pcap files, and timestamps

        Returns:
            bool: True if the trace is valid
        """
        return self.check_no_packet_loss() and self.check_seqnum_consecutive() and self.check_tstamp()
