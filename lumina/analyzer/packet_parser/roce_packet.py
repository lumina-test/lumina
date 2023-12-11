import dpkt, socket
import lumina.analyzer.packet_parser.utils as utils
import lumina.analyzer.packet_parser.rdma_header as rdma_header

DEFAULT_RROCE_PORT   = 4791
EVENT_DROP_FLAG      = 1
EVENT_ECN_FLAG       = 2
EVENT_BIT_ERROR_FLAG = 3

TRIGGER_NONE    = 0
# Triggered by out of sequence (OOS) arriving packets
TRIGGER_OOS     = 1
# Triggered by timeout
TRIGGER_TIMEOUT = 2

class RRoCEPacket:
    """ Class for RDMA over Converged Ethernet (RoCE) v2 packet. RoCEv2 is also known
    as Routable RoCE, or RRoCE. RRoCE packet encpasulates Infiniband L4 packet over UDP.

    Attributes:
        timestamp (float): Timestamp of the packet
        buffer (bytes): Packet buffer
        eth (dpkt.ethernet.Ethernet): Ethernet header
        ip (dpkt.ip.IP): IP header
        udp (dpkt.udp.UDP): UDP header
        rdma_bth (rdma_header.RDMA_BTH): RDMA Base Transport Header (BTH)
        rdma_aeth (rdma_header.RDMA_AETH): RDMA Acknowledgement Extended Transport Header (AETH)
        rdma_reth (rdma_header.RDMA_RETH): RDMA Extended Transport Header (RETH)
        trigger (int): The triggering reason of the packet
    """
    def __init__(self, packet, roce_port=DEFAULT_RROCE_PORT):
        """ Constructor for RRoCEPacket

        Args:
            packet (bytes): The packet to parse
            roce_port (int, optional): UDP destination port number for RoCE. Defaults to DEFAULT_RROCE_PORT.

        Returns:
            N/A
        """
        self.timestamp, self.buffer = packet
        self.eth = dpkt.ethernet.Ethernet(self.buffer)
        if self.eth != None and self.eth.type == dpkt.ethernet.ETH_TYPE_IP:
            self.ip = self.eth.data
        else:
            self.ip = None

        if self.ip != None and self.ip.p == dpkt.ip.IP_PROTO_UDP:
            self.udp = self.ip.data
        else:
            self.udp = None

        if self.udp != None and self.udp.dport == roce_port:
            self.rdma_bth = rdma_header.RDMA_BTH(self.udp.data)
        else:
            self.rdma_bth = None

        if self.rdma_bth != None and self.rdma_bth.is_ack():
            self.rdma_aeth = rdma_header.RDMA_AETH(self.rdma_bth.data)
        else:
            self.rdma_aeth = None

        # At least RDMA WRITE and READ verbs require RETH
        if self.rdma_bth != None and (self.rdma_bth.is_write() or self.rdma_bth.is_read()):
            self.rdma_reth = rdma_header.RDMA_RETH(self.rdma_bth.data)
        else:
            self.rdma_reth = None

        # This field denotes why a RDMA READ request is triggered
        # It is used for RDMA READ retransmission analysis.
        self.trigger = TRIGGER_NONE

    def is_roce_pkt(self):
        """ Return True if it is a ROCE packet, False otherwise """
        return self.rdma_bth != None

    def is_roce_data_pkt(self):
        """ Return True if it is a ROCE data packet, False otherwise """
        return self.rdma_bth != None and self.rdma_bth.is_data()

    def is_roce_ack(self):
        """ Return True if it is a ROCE ACK packet, False otherwise """
        return self.rdma_aeth != None and self.rdma_aeth.is_ack()

    def is_roce_nack(self):
        """ Return True if it is a ROCE NACK packet, False otherwise """
        return self.rdma_aeth != None and self.rdma_aeth.is_nack()

    def is_roce_cnp(self):
        """ Return True if it is a ROCE CNP, False otherwise """
        return self.rdma_bth != None and self.rdma_bth.is_cnp()

    def is_roce_read(self):
        """ Return True if it is a ROCE Read packet, False otherwise """
        return self.rdma_bth != None and self.rdma_bth.is_read()

    def is_roce_read_req(self):
        """ Return True if it is a ROCE Read Request packet, False otherwise """
        return (self.rdma_bth != None) and (self.rdma_bth.is_read_req())

    def is_roce_read_rsp(self):
        """ Return True if it is a ROCE Read Response packet, False otherwise """
        return (self.rdma_bth != None) and (self.rdma_bth.is_read_rsp())

    def is_delivered(self):
        """
        Return True if the packet is delivered, False otherwise.
        The packet is delivered if it is not dropped and has no bit errors
        """
        return not (self.is_dropped() or self.is_bit_error())

    def is_dropped(self):
        """
        Return True if switch will drop the packet, False otherwise.
        The switch action is stored in ip.ttl.
        """
        return self.ip.ttl == EVENT_DROP_FLAG

    def is_ecn(self):
        """
        Return True if switch will mark the packet with ECN, False otherwise.
        The switch action is stored in ip.ttl.
        """
        return self.ip.ttl == EVENT_ECN_FLAG

    def is_bit_error(self):
        """
        Return True if switch will inject bit error to the packet, False otherwise.
        The switch action is stored in ip.ttl.
        """
        return self.ip.ttl == EVENT_BIT_ERROR_FLAG

    def get_event_str(self):
        """ Return the string representation of the event that switch will perform on the packet """
        if self.is_ecn():
            return "ECN marked"

        elif self.is_dropped():
            return "dropped"

        elif self.is_bit_error():
            return "bit error"

        else:
            return "no event"

    def get_switch_timestamp(self):
        """ Return the switch timestamp (in second), which is stored in the destination mac address """
        return (utils.bytes_to_int((self.eth.dst))) * 1e-9

    def get_switch_seqnum(self):
        """ Return the switch sequence number, which is stored in the source mac address """
        return utils.bytes_to_int(self.eth.src)

    def get_roce_pkt_seq(self):
        """ Return the RoCE packet sequence number, which is stored in the BTH. """
        if self.rdma_bth == None:
            return None
        return self.rdma_bth.get_psn()

    def get_roce_dest_qp(self):
        """ Return the RoCE destination queue pair number, which is stored in the BTH """
        if self.rdma_bth == None:
            return None
        return self.rdma_bth.get_dest_qp()

    def get_roce_virtual_addr(self):
        """ Return the RoCE packet's virtual address, which is stored in the RETH """
        if self.rdma_reth == None:
            return None
        return self.rdma_reth.get_virtual_addr()

    def get_roce_remote_key(self):
        """ Return the RoCE packet's remote key, which is stored in the RETH """
        if self.rdma_reth == None:
            return None
        return self.rdma_reth.get_remote_key()

    def get_roce_dma_length(self):
        """ Return the RoCE packet's DMA length, which is stored in the RETH """
        if self.rdma_reth == None:
            return None
        return self.rdma_reth.get_dma_length()

    def get_buffer(self):
        """ Return the packet buffer """
        return self.buffer

    def get_src_ip(self):
        """ Return source IP in string format A.B.C.D """
        return socket.inet_ntoa(self.ip.src)

    def get_dst_ip(self):
        """ Return destination IP in string format A.B.C.D """
        return socket.inet_ntoa(self.ip.dst)

    def get_orig_len(self):
        """ Return the original packet length since the switch may truncate the mirrored packet """
        if self.ip != None:
            return self.ip.len + dpkt.ethernet.ETH_HDR_LEN
        else:
            return len(bytes(self.get_buffer()))

    def set_trigger(self, trigger_val):
        """ Set the triggering reason of the packet

        Args:
            trigger_val (int): The triggering reason of the packet

        Returns:
            N/A
        """
        self.trigger = trigger_val

    def get_trigger(self):
        """ Return the triggering reason of the packet """
        return self.trigger
