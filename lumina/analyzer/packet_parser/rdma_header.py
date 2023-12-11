import dpkt, sys, logging
import lumina.analyzer.packet_parser.utils as utils

# RDMA packet types: Acknowledge, data, Congestion Notification Packet (CNP)
RDMA_PKT_TYPE_ACK   = 'ack'
RDMA_PKT_TYPE_DATA  = 'data'
RDMA_PKT_TYPE_CNP   = 'cnp'

"""
AETH = ACK Extended Transport Header
AETH 2-bit opcode (part of syndrome):
1. Acknowledge (ACK)
2. Receiver Not Ready (RNR) Negative Acknowledge (NAK)
3. Reserved
4. Negative Acknowledge (NAK)
"""
AETH_OPCODE_ACK     = 0
AETH_OPCODE_RNR_NAK = 1
AETH_OPCODE_RESERVE = 2
AETH_OPCODE_NAK     = 3

"""
Transport modes:
Reliable Connection (RC), Unreliable Connection (UC),
Reliable Datagram (RD), Unreliable Datagram (UD)
"""
_transports = {
    'RC': 0x00,
    'UC': 0x20,
    'RD': 0x40,
    'UD': 0x60,
}

_ops = {
    'SEND_FIRST': 0x00,
    'SEND_MIDDLE': 0x01,
    'SEND_LAST': 0x02,
    'SEND_LAST_WITH_IMMEDIATE': 0x03,
    'SEND_ONLY': 0x04,
    'SEND_ONLY_WITH_IMMEDIATE': 0x05,
    'RDMA_WRITE_FIRST': 0x06,
    'RDMA_WRITE_MIDDLE': 0x07,
    'RDMA_WRITE_LAST': 0x08,
    'RDMA_WRITE_LAST_WITH_IMMEDIATE': 0x09,
    'RDMA_WRITE_ONLY': 0x0a,
    'RDMA_WRITE_ONLY_WITH_IMMEDIATE': 0x0b,
    'RDMA_READ_REQUEST': 0x0c,
    'RDMA_READ_RESPONSE_FIRST': 0x0d,
    'RDMA_READ_RESPONSE_MIDDLE': 0x0e,
    'RDMA_READ_RESPONSE_LAST': 0x0f,
    'RDMA_READ_RESPONSE_ONLY': 0x10,
    'ACKNOWLEDGE': 0x11,
    'ATOMIC_ACKNOWLEDGE': 0x12,
    'COMPARE_SWAP': 0x13,
    'FETCH_ADD': 0x14,
}

def _opcode(transport, op):
    """ Given transport mode and operation, return the opcode of Basic Transport Header (BTH) and packet type

    Args:
        transport (str): The transport mode
        op (str): The operation

    Returns:
        tuple: A tuple of (opcode, packet type)
    """
    pkt_type = RDMA_PKT_TYPE_ACK if op in ['ACKNOWLEDGE', 'ATOMIC_ACKNOWLEDGE'] else RDMA_PKT_TYPE_DATA
    return (_transports[transport] + _ops[op], pkt_type)

# Opcode of Basic Transport Header (BTH) for Congestion Notification Packet (CNP)
RDMA_CNP_OPCODE = 0x81

# Basic Transport Header (BTH) opcodes and packet types
_bth_opcodes = dict([
    _opcode('RC', 'SEND_FIRST'),
    _opcode('RC', 'SEND_MIDDLE'),
    _opcode('RC', 'SEND_LAST'),
    _opcode('RC', 'SEND_LAST_WITH_IMMEDIATE'),
    _opcode('RC', 'SEND_ONLY'),
    _opcode('RC', 'SEND_ONLY_WITH_IMMEDIATE'),
    _opcode('RC', 'RDMA_WRITE_FIRST'),
    _opcode('RC', 'RDMA_WRITE_MIDDLE'),
    _opcode('RC', 'RDMA_WRITE_LAST'),
    _opcode('RC', 'RDMA_WRITE_LAST_WITH_IMMEDIATE'),
    _opcode('RC', 'RDMA_WRITE_ONLY'),
    _opcode('RC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE'),
    _opcode('RC', 'RDMA_READ_REQUEST'),
    _opcode('RC', 'RDMA_READ_RESPONSE_FIRST'),
    _opcode('RC', 'RDMA_READ_RESPONSE_MIDDLE'),
    _opcode('RC', 'RDMA_READ_RESPONSE_LAST'),
    _opcode('RC', 'RDMA_READ_RESPONSE_ONLY'),
    _opcode('RC', 'ACKNOWLEDGE'),
    _opcode('RC', 'ATOMIC_ACKNOWLEDGE'),
    _opcode('RC', 'COMPARE_SWAP'),
    _opcode('RC', 'FETCH_ADD'),

    _opcode('UC', 'SEND_FIRST'),
    _opcode('UC', 'SEND_MIDDLE'),
    _opcode('UC', 'SEND_LAST'),
    _opcode('UC', 'SEND_LAST_WITH_IMMEDIATE'),
    _opcode('UC', 'SEND_ONLY'),
    _opcode('UC', 'SEND_ONLY_WITH_IMMEDIATE'),
    _opcode('UC', 'RDMA_WRITE_FIRST'),
    _opcode('UC', 'RDMA_WRITE_MIDDLE'),
    _opcode('UC', 'RDMA_WRITE_LAST'),
    _opcode('UC', 'RDMA_WRITE_LAST_WITH_IMMEDIATE'),
    _opcode('UC', 'RDMA_WRITE_ONLY'),
    _opcode('UC', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE'),

    _opcode('RD', 'SEND_FIRST'),
    _opcode('RD', 'SEND_MIDDLE'),
    _opcode('RD', 'SEND_LAST'),
    _opcode('RD', 'SEND_LAST_WITH_IMMEDIATE'),
    _opcode('RD', 'SEND_ONLY'),
    _opcode('RD', 'SEND_ONLY_WITH_IMMEDIATE'),
    _opcode('RD', 'RDMA_WRITE_FIRST'),
    _opcode('RD', 'RDMA_WRITE_MIDDLE'),
    _opcode('RD', 'RDMA_WRITE_LAST'),
    _opcode('RD', 'RDMA_WRITE_LAST_WITH_IMMEDIATE'),
    _opcode('RD', 'RDMA_WRITE_ONLY'),
    _opcode('RD', 'RDMA_WRITE_ONLY_WITH_IMMEDIATE'),
    _opcode('RD', 'RDMA_READ_REQUEST'),
    _opcode('RD', 'RDMA_READ_RESPONSE_FIRST'),
    _opcode('RD', 'RDMA_READ_RESPONSE_MIDDLE'),
    _opcode('RD', 'RDMA_READ_RESPONSE_LAST'),
    _opcode('RD', 'RDMA_READ_RESPONSE_ONLY'),
    _opcode('RD', 'ACKNOWLEDGE'),
    _opcode('RD', 'ATOMIC_ACKNOWLEDGE'),
    _opcode('RD', 'COMPARE_SWAP'),
    _opcode('RD', 'FETCH_ADD'),

    _opcode('UD', 'SEND_ONLY'),
    _opcode('UD', 'SEND_ONLY_WITH_IMMEDIATE'),

    (RDMA_CNP_OPCODE, RDMA_PKT_TYPE_CNP),
])

class RDMA_BTH(dpkt.Packet):
    """ Class for RDMA Basic Transport Header (BTH)

    Attributes:
        __hdr__ (tuple): Header fields of BTH
    """
    __hdr__ = (
        ('opcode',        'B' , 0),
        ('migreq_headv',  'B' , 0),
        ('partition_key', 'H' , 0),
        ('reserved',      'B' , 0),
        ('dest_qp',       '3s', 0),
        ('ack_req',       'B' , 0),
        ('pkt_seqnum',    '3s', 0)
    )

    def is_ack(self):
        """ Return True if it is an ACK packet, False otherwise """
        if self.opcode in _bth_opcodes:
            return _bth_opcodes[self.opcode] == RDMA_PKT_TYPE_ACK
        else:
            logging.error("Unknown RDMA BTH opcode (%d)." % self.opcode)
            return False

    def is_data(self):
        """ Return True if it is a data packet, False otherwise """
        if self.opcode in _bth_opcodes:
            return _bth_opcodes[self.opcode] == RDMA_PKT_TYPE_DATA
        else:
            logging.error("Unknown RDMA BTH opcode (%d)." % self.opcode)
            return False

    def is_cnp(self):
        """ Return True if it is a CNP packet, False otherwise """
        if self.opcode in _bth_opcodes:
            return _bth_opcodes[self.opcode] == RDMA_PKT_TYPE_CNP
        else:
            logging.error("Unknown RDMA BTH opcode (%d)." % self.opcode)
            return False

    def is_read_req(self):
        """ Return True if it is a read request packet, False otherwise """
        if self.opcode in _bth_opcodes:
            op = self.opcode % 0x20
            return op == _ops['RDMA_READ_REQUEST']
        else:
            logging.error("Unknown RDMA BTH opcode (%d)." % self.opcode)
            return False

    def is_read_rsp(self):
        """ Return True if it is a read response packet, False otherwise """
        if self.opcode in _bth_opcodes:
            op = self.opcode % 0x20
            rdma_read_ops = [_ops['RDMA_READ_RESPONSE_FIRST'], _ops['RDMA_READ_RESPONSE_MIDDLE'],\
                             _ops['RDMA_READ_RESPONSE_LAST'], _ops['RDMA_READ_RESPONSE_ONLY']]
            return op in rdma_read_ops
        else:
            logging.error("Unknown RDMA opcode.")
            return False

    def is_read(self):
        """ Return True if it is a read packet, False otherwise """
        return self.is_read_req() or self.is_read_rsp()

    def is_write(self):
        """ Return True if it is a write packet, False otherwise """
        if self.opcode in _bth_opcodes:
            op = self.opcode % 0x20
            rdma_write_ops = [_ops['RDMA_WRITE_FIRST'], _ops['RDMA_WRITE_MIDDLE'],\
                              _ops['RDMA_WRITE_LAST'], _ops['RDMA_WRITE_LAST_WITH_IMMEDIATE'],\
                              _ops['RDMA_WRITE_ONLY'], _ops['RDMA_WRITE_ONLY_WITH_IMMEDIATE']]
            return op in rdma_write_ops
        else:
            logging.error("Unknown RDMA opcode.")
            sys.exit(-1)

    def get_dest_qp(self):
        """ Return the destination queue pair number """
        return utils.bytes_to_int(self.dest_qp)

    def get_psn(self):
        """ Return the packet sequence number """
        return utils.bytes_to_int(self.pkt_seqnum)

class RDMA_AETH(dpkt.Packet):
    """ Class for RDMA ACK Extended Transport Header (AETH)

    Attributes:
        __hdr__ (tuple): Header fields of AETH
    """
    __hdr__ = (
        ('syndrome', 'B' , 0),
        ('message_seqnum', '3s', 0)
    )

    def aeth_opcode(self):
        """ Return the opcode of AETH (the second and third bits of syndrome) """
        return (self.syndrome >> 5) & 3

    def is_nack(self):
        """ Return True if it is a NAK packet, False otherwise """
        return self.aeth_opcode() == AETH_OPCODE_NAK

    def is_ack(self):
        """ Return True if it is an ACK packet, False otherwise """
        return self.aeth_opcode() == AETH_OPCODE_ACK

class RDMA_RETH(dpkt.Packet):
    """ Class for RDMA Extended Transport Header (RETH)

    Attributes:
        __hdr__ (tuple): Header fields of RETH
    """
    __hdr__ = (
        ('virtual_addr', '8s', 0),
        ('remote_key', '4s', 0),
        ('dma_length', '4s', 0),
    )

    def get_virtual_addr(self):
        """ Return the virtual address """
        return self.virtual_addr

    def get_remote_key(self):
        """ Return the remote key """
        return self.remote_key

    def get_dma_length(self):
        """ Return the DMA length """
        return utils.bytes_to_int(self.dma_length)
