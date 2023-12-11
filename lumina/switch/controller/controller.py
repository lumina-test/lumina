import logging
import random
import sys
import re
import socket
import yaml
import argparse
import collections

import bfrt_grpc.client as gc
from functools import partial
from pal_rpc.ttypes import *
from res_pd_rpc.ttypes import *
from pkt_pd_rpc.ttypes import *
import pd_base_tests
from pal_rpc.pal import Iface
from config_loader import config_translate, ConfigLoader
from config_loader import EVENT_TYPE_DROP, EVENT_TYPE_ECN, EVENT_TYPE_BIT_ERROR
from add_ports import add_ports, wait_for_switchd_ready

dev_id = 0
MIR_SESS_COUNT = 1024
MAX_SID_NORM = 1015
MAX_SID_COAL = 1023
BASE_SID_NORM = 1
BASE_SID_COAL = 1016


port_speed_dic = {
    'NONE': pal_port_speed_t.BF_SPEED_NONE,
    '1G'  : pal_port_speed_t.BF_SPEED_1G,
    '10G' : pal_port_speed_t.BF_SPEED_10G,
    '25G' : pal_port_speed_t.BF_SPEED_25G,
    '40G' : pal_port_speed_t.BF_SPEED_40G,
    '50G' : pal_port_speed_t.BF_SPEED_50G,
    '100G': pal_port_speed_t.BF_SPEED_100G,
    '200G': pal_port_speed_t.BF_SPEED_200G,
    '400G': pal_port_speed_t.BF_SPEED_400G,
}
fec_type_dic = {
    'NONE': pal_fec_type_t.BF_FEC_TYP_NONE,
    'FC'  : pal_fec_type_t.BF_FEC_TYP_FIRECODE,
    'RS'  : pal_fec_type_t.BF_FEC_TYP_REED_SOLOMON,
}

logger = logging.getLogger('Test')
logger.setLevel(logging.DEBUG)

def str_to_int(str):
    """ Convert string to integer

    Args:
        str (str): String to convert

    Returns:
        Converted integer (int)
    """
    m = re.search(r'\d+', str)
    numeric = m.group()
    return int(numeric)

def unicode_to_str(data):
    """ Convert unicode to string

    Args:
        data (unicode): Data to convert

    Returns:
        Converted string (str)
    """
    if sys.version_info > (3, 0):
        return data
    else:
        return str(data)

def unicode_dict_to_str(data):
    """ Convert the keys and values from unicode to normal string """
    if sys.version_info > (3, 0):
        return data
    else:
        if isinstance(data, basestring):
            return str(data)
        elif isinstance(data, collections.Mapping):
            return dict(map(unicode_dict_to_str, data.iteritems()))
        elif isinstance(data, collections.Iterable):
            return type(data)(map(unicode_dict_to_str, data))
        else:
            return data

def make_port(pipe, local_port):
    """  Given a pipe and a port within that pipe construct the global port number
    Args:
        pipe (int): Pipe number
        local_port (int): Local port number

    Returns:
        Global port number (int)
    """
    return (pipe << 7) | local_port

def port_to_local_port(port):
    """ Given a global port number return the local port number within the pipe

    Args:
        port (int): Global port number

    Returns:
        Local port number (int)
    """
    local_port = port & 0x7F
    assert (local_port < 72)
    return local_port

def port_to_pipe(port):
    """ Given a port return the pipe it belongs to.

    Args:
        port (int): Global port number

    Returns:
        Pipe number (int)
    """
    local_port = port_to_local_port(port)
    pipe = (port >> 7) & 0x3
    assert (port == make_port(pipe, local_port))
    return pipe

def mac_str_to_int(mac_str):
    """ Convert mac string to integer

    Args:
        mac_str (str): Mac address string

    Returns:
        Mac address integer (int)
    """
    mac_int = int(re.sub(":|\.|-| ", "", mac_str), 16)
    return mac_int

class Dumper(yaml.Dumper):
    def increase_indent(self, flow=False, *args, **kwargs):
        ## Set indent for yaml dump
        return super(Dumper, self).increase_indent(flow=flow, indentless=False)

class ConfigTable:
    """ Class for configuring tables in P4 program """
    def __init__(self, p4_name, config_loader, grpc_addr):
        """ Constructor

        Args:
            self (ConfigTable): self
            p4_name (str): P4 program name
            config_loader (ConfigLoader): ConfigLoader object
            grpc_addr (str): gRPC address of the switch

        Returns:
            N/A
        """
        client_id = 0
        self.bfrt_info = None
        if grpc_addr is None or grpc_addr is 'localhost':
            grpc_addr = 'localhost:50052'
        else:
            grpc_addr = grpc_addr + ":50052"
        self.interface = gc.ClientInterface(grpc_addr,
                                            client_id=client_id,
                                            device_id=0,
                                            notifications=None,
		                                    perform_subscribe=True)
        self.interface.bind_pipeline_config(p4_name)

        self.conf_listen_port      = config_loader.listen_port()
        self.conf_rewrite_udp_port = config_loader.rewrite_udp_dst_port()
        self.conf_forward          = config_loader.forward()
        self.conf_arp              = config_loader.arp()
        self.conf_mirror           = config_loader.mirror()
        self.conf_data_pkt_events  = config_loader.data_pkt_events()
        self.conf_port_list        = config_loader.get_port_list()
        self.conf_num_pkts_per_msg = config_loader.get_num_pkts_per_msg()
        self.conf_num_msgs_per_qp  = config_loader.get_num_msgs_per_qp()

    def configure_forwarding(self, bfrt_info, target):
        """ Configure the forwarding table by removing all entries and adding new entries

        Args:
            self (ConfigTable): self
            bfrt_info (BfRtInfo): BfRtInfo (Barefoot Runtime Info) object
            target (Target): Target object

        Returns:
            N/A
        """
        forward_table = bfrt_info.table_get("SwitchIngress.forward_table")

        self.del_entries(table=forward_table, target=target)

        forward_table.info.key_field_annotation_add("hdr.ethernet.dst_addr", "mac")

        for table_entry in self.conf_forward:
            dst_mac = table_entry['dst-mac']
            eg_port = table_entry['eg-port']
            forward_table_bfrt_key = forward_table.make_key([gc.KeyTuple('hdr.ethernet.dst_addr', dst_mac)])
            forward_table_bfrt_data = forward_table.make_data([gc.DataTuple('dst_port', eg_port)] , "SwitchIngress.l2_forward")
            forward_table.entry_add(target, [forward_table_bfrt_key], [forward_table_bfrt_data])

    def configure_arp(self, bfrt_info, target):
        """ Configure the ARP table by removing all entries and adding new entries

        Args:
            self (ConfigTable): self
            bfrt_info (BfRtInfo): BfRtInfo (Barefoot Runtime Info) object
            target (Target): Target object

        Returns:
            N/A
        """
        arp_table = bfrt_info.table_get("SwitchIngress.arp_table")

        self.del_entries(table=arp_table, target=target)

        arp_table.info.key_field_annotation_add("hdr.arp.target_ip", "ipv4")
        arp_table.info.data_field_annotation_add("resp_mac", "SwitchIngress.arp_hit", "mac")

        for table_entry in self.conf_arp:
            dst_mac = table_entry['dst-mac']
            dst_ip  = table_entry['dst-ip']
            arp_table_bfrt_key = arp_table.make_key([gc.KeyTuple('hdr.arp.opcode', 1), gc.KeyTuple('hdr.arp.target_ip', dst_ip)])
            arp_table_bfrt_data = arp_table.make_data([gc.DataTuple('resp_mac', dst_mac)], "SwitchIngress.arp_hit")
            arp_table.entry_add(target, [arp_table_bfrt_key], [arp_table_bfrt_data])

    def configure_mirroring(self, bfrt_info, target):
        """ Configure the mirroring related tables by removing all entries and adding new entries

        Args:
            self (ConfigTable): self
            bfrt_info (BfRtInfo): BfRtInfo (Barefoot Runtime Info) object
            target (Target): Target object

        Returns:
            N/A
        """
        mirror_cfg_table = bfrt_info.table_get("$mirror.cfg")
        set_mirror_ig_table = bfrt_info.table_get("SwitchIngress.set_mirror_ig_table")
        add_timestamp_table = bfrt_info.table_get("SwitchEgress.add_timestamp_table")

        self.del_entries(table=mirror_cfg_table, target=target)
        self.del_entries(table=set_mirror_ig_table, target=target)
        self.del_entries(table=add_timestamp_table, target=target)

        sids = random.sample(range(BASE_SID_NORM, MAX_SID_NORM), len(self.conf_mirror))
        sids.sort()

        # * The mirror_cfg table controls what a specific mirror session id does to a packet.
        # * This is programming the mirror block in hardware.
        # * mirror_cfg_bfrt_key is equivalent to old "mirror_id" in PD term
        index = 0
        for sid, entry in zip(sids, self.conf_mirror):
            direction = entry['direction']
            dst_port  = entry['dst-port']
            src_port  = entry['src-port']
            mirror_cfg_bfrt_key  = mirror_cfg_table.make_key([gc.KeyTuple('$sid', sid)])
            mirror_cfg_bfrt_data = mirror_cfg_table.make_data([
                gc.DataTuple('$direction', str_val=config_translate(direction)),
                gc.DataTuple('$ucast_egress_port', dst_port),
                gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                gc.DataTuple('$session_enable', bool_val=True),
            ], "$normal")
            mirror_cfg_table.entry_add(target, [mirror_cfg_bfrt_key], [mirror_cfg_bfrt_data])

            set_mirror_ig_table_bfrt_key = set_mirror_ig_table.make_key([gc.KeyTuple('ig_md.mirror_index', index)])
            set_mirror_ig_table_bfrt_data = set_mirror_ig_table.make_data([gc.DataTuple('ig_mir_ses', sid)], 'SwitchIngress.set_mirror_ig')
            set_mirror_ig_table.entry_add(target, [set_mirror_ig_table_bfrt_key], [set_mirror_ig_table_bfrt_data])
            index += 1

        add_timestamp_table.default_entry_set(target, add_timestamp_table.make_data([gc.DataTuple('dst_port', self.conf_rewrite_udp_port)], 'SwitchEgress.add_timestamp'))

    def parse_msg(self, msg):
        """ Parse the message received from RDMA traffic generator

        Args:
            self (ConfigTable): self
            msg (str): Message received from RDMA traffic generator with the following format:
            [verb];[number of QPs];[local QPN],[local PSN],[local GID];[remote QPN],[remote PSN],[remote GID];...&

        Returns:
            A list of dictionaries, each dictionary contains the information for a QP, or None if the message is invalid
        """
        msg = msg.strip('\0').strip("&")
        print("Parsing message %s" % msg)
        words = msg.split(";")

        if len(words) <= 2:
            print("Invalid message %s" % msg)
            return None

        ib_verb = str(words[0])
        verb_to_qp_list = collections.defaultdict(list)
        if '_' in ib_verb:
            # dual verbs
            # verb is in the format of "[verb_a]_[verb_b]" (e.g., "SEND_READ")
            ib_verb_a, ib_verb_b = ib_verb.split('_')
            # num_qps is in the format of "[num_qps_verb_a]_[num_qps_verb_b]" (e.g., "2_2")
            num_qps_verb_a, num_qps_verb_b = words[1].split('_')
            num_qps_verb_a = int(num_qps_verb_a)
            num_qps_verb_b = int(num_qps_verb_b)
            # total number of QPs
            num_qps = num_qps_verb_a + num_qps_verb_b

            verb_to_qp_list[ib_verb_a] += range(num_qps_verb_a)
            verb_to_qp_list[ib_verb_b] += range(num_qps_verb_a, num_qps)

            print("RDMA verbs: %s %s" % (ib_verb_a, ib_verb_b))
            print("Number of queue pairs: %d (%d for %s, %d for %s)" % \
                  (num_qps, num_qps_verb_a, ib_verb_a, num_qps_verb_b, ib_verb_b))
            print("Verb to QP list:", verb_to_qp_list)
        else:
            num_qps = int(words[1])
            verb_to_qp_list[ib_verb] += range(num_qps)
            print("RDMA verb: %s" % (ib_verb))
            print("Number of queue pairs: %d" % (num_qps))
            print("Verb to QP list:", verb_to_qp_list)

        if len(words) != 2 + 2 * num_qps:
            print("Incomplete message %s" % msg)
            return None

        batched_qp_info = words[2:]
        assert ib_verb in set(['SEND', 'READ', 'WRITE', 'SEND_READ']), "Invalid IB verb"
        print("ib-verb: %s" % (ib_verb))
        sys.stdout.flush()

        requester_eg_port = ([entry['eg-port'] for entry in self.conf_forward
                              if entry['host'] == 'requester'] + [None])[0]
        responder_eg_port = ([entry['eg-port'] for entry in self.conf_forward
                              if entry['host'] == 'responder'] + [None])[0]
        print("requester_eg_port: %d, responder_eg_port: %d" % (requester_eg_port, responder_eg_port))
        if (requester_eg_port == None) or (responder_eg_port == None):
            print("Cannot find host's eth address in the forwarding table")
            sys.exit(-1)

        for word in batched_qp_info:
            qpn, psn, gid = word.split(",")
            print("QPN: %s" % qpn, "PSN: %s" % psn, "GID: %s" % gid)

        qp_info_list = []
        for i in range(num_qps):
            ## Process the infomation for each qp and store them in qp_info_list
            ## qp_info_list contains
            ## - qpn_snd/rcv     : qpn at the sender/receiver side
            ## - psn_snd/rcv     : the initial psn of this qp at sender/receiver side
            ## - ip_snd/rcv      : ip address of the sender/receiver for this qp
            ## - snd_sw_port/rcv : the switch port connected to sender/receiver
            ## The sender/receiver means it's the sender/receiver of data packets
            requester_qp_info = batched_qp_info[2*i].split(",")
            responder_qp_info = batched_qp_info[2*i+1].split(",")
            qpn_req = str_to_int(requester_qp_info[0])
            psn_req = str_to_int(requester_qp_info[1])
            ip_req  = unicode_to_str(requester_qp_info[2].split(":")[3])
            qpn_rsp = str_to_int(responder_qp_info[0])
            psn_rsp = str_to_int(responder_qp_info[1])
            ip_rsp  = unicode_to_str(responder_qp_info[2].split(":")[3])

            if i in verb_to_qp_list['READ']:
                # With ib-read, the psn of data packets is decided by requester, so psn_snd=psn_req
                # With ib-send-read, the first half of QPs are doing send-receive, the second half
                # QPs are doing read
                qp_info_list.append({'qpn_snd'     : qpn_rsp,
                                     'psn_snd'     : psn_req,
                                     'ip_snd'      : ip_rsp,
                                     'snd_sw_port' : responder_eg_port,
                                     'qpn_rcv'     : qpn_req,
                                     'psn_rcv'     : psn_rsp,
                                     'ip_rcv'      : ip_req,
                                     'rcv_sw_port' : requester_eg_port})
            else:
                qp_info_list.append({'qpn_snd'     : qpn_req,
                                     'psn_snd'     : psn_req,
                                     'ip_snd'      : ip_req,
                                     'snd_sw_port' : requester_eg_port,
                                     'qpn_rcv'     : qpn_rsp,
                                     'psn_rcv'     : psn_rsp,
                                     'ip_rcv'      : ip_rsp,
                                     'rcv_sw_port' : responder_eg_port})
        return qp_info_list

    def configure_counter(self, bfrt_info, target):
        """ Initialzie all the counters to 0

        Args:
            self (ConfigTable): self
            bfrt_info (BfRtInfo): BfRtInfo (Barefoot Runtime Info) object
            target (Target): Target object

        Returns:
            N/A
        """
        ingress_counter_table = bfrt_info.table_get("SwitchIngress.ingress_counter_table")
        egress_counter_table = bfrt_info.table_get("SwitchEgress.egress_counter_table")

        self.del_entries(table=ingress_counter_table, target=target)
        self.del_entries(table=egress_counter_table, target=target)

        port_list = self.conf_port_list
        for i in range(len(port_list)):
            cur_port = port_list[i]
            ingress_counter_table_bfrt_key  = ingress_counter_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', cur_port)])
            ingress_counter_table_bfrt_data = ingress_counter_table.make_data([gc.DataTuple('ingress_counter_index', i)], "SwitchIngress.ingress_counter")
            ingress_counter_table.entry_add(target, [ingress_counter_table_bfrt_key], [ingress_counter_table_bfrt_data])
            self.write_register(target, bfrt_info, "SwitchIngress.ingress_counter_reg", i, 0)

        for i in range(len(port_list)):
            cur_port = port_list[i]
            egress_counter_table_bfrt_key  = egress_counter_table.make_key([gc.KeyTuple('eg_intr_md.egress_port', cur_port)])
            egress_counter_table_bfrt_data = egress_counter_table.make_data([gc.DataTuple('egress_counter_index', i)], "SwitchEgress.egress_counter")
            egress_counter_table.entry_add(target, [egress_counter_table_bfrt_key], [egress_counter_table_bfrt_data])
            self.write_register(target, bfrt_info, "SwitchEgress.egress_counter_reg", i, 0)

    def configure_injection(self, bfrt_info, target, filename):
        """ Configure corresponding tables to add injection events

        Args:
            self (ConfigTable): self
            bfrt_info (BfRtInfo): BfRtInfo (Barefoot Runtime Info) object
            target (Target): Target object
            filename (str): File name of the injection events

        Returns:
            N/A
        """
        port = self.conf_listen_port
        check_first_pkt_in_msg_table = bfrt_info.table_get("SwitchIngress.check_first_pkt_in_msg_table")
        update_next_roceseq_table = bfrt_info.table_get("SwitchIngress.update_next_roceseq_table")
        inject_event_table = bfrt_info.table_get("SwitchIngress.inject_event_table")
        self.del_entries(table=check_first_pkt_in_msg_table, target=target)
        self.del_entries(table=update_next_roceseq_table, target=target)
        self.del_entries(table=inject_event_table, target=target)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        print("Listening...")
        server.listen(5)
        conn, addr = server.accept()
        print("Accepted a connection request from %s:%s" % (addr[0], addr[1]))

        # Wait for the message from RDMA traffic generator
        msg = ""
        while True:
            data = conn.recv(1024)
            msg = msg + data.decode()
            if '&' in msg:
                break

        qp_info_list = self.parse_msg(msg)
        if qp_info_list is None:
            print("Invalid message %s" % msg)
            conn.sendall(msg)
            conn.close()
            print("Connection to client closed.")

        event_list = self.conf_data_pkt_events
        traffic_md_list = []

        for i in range(len(qp_info_list)):
            # qpn_snd, psn_snd, qpn_rcv, psn_rcv = qp_info_list[i]
            qp_info     = qp_info_list[i]
            qpn_snd     = qp_info['qpn_snd']
            psn_snd     = qp_info['psn_snd']
            qpn_rcv     = qp_info['qpn_rcv']
            psn_rcv     = qp_info['psn_rcv']
            snd_sw_port = qp_info['snd_sw_port']
            rcv_sw_port = qp_info['rcv_sw_port']

            num_pkts_per_msg = self.conf_num_pkts_per_msg
            for iter in range(self.conf_num_msgs_per_qp):
                bfrt_key = check_first_pkt_in_msg_table.make_key([gc.KeyTuple("hdr.roce.destination_qp", qpn_rcv),
                                                                  gc.KeyTuple("ig_intr_md.ingress_port", snd_sw_port),
                                                                  gc.KeyTuple("hdr.roce.packet_seqnum", psn_snd + iter * num_pkts_per_msg)])
                bfrt_data = check_first_pkt_in_msg_table.make_data([gc.DataTuple("is_first_pkt_in_msg", 1)],
                                                                    "SwitchIngress.check_first_pkt_in_msg")
                check_first_pkt_in_msg_table.entry_add(target, [bfrt_key], [bfrt_data])

                bfrt_key = check_first_pkt_in_msg_table.make_key([gc.KeyTuple("hdr.roce.destination_qp", qpn_snd),
                                                                  gc.KeyTuple("ig_intr_md.ingress_port", rcv_sw_port),
                                                                  gc.KeyTuple("hdr.roce.packet_seqnum", psn_rcv + iter * num_pkts_per_msg)])
                bfrt_data = check_first_pkt_in_msg_table.make_data([gc.DataTuple("is_first_pkt_in_msg", 1)],
                                                                   "SwitchIngress.check_first_pkt_in_msg")
                check_first_pkt_in_msg_table.entry_add(target, [bfrt_key], [bfrt_data])

            update_next_roceseq_table_bfrt_key = update_next_roceseq_table.make_key([gc.KeyTuple("hdr.roce.destination_qp", qpn_snd),
                                                                                   gc.KeyTuple("ig_intr_md.ingress_port", rcv_sw_port),
                                                                                   gc.KeyTuple("ig_md.is_first_pkt_in_msg", 0)])
            update_next_roceseq_table_bfrt_data = update_next_roceseq_table.make_data([gc.DataTuple("index", 2*i)], "SwitchIngress.update_next_roceseq")
            update_next_roceseq_table.entry_add(target, [update_next_roceseq_table_bfrt_key], [update_next_roceseq_table_bfrt_data])

            update_next_roceseq_table_bfrt_key = update_next_roceseq_table.make_key([gc.KeyTuple("hdr.roce.destination_qp", qpn_snd),
                                                                                    gc.KeyTuple("ig_intr_md.ingress_port", rcv_sw_port),
                                                                                    gc.KeyTuple("ig_md.is_first_pkt_in_msg", 1)])
            update_next_roceseq_table_bfrt_data = update_next_roceseq_table.make_data([gc.DataTuple("index", 2*i)], "SwitchIngress.reset_next_roceseq")
            update_next_roceseq_table.entry_add(target, [update_next_roceseq_table_bfrt_key], [update_next_roceseq_table_bfrt_data])
            self.write_register(target, bfrt_info, "SwitchIngress.next_roceseq_reg", 2*i, psn_rcv, 1)

            update_next_roceseq_table_bfrt_key = update_next_roceseq_table.make_key([gc.KeyTuple("hdr.roce.destination_qp", qpn_rcv),
                                                                                   gc.KeyTuple("ig_intr_md.ingress_port", snd_sw_port),
                                                                                   gc.KeyTuple("ig_md.is_first_pkt_in_msg", 0)])
            update_next_roceseq_table_bfrt_data = update_next_roceseq_table.make_data([gc.DataTuple("index", 2*i + 1)], "SwitchIngress.update_next_roceseq")
            update_next_roceseq_table.entry_add(target, [update_next_roceseq_table_bfrt_key], [update_next_roceseq_table_bfrt_data])

            update_next_roceseq_table_bfrt_key = update_next_roceseq_table.make_key([gc.KeyTuple("hdr.roce.destination_qp", qpn_rcv),
                                                                                    gc.KeyTuple("ig_intr_md.ingress_port", snd_sw_port),
                                                                                    gc.KeyTuple("ig_md.is_first_pkt_in_msg", 1)])
            update_next_roceseq_table_bfrt_data = update_next_roceseq_table.make_data([gc.DataTuple("index", 2*i + 1)], "SwitchIngress.reset_next_roceseq")
            update_next_roceseq_table.entry_add(target, [update_next_roceseq_table_bfrt_key], [update_next_roceseq_table_bfrt_data])
            self.write_register(target, bfrt_info, "SwitchIngress.next_roceseq_reg", 2*i + 1, psn_snd, 1)

            traffic_md = {'qpn_snd': qpn_snd, 'psn_snd': psn_snd, 'qpn_rcv': qpn_rcv, 'psn_rcv': psn_rcv}
            traffic_md_list.append(traffic_md)

        for cur_event in event_list:
            qp_index = cur_event['qpn']
            ps_index = cur_event['psn']
            type = config_translate(cur_event['type'])
            iter = cur_event['iter']
            try:
                qp_info     = qp_info_list[qp_index]
                qpn_snd     = qp_info['qpn_snd']
                psn_snd     = qp_info['psn_snd']
                snd_sw_port = qp_info['snd_sw_port']
                qpn_rcv     = qp_info['qpn_rcv']
                psn_rcv     = qp_info['psn_rcv']
                rcv_sw_port = qp_info['rcv_sw_port']
                psn_snd     = psn_snd + ps_index
                if type == EVENT_TYPE_DROP:
                    inject_event_table_bfrt_key = inject_event_table.make_key([gc.KeyTuple("hdr.roce.destination_qp", qpn_rcv),
                                                                               gc.KeyTuple("ig_intr_md.ingress_port", snd_sw_port),
                                                                               gc.KeyTuple("hdr.roce.packet_seqnum", psn_snd),
                                                                               gc.KeyTuple("ig_md.iteration", iter)])
                    inject_event_table_bfrt_data = inject_event_table.make_data([], "SwitchIngress.drop")
                    inject_event_table.entry_add(target, [inject_event_table_bfrt_key], [inject_event_table_bfrt_data])
                    logger.debug("add drop-event entry with qp:" + str(qpn_rcv) + "; ps:" + str(psn_snd))
                elif type == EVENT_TYPE_ECN:
                    inject_event_table_bfrt_key = inject_event_table.make_key([gc.KeyTuple("hdr.roce.destination_qp", qpn_rcv),
                                                                               gc.KeyTuple("ig_intr_md.ingress_port", snd_sw_port),
                                                                               gc.KeyTuple("hdr.roce.packet_seqnum", psn_snd),
                                                                               gc.KeyTuple("ig_md.iteration", iter)])
                    inject_event_table_bfrt_data = inject_event_table.make_data([], "SwitchIngress.mark_ecn")
                    inject_event_table.entry_add(target, [inject_event_table_bfrt_key], [inject_event_table_bfrt_data])
                    logger.debug("add ecn-event entry with qp:" + str(qpn_rcv) + "; ps:" + str(psn_snd))
                elif type == EVENT_TYPE_BIT_ERROR:
                    inject_event_table_bfrt_key = inject_event_table.make_key([gc.KeyTuple("hdr.roce.destination_qp", qpn_rcv),
                                                                               gc.KeyTuple("ig_intr_md.ingress_port", snd_sw_port),
                                                                               gc.KeyTuple("hdr.roce.packet_seqnum", psn_snd),
                                                                               gc.KeyTuple("ig_md.iteration", iter)])
                    inject_event_table_bfrt_data = inject_event_table.make_data([], "SwitchIngress.bit_error")
                    inject_event_table.entry_add(target, [inject_event_table_bfrt_key], [inject_event_table_bfrt_data])
                    logger.debug("add bit-error-event entry with qp:" + str(qpn_rcv) + "; ps:" + str(psn_snd))
            except:
                print("Invalid combination of queue-pair, packet-sequence, event-type.")
                conn.sendall(msg)
                conn.close()
                print("Connection to client closed.")

        conn.sendall(msg)
        conn.close()
        print("Connection to client closed.")

        with open(filename, 'w') as file:
            yaml.dump(qp_info_list, file, Dumper=Dumper)
        print("Dump the traffic metadata to %s" % filename)

    def write_register(self, target, bfrt_info, reg_name, index, value_first, value_second=None):
        """ Write value to the register

        Args:
            self (ConfigTable): self
            target (Target): Target object
            bfrt_info (BfRtInfo): BfRtInfo (Barefoot Runtime Info) object
            reg_name (str): Register name
            index (int): Register index
            value_first (int): First value to be written
            value_second (int): Second value to be written (optional)

        Returns:
            True if success, False otherwise
        """
        register_table = bfrt_info.table_get(reg_name)
        if value_second == None:
            ret = register_table.entry_add(
                target,
                [register_table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)])],
                [register_table.make_data([gc.DataTuple(reg_name + ".f1", value_first)])]
            )
        else:
            ret = register_table.entry_add(
                target,
                [register_table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)])],
                [register_table.make_data([gc.DataTuple(reg_name + ".first", value_first),
                                           gc.DataTuple(reg_name + ".second", value_second)])]
            )
        return ret

    def read_register(self, target, bfrt_info, reg_name, index, pipe):
        """ Read register value

        Args:
            self (ConfigTable): self
            target (Target): Target object
            bfrt_info (BfRtInfo): BfRtInfo (Barefoot Runtime Info) object
            reg_name (str): Register name
            index (int): Register index
            pipe (int): Pipe id

        Returns:
            Register value (int) or (value_first, value_second)
        """
        register_table = bfrt_info.table_get(reg_name)
        ret = register_table.entry_get(
            target,
            [register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', index)])],
            {"from_hw": True}
        )
        data, _ = next(ret)
        data_dict = data.to_dict()
        if reg_name + ".f1" in data_dict.keys():
            return data_dict[reg_name + '.f1'][pipe]
        else:
            return (data_dict[reg_name + '.first'][pipe], data_dict[reg_name + '.second'][pipe])

    def del_entries(self, table, target):
        """ Delete table entries

        Args:
            self (ConfigTable): self
            table (Table): Table object
            target (Target): Target object

        Returns:
            N/A
        """
        resp = table.entry_get(target, None, {"from_hw": True})
        for data, key in resp:
            table.entry_del(target, [key])

    def init(self):
        """ Initialize, configure all the tables """
        target = gc.Target(device_id=0, pipe_id = 0xffff)
        bfrt_info = self.interface.bfrt_info_get()

        self.configure_forwarding(bfrt_info, target)
        self.configure_arp(bfrt_info, target)
        self.configure_mirroring(bfrt_info, target)
        self.configure_counter(bfrt_info, target)
        print("Init Finished.")

    def set_events(self, filename):
        """ Configure the injection event table """
        target = gc.Target(device_id=0, pipe_id = 0xffff)
        bfrt_info = self.interface.bfrt_info_get()

        self.configure_injection(bfrt_info, target, filename)
        print("Event table setup.")

    def dump_counters(self, target, bfrt_info):
        """Dump ingress and egress counters

        Args:
            self (ConfigTable): self
            target (Target): Target object
            bfrt_info (BfRtInfo): BfRtInfo (Barefoot Runtime Info) object

        Returns:
            A dictionary containing the ingress and egress counters
        """
        counter = {}
        counter['ingress'] = {}
        counter['egress'] = {}

        for i in range(len(self.conf_port_list)):
            port = self.conf_port_list[i]
            pipe = port_to_pipe(port)
            counter['ingress'][port] = self.read_register(target, bfrt_info, "SwitchIngress.ingress_counter_reg", i, pipe)
            counter['egress'][port] = self.read_register(target, bfrt_info, "SwitchEgress.egress_counter_reg", i, pipe)

        return counter

    def dump_events(self, target, bfrt_info):
        """Dump the injection events

        Args:
            self (ConfigTable): self
            target (Target): Target object
            bfrt_info (BfRtInfo): BfRtInfo (Barefoot Runtime Info) object

        Returns:
            A list of dictionaries, each dictionary contains the key and data of an event table entry
        """
        events = []
        inject_event_table = bfrt_info.table_get("SwitchIngress.inject_event_table")
        resp = inject_event_table.entry_get(target, None, {"from_hw": True})

        for data, key in resp:
            key_fields = key.to_dict()
            data_fields = data.to_dict()
            print("key_fields: %s" % key_fields)
            print("data_fields: %s" % data_fields)
            events.append({'key': unicode_dict_to_str(key_fields), 'data': unicode_dict_to_str(data_fields)})

        return events

    def dump_results(self, filename):
        """Dump the results (events and counters) to a yaml file

        Args:
            self (ConfigTable): self
            filename (str): File name of the yaml file

        Returns:
            N/A
        """
        target = gc.Target(device_id=0, pipe_id = 0xffff)
        bfrt_info = self.interface.bfrt_info_get()

        results = {}
        results['counter'] = self.dump_counters(target, bfrt_info)
        results['event-table'] = self.dump_events(target, bfrt_info)
        print(results)
        with open(filename, 'w') as file:
            yaml.dump(results, file, Dumper=Dumper)
        print("Dumping finished.")

def main(args):
    sys_name = args.sys_name
    config_filename = args.config_yml
    thrift_server = args.thrift_server
    grpc_server = args.grpc_server
    config_loader = ConfigLoader(config_filename)
    if wait_for_switchd_ready([dev_id]) == False:
        print("Exit because the device is not ready.")
        sys.exit(-1)
    config_table = ConfigTable(sys_name, config_loader, grpc_server)
    if args.mode == 'init' or args.mode == 'all':
        if add_ports(dev_id = dev_id,
                     port_list = config_loader.get_port_list(),
                     bf_speed = port_speed_dic[config_loader.port_speed()],
                     bf_fec = fec_type_dic[config_loader.fec_type()],
                     thrift_server = thrift_server) == False:
            print("Exit because the ports are not up.")
            sys.exit(-1)
        config_table.init()
    if args.mode == 'event' or args.mode == 'all':
        config_table.set_events(args.snapshot_yml)
    if args.mode == 'dump' or args.mode == 'all':
        config_table.dump_results(args.snapshot_yml)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'Inject-switch Controller')
    parser.add_argument('-n', '--sys_name', type=str, help='The p4 name of the program', required=True)
    parser.add_argument('-f', '--config_yml',   type=str, help='The config (yaml) file path', default='../controller/switch_config.yml')
    parser.add_argument('--thrift_server', type=str, help='Thrift server IP address, localhost by default', default='localhost')
    parser.add_argument('--grpc_server', type=str, help='GRPC server IP address, localhost by default', default='localhost')
    parser.add_argument('-m', '--mode', type=str, help='Running mode, "init": init the ports and tables, "event": setup the event table, "dump": dump the results, "all": "init" + "event" + "dump"', default='all')
    parser.add_argument('-s', '--snapshot_yml', type=str, help='The snapshot (yaml) file path', default='../result/switch_snapshot.yaml')
    args = parser.parse_args()

    print(args)
    main(args)
