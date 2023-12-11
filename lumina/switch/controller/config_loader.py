import yaml
import sys

EVENT_TYPE_DROP = 1
EVENT_TYPE_ECN  = 2
EVENT_TYPE_BIT_ERROR = 3

translator = {
    'ingress_to_egress': "INGRESS",
    'egress_to_egress' : "EGRESS",
    'drop': EVENT_TYPE_DROP,
    'ecn' : EVENT_TYPE_ECN,
    'bit-error': EVENT_TYPE_BIT_ERROR,
}

def config_translate(str):
    """ Convert strings in yaml file to the values we need

    Args:
        str (str): String to convert

    Returns:
        Converted value if the string is recognized, None otherwise
    """
    if str not in translator:
        print("Error: " + str + " is not identified.")
        return None
    return translator[str]

class ConfigLoader:
    """ Class to load the configures in yaml file """
    def __init__(self, filename="../controller/config.yml"):
        """ Constructor

        Args:
            self (ConfigLoader): self
            filename (str): path to the yaml (config) file. The file contains configs for forwarding table,
                            mirror table, listen port, link speed/type, and events to inject

        Returns:
            N/A
        """
        self._conf = None
        self._port_list = None
        self._ip_list   = None
        self._mac_list  = None

        with open(filename, "r") as stream:
            self._conf = yaml.safe_load(stream)

        try:
            self._port_speed           = self._conf['port-speed']
            self._fec_type             = self._conf['fec-type']
            self._listen_port          = self._conf['listen-port']
            self._forward              = self._conf['forward']
            self._mirror               = self._conf['mirror']
            self._arp                  = self._conf['arp']
            self._rewrite_udp_dst_port = self._conf['rewrite-udp-dst-port']
            self._num_pkts_per_msg     = self._conf['traffic']['num-pkts-per-msg']
            self._num_msgs_per_qp      = self._conf['traffic']['num-msgs-per-qp']
            self._data_pkt_events      = self._conf['traffic']['data-pkt-events']

        except:
            print("Bad formatted yaml file")
            sys.exit(-1)

    def port_speed(self):
        """ Return port speed """
        return self._port_speed

    def fec_type(self):
        """ Return port forward error correction (FEC) type """
        return self._fec_type

    def listen_port(self):
        """ Return listen port """
        return self._listen_port

    def rewrite_udp_dst_port(self):
        """ Return the udp dst port to rewrite for RoCE packets """
        return self._rewrite_udp_dst_port

    def forward(self):
        """ Return forward table information """
        return self._forward

    def arp(self):
        """ Return arp table information """
        return self._arp

    def mirror(self):
        """ Return mirror table information """
        return self._mirror

    def data_pkt_events(self):
        """ Return events to inject for data packets """
        return self._data_pkt_events

    def get_port_list(self):
        """ Return the port list (numbered 0~188) """
        if self._port_list != None:
            return self._port_list
        self._port_list = []
        for table_entry in self._forward:
            self._port_list.append(table_entry['eg-port'])
        print("forward", self._forward)
        print("port_list", self._port_list)
        return self._port_list

    def get_num_pkts_per_msg(self):
        """ Return the number of packets per message """
        return self._num_pkts_per_msg

    def get_num_msgs_per_qp(self):
        """ Return the number of messages per qp """
        return self._num_msgs_per_qp
