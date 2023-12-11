"""
    Host counters
"""
import yaml, sys
import lumina.orchestrator.host as host

class HostCounter:
    """ Base class to parse host counter files

    Attributes:
        _counter (dict of dict): the host counters in the format of {counter_type: {counter_name: counter_value}}
    """
    def __init__(self, counter_start_filename, counter_finish_filename):
        """ Constructor

        Args:
            counter_start_filename (str): the file where host dumps its counters at the start phase
            counter_finish_filename (str): the file where host dumps its counters at the finish phase

        Returns:
            N/A
        """
        counter_start  = self.read(counter_start_filename)
        counter_finish = self.read(counter_finish_filename)

        self._counter = {}
        for counter_type in counter_finish.keys():
            self._counter[counter_type] = {x: counter_finish[counter_type][x] - counter_start[counter_type][x]\
                                           for x in counter_finish[counter_type] if x in counter_start[counter_type]}

    def read(self, filename):
        """ Read the host counter file

        Args:
            filename (str): the file where host dumps its counters

        Returns:
            dict of dict: the host counters in the format of {counter_type: {counter_name: counter_value}}
        """
        with open(filename, "r") as stream:
            try:
                conf = yaml.safe_load(stream)
            except:
                print("Bad yaml format in %s" % filename)
                sys.exit(-1)

        return conf


class MLNXHostCounter(HostCounter):
    """ Class to parse MLNX host counter files """
    def __init__(self, counter_start_filename, counter_finish_filename):
        """ Constructor

        Args:
            counter_start_filename (str): the file where host dumps its counters at the start phase
            counter_finish_filename (str): the file where host dumps its counters at the finish phase

        Returns:
            N/A
        """
        super().__init__(counter_start_filename, counter_finish_filename)

    def get_port_rcv_packets(self):
        """ Return the number of received packets """
        return self._counter['port-counters']['port_rcv_packets']

    def get_port_xmit_packets(self):
        """ Return the number of transmitted packets """
        return self._counter['port-counters']['port_xmit_packets']

    def get_num_packet_seq_err(self):
        """ Return the number of received NAK sequence error packets """
        return self._counter['hw-counters']['packet_seq_err']

    def get_num_out_of_sequence(self):
        """ Return the number of out-of-sequence packets received """
        return self._counter['hw-counters']['out_of_sequence']

    def get_num_dup_requests(self):
        """ Return the number of duplicate requests """
        return self._counter['hw-counters']['duplicate_request']

    def implied_nak_seq_err(self):
        """ Return the number of READ requests implying sequence errors """
        return self._counter['hw-counters']['implied_nak_seq_err']

    def get_num_cnp_sent(self):
        """ Return the number of congestion notification packets sent by notification point """
        return self._counter['hw-counters']['np_cnp_sent']

    def get_num_ecn_marked_packets(self):
        """ Return the number of ECN marked RoCEv2 packets received by notification point """
        return self._counter['hw-counters']['np_ecn_marked_roce_packets']

    def get_num_cnp_handled(self):
        """ Return the number of congestion notification packets handled by reaction point """
        return self._counter['hw-counters']['rp_cnp_handled']

    def get_num_icrc_errors(self):
        """ Return the number of RoCE packets with ICRC errors received """
        return self._counter['hw-counters']['rx_icrc_encapsulated']

    def get_num_timeout_err(self):
        """ Return the number of times QP's ack timer expired for RC, XRC, DCT QPs at the sender side """
        return self._counter['hw-counters']['local_ack_timeout_err']

    def get_num_discards_dict_tx(self):
        """ Return the number of TX discarded packets (dict)"""
        discards_dict_tx = {}
        for x in self._counter['ethtool-counters'].keys():
            if 'discard' in x and 'tx' in x:
                discards_dict_tx[x] = self._counter['ethtool-counters'][x]
        return discards_dict_tx

    def get_num_discards_dict_rx(self):
        """ Return the number of RX discarded packets (dict) """
        discards_dict_rx = {}
        for x in self._counter['ethtool-counters'].keys():
            if 'discard' in x and 'rx' in x:
                discards_dict_rx[x] = self._counter['ethtool-counters'][x]
        return discards_dict_rx

class IntelHostCounter(HostCounter):
    """ Class to parse Intel host counter files """
    def __init__(self, counter_start_filename, counter_finish_filename):
        """ Constructor

        Args:
            counter_start_filename (str): the file where host dumps its counters at the start phase
            counter_finish_filename (str): the file where host dumps its counters at the finish phase

        Returns:
            N/A
        """
        super().__init__(counter_start_filename, counter_finish_filename)

    def get_num_cnp_sent(self):
        """ Return the number of congestion notification packets sent by notification point """
        return self._counter['hw-counters']['cnpSent']

    def get_num_ecn_marked_packets(self):
        """ Return the number of ECN marked RoCEv2 packets received by notification point """
        return self._counter['hw-counters']['RxECNMrkd']

    def get_num_cnp_handled(self):
        """ Return the number of congestion notification packets handled by reaction point """
        return self._counter['hw-counters']['cnpHandled']

    def get_num_discards_dict(self):
        """ Return the number of discarded packets (dict) """
        discards_dict= {}
        for x in self._counter['hw-counters'].keys():
            if 'discard' in x:
                discards_dict[x] = self._counter['hw-counters'][x]
        return discards_dict
