"""
    Switch counters
"""
import yaml, sys

class SwitchCounter:
    """ Class to parse switch counter files

    Attributes:
        _counter (dict of dict): the switch counters with the following format:
            {'requester': {'ingress': counter_value, 'egress': counter_value},
             'responder': {'ingress': counter_value, 'egress': counter_value},
             'requester-mirror': {'ingress': counter_value, 'egress': counter_value},
             'responder-mirror': {'ingress': counter_value, 'egress': counter_value}}
    """
    def __init__(self, snapshot_filename, port_map):
        """ Constructor

        Args:
            snapshot_filename (str): the file where switch dumps its counters
            port_map (dict): the mapping between port name and port number

        Returns:
            N/A
        """
        with open(snapshot_filename, "r") as stream:
            conf = yaml.safe_load(stream)
            try:
                ingress_counters = conf['counter']['ingress']
                egress_counters  = conf['counter']['egress']
            except:
                print("Bad yaml format in %s" % snapshot_filename)
                sys.exit(-1)

        requester_port = port_map['requester']
        responder_port = port_map['responder']
        requester_mirror_port = port_map['requester-mirror']
        responder_mirror_port = port_map['responder-mirror']

        self._counter = {'requester'        : {'ingress':0, 'egress': 0},
                         'responder'        : {'ingress':0, 'egress': 0},
                         'requester-mirror' : {'ingress':0, 'egress': 0},
                         'responder-mirror' : {'ingress':0, 'egress': 0}}
        try:
            self._counter['requester']['ingress'] = ingress_counters[requester_port]
            self._counter['responder']['ingress'] = ingress_counters[responder_port]
            self._counter['requester-mirror']['ingress'] = ingress_counters[requester_mirror_port]
            self._counter['responder-mirror']['ingress'] = ingress_counters[responder_mirror_port]

            self._counter['requester']['egress'] = egress_counters[requester_port]
            self._counter['responder']['egress'] = egress_counters[responder_port]
            self._counter['requester-mirror']['egress'] = egress_counters[requester_mirror_port]
            self._counter['responder-mirror']['egress'] = egress_counters[responder_mirror_port]

        except:
            print("Port number not exist in the switch snapshot")
            sys.exit(-1)

    def get_counter(self):
        """ Return the switch counters (dict of dict) """
        return self._counter
