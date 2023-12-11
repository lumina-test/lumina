import argparse, sys, os, yaml, time, subprocess, logging, math, copy
import lumina.orchestrator.host as host
import lumina.orchestrator.switch as switch
import lumina.analyzer.pcap_processor.pcap_process as pcap_process
from lumina.utils.config_loggers import config_stream_handler, config_file_handler
from lumina.analyzer.pcap_processor.pcap_process import get_packet_list
from lumina.analyzer.counter.switch_counter import SwitchCounter
from lumina.analyzer.checker.integrity_check import IntegrityCheck

## Logs will be logged into file LOG_FILENAME
LOG_FILENAME = "run.log"
## Max # of experiment retries
MAX_NB_EXP_RETRIES = 3

class Orchestrator:
    """ Class to manage the experiment """
    def __init__(self, config_file):
        """ Constructor for Orchestrator class

        Args:
            config_file (str): path to the yaml (config) file.
            The file contains configs for switch, requester, responder, traffic, etc.

        Returns:
            N/A
        """
        with open(config_file, "r") as stream:
            conf = yaml.safe_load(stream)
            try:
                local_workspace         = conf['local-workspace']
                result_path             = conf['result-path']
                switch_conf             = conf['switch']
                requester_conf          = conf['requester']
                responder_conf          = conf['responder']
                requester_mirror_conf   = conf['requester-mirror']
                responder_mirror_conf   = conf['responder-mirror']
                traffic_conf            = conf['traffic']
                rewrite_udp_dst_port    = conf['rewrite-udp-dst-port']
                num_repeats             = conf['num-repeats']
                agg_pcap_filename       = conf['aggregate-pcap-filename']
            except KeyError as e:
                print("Config file %s has a bad yaml format (key error: %s)" % (config_file, e))
                sys.exit(-1)

        switch_conf['rewrite-udp-dst-port'] = rewrite_udp_dst_port
        requester_mirror_conf['pkt-dump-conf']['rewrite-udp-dst-port'] = rewrite_udp_dst_port
        responder_mirror_conf['pkt-dump-conf']['rewrite-udp-dst-port'] = rewrite_udp_dst_port

        self.local_workspace = local_workspace
        self.result_path = result_path
        self.traffic_conf = traffic_conf
        self.num_repeats = num_repeats
        self.switch = switch.Switch(switch_conf)
        self.requester = host.RDMAHost(requester_conf)
        self.responder = host.RDMAHost(responder_conf)
        self.requester_mirror = host.MirrorHost(requester_mirror_conf)
        self.responder_mirror = host.MirrorHost(responder_mirror_conf)
        self.aggregate_pcap_filename = agg_pcap_filename

        cmd = "mkdir -p %s" % self.result_path
        subprocess.call(cmd, shell = True)

    def rm_old_files(self):
        """ Remove result files left by previous experiments """
        old_iter_id = 0
        old_iter_result_path = os.path.join(self.result_path, str(old_iter_id))

        while os.path.exists(old_iter_result_path) and not os.path.isfile(old_iter_result_path):
            cmd = "rm -rf %s" % (old_iter_result_path)
            subprocess.call(cmd, shell=True)

            old_iter_id += 1
            old_iter_result_path = os.path.join(self.result_path, str(old_iter_id))

    def get_requester_ip_list(self):
        """ Return the list of requester IP addresses (without prefix length info) """
        return [x.split('/')[0] for x in self.requester.conf['nic']['ip-list']]

    def get_responder_ip_list(self):
        """ Return the list of responder IP addresses (without prefix length info) """
        return [x.split('/')[0] for x in self.responder.conf['nic']['ip-list']]

    def get_num_repeats(self):
        """ Return the number of experiment repeats """
        return self.num_repeats

    def sync_and_compile(self):
        """ Syncronize and compile the code on all the hosts

        Returns:
            bool: True if the code is synced and compiled successfully, False otherwise
        """
        logging.info("Sync and compile the code")

        ## Sync and compile the switch code
        ret = self.switch.sync_and_compile(self.local_workspace,
                                           switch.SWITCH_PROG_DIR_NAME,
                                           switch.SWITCH_PROG_FILE_NAME)
        if ret == False:
            logging.error("Failed to sync and compile the switch code")
            return False

        ## Sync and compile the traffic generator code
        rdma_verb = self.traffic_conf['rdma-verb'].strip().lower()
        if rdma_verb not in host.VALID_IB_VERB_LIST_LOWER:
            logging.error("Invalid RDMA verb: %s" % rdma_verb)
            return False

        ret = self.requester.sync_and_compile(local_workspace=self.local_workspace,
                                              prog_dir_name=self.requester.traffic_gen_dir_name(),
                                              prog_file_name=self.requester.traffic_gen_client_name(rdma_verb))
        if ret == False:
            logging.error("Failed to sync and compile the traffic generator code on requester")
            return False

        ret = self.responder.sync_and_compile(local_workspace=self.local_workspace,
                                              prog_dir_name=self.requester.traffic_gen_dir_name(),
                                              prog_file_name=self.requester.traffic_gen_server_name(rdma_verb))
        if ret == False:
            logging.error("Failed to sync and compile the traffic generator code on responder")
            return False

        ret = self.requester.sync(local_workspace=self.local_workspace,
                                  prog_dir_name=host.DUMP_COUNTER_DIR_NAME)
        if ret == False:
            logging.error("Failed to sync the dump counter code on requester")
            return False

        ret = self.responder.sync(local_workspace=self.local_workspace,
                                  prog_dir_name=host.DUMP_COUNTER_DIR_NAME)
        if ret == False:
            logging.error("Failed to sync the dump counter code on responder")
            return False

        ## Sync and compile the packet capture code
        ret = self.requester_mirror.sync_and_compile(local_workspace=self.local_workspace,
                                                     prog_dir_name=host.PKT_CAPTURE_DIR_NAME,
                                                     prog_file_name=host.PKT_CAPTURE_FILE_NAME)
        if ret == False:
            logging.error("Failed to sync and compile the packet capture code on requester_mirror")
            return False

        ret = self.responder_mirror.sync_and_compile(local_workspace=self.local_workspace,
                                                     prog_dir_name=host.PKT_CAPTURE_DIR_NAME,
                                                     prog_file_name=host.PKT_CAPTURE_FILE_NAME)
        if ret == False:
            logging.error("Failed to sync and compile the packet capture code on responder_mirror")
            return False

        return True

    def generate_switch_table_config(self):
        """ Generate the switch configuration, including:
            1. Forward table
            2. Mirror table
            3. ARP table
            4. Traffic table, including the events to inject

        Returns:
            bool: True if the switch configuration is generated successfully, False otherwise
        """
        requester_nic_conf          = self.requester.conf['nic']
        responder_nic_conf          = self.responder.conf['nic']
        requester_mirror_nic_conf   = self.requester_mirror.conf['nic']
        responder_mirror_nic_conf   = self.responder_mirror.conf['nic']

        ## Set up forward table entries
        self.switch.conf['forward-table'] = []
        try:
            for nic_conf, host_type in zip([requester_nic_conf, responder_nic_conf, \
                                            requester_mirror_nic_conf, responder_mirror_nic_conf],
                                           ['requester', 'responder', 'requester_mirror', 'responder_mirror']):
                forward_table_entry = {'dst-mac': nic_conf['mac'],
                                       'eg-port': nic_conf['switch-port'],
                                       'host': host_type}
                self.switch.conf['forward-table'].append(forward_table_entry)
        except:
            logging.error("Failed to set forward table")
            return False

        ## Set up mirror table entries, use ingress_to_egress
        try:
            requester_mirror_entry = {'direction': 'ingress_to_egress',
                                      'src-port': requester_nic_conf['switch-port'],
                                      'dst-port': requester_mirror_nic_conf['switch-port']}

            responder_mirror_entry = {'direction': 'ingress_to_egress',
                                      'src-port': responder_nic_conf['switch-port'],
                                      'dst-port': responder_mirror_nic_conf['switch-port']}
            self.switch.conf['mirror-table'] = [requester_mirror_entry, responder_mirror_entry]
        except:
            logging.error("Failed to set mirror table")
            return False

        requester_mac       = requester_nic_conf['mac']
        responder_mac       = responder_nic_conf['mac']
        requester_ip_list   = requester_nic_conf['ip-list']
        responder_ip_list   = responder_nic_conf['ip-list']
        ## Set up arp table entries
        arp_entries = []
        try:
            for dst_ip_list, dst_mac in zip([requester_ip_list, responder_ip_list],
                                            [requester_mac, responder_mac]):
                for dst_ip_subnet in dst_ip_list:
                    dst_ip = dst_ip_subnet.split('/')[0]
                    arp_entries.append({'dst-ip': dst_ip, 'dst-mac': dst_mac})
            self.switch.conf['arp-table'] = arp_entries
        except:
            logging.error("Failed to set ARP table")
            return False

        ## Generate the events of each iteration for switch config
        per_iter_event_list = self.traffic_conf['data-pkt-events']
        msg_size = self.traffic_conf['message-size']
        mtu = self.traffic_conf['mtu']
        num_msgs_per_qp = self.traffic_conf['num-msgs-per-qp']
        num_pkts_per_msg = int(math.ceil(msg_size / mtu))
        self.switch.conf['traffic'] = {}
        self.switch.conf['traffic']['num-msgs-per-qp'] = num_msgs_per_qp
        self.switch.conf['traffic']['num-pkts-per-msg'] = num_pkts_per_msg
        self.switch.conf['traffic']['data-pkt-events'] = []

        if per_iter_event_list is None or len(per_iter_event_list) == 0:
            ## No events at all
            return True

        for i in range(num_msgs_per_qp):
            for per_iter_event in per_iter_event_list:
                global_event = copy.deepcopy(per_iter_event)

                ## This event is applied to all the packets of the message. We need to expand it!
                if str(global_event['psn']).lower() == 'all':
                    for psn in range(num_pkts_per_msg):
                        global_event['psn'] = psn + i * num_pkts_per_msg
                        self.switch.conf['traffic']['data-pkt-events'].append(copy.deepcopy(global_event))
                else:
                    global_event['psn'] += i * num_pkts_per_msg
                    self.switch.conf['traffic']['data-pkt-events'].append(copy.deepcopy(global_event))

        return True

    def ping_mesh(self):
        """ Ping all the IP addresses between requester and responder to check the connectivity

        Returns:
            bool: True if all the IP addresses can be pinged successfully, False otherwise
        """
        for requester_ip_subnet in self.requester.conf['nic']['ip-list']:
            requester_ip = requester_ip_subnet.split('/')[0]
            command = "ping " + requester_ip + " -c 5 -i 0.2"
            ret_val, err_info, exit_status = self.responder.execute_command(command)
            if exit_status != 0:
                logging.error("Failed to ping ip " + requester_ip)
                logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
                return False

        for responder_ip_subnet in self.responder.conf['nic']['ip-list']:
            responder_ip = responder_ip_subnet.split('/')[0]
            command = "ping " + responder_ip + " -c 5 -i 0.2"
            ret_val, err_info, exit_status = self.requester.execute_command(command)
            if exit_status != 0:
                logging.error("Failed to ping ip " + responder_ip)
                logging.error("[Command return info]: %s %s" % (ret_val, err_info))
                return False

        logging.info("Successfully pinged all the IP addresses between requester and responder")
        return True

    def generate_switch_config_file(self):
        """ Generate the switch configuration file and copy it to the switch

        Returns:
            bool: True if the switch configuration file is generated and copied successfully, False otherwise
        """
        ## Get the mac address for all the hosts
        self.requester.get_mac_address()
        self.responder.get_mac_address()
        self.requester_mirror.get_mac_address()
        self.responder_mirror.get_mac_address()

        ## Generate config for Match-Action table in switch
        if self.generate_switch_table_config() == False:
            logging.error("Failed to generate switch table configuration")
            return False

        ## Dump the switch configuration into a file, and copy it to the switch
        if self.switch.dump_controller_config(self.local_workspace) == False:
            logging.error("Failed to dump switch config")
            return False

        return True

    def __is_valid_traffc(self):
        """ Check if the traffic configuration is valid, including:
            1. The tx-depth should be 1 or > 1
            2. If tx-depth > 1, then we can only inject ECN marking events

        Returns:
            bool: True if the traffic configuration is valid, False otherwise
        """
        try:
            data_pkt_events = self.traffic_conf['data-pkt-events']
            tx_depth = self.traffic_conf['tx-depth']

            if tx_depth == 1:
                return True
            elif tx_depth <= 0:
                return False

            for event in data_pkt_events:
                if event['type'] != 'ecn':
                    logging.error("Cannot inject %s event when tx depth = %d" % (event['type'], tx_depth))
                    return False
        except:
            logging.error("Failed to parse traffic configuration")
            return False

        return True

    def run_experiment(self):
        """ Run the experiment

        Returns:
            bool: True if the experiment is completed successfully, False otherwise
        """

        ## Check if traffic configuration is valid
        if self.__is_valid_traffc() == False:
            logging.error("Invalid traffic configuration")
            return False

        ## Run switch program
        if self.switch.run_switch() == False:
            logging.error("Failed to run switch")
            return False

        ## Sleep for 1 second to make sure control plane is listenning (for client message)
        time.sleep(1)

        ## Configure the servers
        if self.requester.config_traffic_gen() == False:
            logging.error("Failed to config RDMA requester")
            return False

        if self.responder.config_traffic_gen() == False:
            logging.error("Failed to config RDMA responder")
            return False

        if self.requester_mirror.config_packet_capture() == False:
            logging.error("Failed to config packet capture on requester mirror")
            return False

        if self.responder_mirror.config_packet_capture() == False:
            logging.error("Failed to config packet capture on responder mirror")
            return False

        ## Check the connectivity through pingmesh (try 5 rounds)
        num_tries = 0
        pingmesh_ret = False

        while num_tries < 5:
            pingmesh_ret = self.ping_mesh()
            if pingmesh_ret == True:
                break
            num_tries += 1
            time.sleep(1)

        if pingmesh_ret == False:
            logging.error("Failed to ping all the IP addresses between requester and responder")
            return False

        ## Launch packet capture for both side
        ## Prerequisite: config hugepage and igb_uio if needed
        if self.requester_mirror.run_packet_capture() == False:
            logging.error("Failed to run packet capture on requester mirror")
            return False

        if self.responder_mirror.run_packet_capture() == False:
            logging.error("Failed to run packet capture on responder mirror")
            return False

        time.sleep(3)

        ## Dump the counters before running
        if self.requester.dump_counters(host.REQ_START_COUNTER_FILE_NAME) == False:
            logging.error("Failed to dump counters on requester before running")
            return False

        if self.responder.dump_counters(host.RSP_START_COUNTER_FILE_NAME) == False:
            logging.error("Failed to dump counters on responder before running")
            return False

        ## Launch RDMA server first
        run_server_ret = self.responder.run_traffic_gen_server(self.traffic_conf)
        if run_server_ret == False:
            logging.error("Failed to run RDMA server")
            return False

        time.sleep(2)

        ## Launch RDMA client
        try:
            destination_ip_subnet = self.responder.conf['nic']['ip-list'][0]
            destination_ip = destination_ip_subnet.split('/')[0]
        except:
            logging.error("Failed to get destination IP")
            return False

        run_client_ret = self.requester.run_traffic_gen_client(traffic_conf=self.traffic_conf,
                                                               destination_ip=destination_ip,
                                                               controller_ip=self.switch.conf['control-ip'],
                                                               controller_listen_port=self.switch.conf['listen-port'])
        if run_client_ret == False:
            logging.error("Failed to run RDMA client")
            return False

        if self.switch.dump_results() == False:
            logging.error("Failed to dump results from switch")
            return False

        if self.requester.dump_counters(host.REQ_FINISH_COUNTER_FILE_NAME) == False:
            logging.error("Failed to dump counters on requester after running")
            return False

        if self.responder.dump_counters(host.RSP_FINISH_COUNTER_FILE_NAME) == False:
            logging.error("Failed to dump counters on responder after running")
            return False

        logging.info("Experiment completed successfully")
        return True

    def clean_up(self):
        """ Clean up the environment after the experiment

        Returns:
            bool: True if the clean up is completed successfully, False otherwise
        """
        logging.info("Start cleaning up the environment")

        if self.switch.clean_up() == False:
            logging.error("Failed to clean up switch")
            return False

        if self.requester.clean_up() == False:
            logging.error("Failed to clean up requester")
            return False

        if self.responder.clean_up() == False:
            logging.error("Failed to clean up responder")
            return False

        if self.requester_mirror.clean_up() == False:
            logging.error("Failed to clean up requester mirror")
            return False

        if self.responder_mirror.clean_up() == False:
            logging.error("Failed to clean up responder mirror")
            return False

        return True

    def fetch_results(self, iter_id=0):
        """ Fetch the results of iteration 'iter_id', including:
            1. Switch table entries and counters
            2. Packet trace (pcap file)
            3. Configs and end-to-end results from RDMA hosts

        Args:
            iter_id (int, optional): iteration ID, defaults to 0

        Returns:
            bool: True if the result collection is completed successfully, False otherwise
        """
        ## Make the results dir if it does not exist
        iter_result_path = os.path.join(self.result_path, str(iter_id))
        cmd = "mkdir -p %s" % iter_result_path
        try:
            subprocess.call(cmd, shell=True)
        except:
            logging.error("Failed to create result directory %s" % iter_result_path)
            return False

        if self.switch.fetch_results(iter_result_path) == False:
            logging.error("Failed to fetch results from switch")
            return False

        if self.requester_mirror.fetch_results(iter_result_path) == False:
            logging.error("Failed to fetch results from requester mirror")
            return False

        if self.responder_mirror.fetch_results(iter_result_path) == False:
            logging.error("Failed to fetch results from responder mirror")
            return False

        if self.requester.fetch_results(iter_result_path) == False:
            logging.error("Failed to fetch results from requester")
            return False

        if self.responder.fetch_results(iter_result_path) == False:
            logging.error("Failed to fetch results from responder")
            return False

        logging.info("Finished fetching results for iteration %d" % iter_id)
        return True

    def merge_traces(self, iter_id=0):
        iter_pcap_dir_path = os.path.join(self.result_path, str(iter_id), host.PCAP_RESULT_DIR)
        src_pcap_file_list = [os.path.join(iter_pcap_dir_path,
                                           self.requester_mirror.conf['pkt-dump-conf']['dump-filename']),
                              os.path.join(iter_pcap_dir_path,
                                           self.responder_mirror.conf['pkt-dump-conf']['dump-filename'])]
        target_pcap_path = os.path.join(self.result_path,
                                        str(iter_id),
                                        host.PCAP_RESULT_DIR,
                                        self.aggregate_pcap_filename)
        packet_list = pcap_process.merge_pcaps(src_pcap_file_list)
        if packet_list is None:
            logging.error("Failed to merge pcap files for iteration %d" % iter_id)
            return False

        if pcap_process.dump_pkts_to_pcap(target_pcap_path, packet_list) == False:
            logging.error("Failed to dump packets to pcap file %s" % target_pcap_path)
            return False

        logging.info("Successfully merged pcap files for iteration %d" % iter_id)

    def check_integrity(self, iter_id=0):
        ## Check if the collected packet trace passes integrity check
        pcap_path = os.path.join(self.result_path,
                                 str(iter_id),
                                 host.PCAP_RESULT_DIR,
                                 self.aggregate_pcap_filename)
        packet_list = get_packet_list(pcap_path)
        packet_list.sort(key=lambda x:x.get_switch_seqnum())
        logging.info("Packet trace sorted by switch sequence number.")

        switch_state_snapshot = os.path.join(self.result_path,
                                             str(iter_id),
                                             switch.SWITCH_RESULT_DIR,
                                             switch.SWITCH_STATE_SNAPSHOT)
        port_map = {'requester': self.requester.conf['nic']['switch-port'],
                    'responder': self.responder.conf['nic']['switch-port'],
                    'requester-mirror': self.requester_mirror.conf['nic']['switch-port'],
                    'responder-mirror': self.responder_mirror.conf['nic']['switch-port']}
        switch_counter = SwitchCounter(switch_state_snapshot, port_map)

        integrity_checker = IntegrityCheck(packet_list=packet_list,
                                           switch_counter=switch_counter,
                                           requester_ip_list=self.get_requester_ip_list(),
                                           responder_ip_list=self.get_responder_ip_list())

        if integrity_checker.check() == True:
            logging.info("Integrity check passed")
            return True
        else:
            logging.info("Integrity check failed")
            return False

def main(args):
    orchestrator = Orchestrator(args.config_file)
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    config_stream_handler(root_logger)
    config_file_handler(root_logger, os.path.join(orchestrator.result_path, LOG_FILENAME), no_format=False)

    if args.sync and orchestrator.sync_and_compile() == False:
        logging.error("Failed to sync and compile the code")
        sys.exit(-1)

    if args.run:
        orchestrator.rm_old_files()
        if orchestrator.generate_switch_config_file() == False:
            logging.error("Failed to generate switch configuration file")
            sys.exit(-1)

        num_repeats = orchestrator.get_num_repeats()

        for i in range(num_repeats):
            logging.info("=" * 100)
            nb_retry = 0

            while nb_retry < MAX_NB_EXP_RETRIES:
                if orchestrator.run_experiment() == False:
                    logging.error("Iteration %d: Failed to complete experiment" % i)
                    logging.error("Iteration %d: Rerun experiment (retry: %d)" % (i, nb_retry))
                    nb_retry += 1
                    orchestrator.clean_up()
                    time.sleep(5)
                    continue

                logging.info("Iteration %d: Completed experiment" % i)
                try:
                    orchestrator.clean_up()
                    orchestrator.fetch_results(i)
                    logging.info("Iteration %d: Fetch experiment results" % i)
                    orchestrator.merge_traces(i)
                    logging.info("Iteration %d: Merge the pcap files" % i)
                except:
                    logging.error("Iteration %d: Result collection failed" % (i))
                    logging.error("Iteration %d: Rerun experiment (retry: %d)" % (i, nb_retry))
                    nb_retry += 1
                    time.sleep(5)
                    continue

                if orchestrator.check_integrity(i) == False:
                    logging.error("Iteration %d: Integrity check failed" % (i))
                    logging.error("Iteration %d: Rerun experiment (retry: %d)" % (i, nb_retry))
                    nb_retry += 1
                    time.sleep(5)
                    continue

                break

def parse_args():
    parser = argparse.ArgumentParser(description = 'Orchestrator')
    parser.add_argument('-f', '--config_file', type=str, help='config file', required=True)
    parser.add_argument('-s', '--sync', help='whether to sync and compile the code', action='store_true')
    parser.add_argument('-r', '--run',  help='whether to run the experiments', action='store_true')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()
    main(args)
