import sys, os, logging, re, time
from abc import abstractmethod
from lumina.orchestrator.remote_control import RemoteClient
from enum import Enum

VALID_IB_VERB_LIST_LOWER = ['send', 'write', 'read', 'send_read']

IB_OPTION_MULTI_GID  = " -m "
IB_OPTION_BARRIER_SYNC = " -b "
IB_OPTION_CONTROLLER_IP = " -C "
IB_OPTION_CONTROLLER_LISTEN_PORT = " -P "
IB_OPTION_NONE       = " "

PKT_CAPTURE_DIR_NAME  = "roce-pkt-dump"
PKT_CAPTURE_FILE_NAME = "roce-pkt-dump"

DUMP_COUNTER_DIR_NAME  = "counter-dump"
DUMP_COUNTER_PROG_NAME = "counter_dump.py"

REQ_START_COUNTER_FILE_NAME  = "requester_counter_start.yml"
RSP_START_COUNTER_FILE_NAME  = "responder_counter_start.yml"
REQ_FINISH_COUNTER_FILE_NAME = "requester_counter_finish.yml"
RSP_FINISH_COUNTER_FILE_NAME = "responder_counter_finish.yml"

RDMA_RESULT_DIR = "rdma-result"
PCAP_RESULT_DIR = "pcap-result"

NUM_LCORES_CAPTURE_PKTS = 4

class NICVendor(Enum):
    Unkown = 0
    MLNX = 1
    Intel = 2

"""
We support the following NICs:
    Mellanox ConnectX-4, ConnectX-5, ConnectX-6
    Intel E810, XL710

It is worth noting that Intel XL710 is not RDMA-capable, so we only use it for capturing packets.
"""
NIC_TYPE2VENDOR_MAP = {"CX4": NICVendor.MLNX,
                       "CX5": NICVendor.MLNX,
                       "CX6": NICVendor.MLNX,
                       "E810": NICVendor.Intel,
                       "XL710": NICVendor.Intel}

"""
Legacy and DPDK drivers for Intel NICs.
Mellanox NICs always use the same driver.
"""
MIRROR_LEGACY_DRIVER_MAP = {"E810":"ice", "XL710":"i40e"}
MIRROR_DPDK_DRIVER_MAP = {"E810":"vfio-pci", "XL710":"igb_uio"}

"""
Default DSCP-to-priority mapping for Mellanox NICs.
Intel NICs only use DSCP values 0-31, so we use the first 32 entries.
"""
DEFAULT_PRIO2DSCP_MAP = {
    0: "07,06,05,04,03,02,01,00",
    1: "15,14,13,12,11,10,09,08",
    2: "23,22,21,20,19,18,17,16",
    3: "31,30,29,28,27,26,25,24",
    4: "39,38,37,36,35,34,33,32",
    5: "47,46,45,44,43,42,41,40",
    6: "55,54,53,52,51,50,49,48",
    7: "63,62,61,60,59,58,57,56"
}
MIN_DSCP = 0
MAX_DSCP = 63
INTEL_MAX_DSCP = 31

class Host(RemoteClient):
    """ Class to control the host """
    def __init__(self, config):
        """ Constructor

        Args:
            config (dict): Configuration for the host

        Returns:
            N/A
        """
        try:
            hostname = config['control-ip']
            username = config['username']
            ssh_key_filepath = config['ssh-key-filepath']
            remote_path = config['workspace']

        except:
            print("Failed to read the switch config")
            sys.exit(-1)

        RemoteClient.__init__(self, hostname, username, ssh_key_filepath, remote_path)
        self._server_conf = config
        self.nic_vendor = None

    @property
    def conf(self):
        """ Get the configuration for the host

        Returns:
            dict: Configuration for the host
        """
        return self._server_conf

    def check_mlnx_connectx_hwinfo(self, nic_name):
        """ Check if the NIC is a Mellanox ConnectX nic or not

        Args:
            nic_name (str): NIC name

        Returns:
            True if the nic is a Mellanox ConnectX NIC, False otherwise
        """
        command = "sudo lshw -c network -businfo | grep %s | grep ConnectX" % (nic_name)
        ret_val, err_info, exit_status = self.execute_command(command)

        if exit_status != 0:
            logging.error("%s is not Mellanox ConnectX NIC" % nic_name)
            return False
        else:
            logging.info("%s is Mellanox ConnectX NIC" % nic_name)
            return True

    def get_nic_vendor(self):
        """ Get the vendor of the NIC of the host and store it in self.nic_vendor

        Returns:
            NICVendor: The NIC vendor
        """
        # Return previously recorded value if available
        if self.nic_vendor != None:
            return self.nic_vendor

        if 'nic' not in self.conf:
            logging.error("NIC configuration not found for %s." % self.hostname)
            self.nic_vendor = NICVendor.Unkown

        elif 'type' not in self.conf['nic']:
            # If NIC type is not specified, try to detect it automatically
            logging.error("NIC type not configured for %s." % self.hostname)
            if 'if-name' in self.conf['nic'] and \
               self.check_mlnx_connectx_hwinfo(self.conf['nic']['if-name']):
                self.nic_vendor = NICVendor.MLNX
            self.nic_vendor = NICVendor.Unkown

        else:
            # If NIC type is specified, use it directly (no detection)
            nic_type = self.conf['nic']['type']
            if nic_type not in NIC_TYPE2VENDOR_MAP.keys():
                logging.error("Unkown NIC type %s" % nic_type)
            else:
                self.nic_vendor = NIC_TYPE2VENDOR_MAP[nic_type]

        return self.nic_vendor

    def is_mlnx_nic(self):
        """ Check if the NIC is a Mellanox NIC or not

        Returns:
            True if the NIC is a Mellanox NIC, False otherwise
        """
        return self.get_nic_vendor() == NICVendor.MLNX

    def is_intel_nic(self):
        """ Check if the NIC is an Intel NIC or not

        Returns:
            True if the NIC is an Intel NIC, False otherwise
        """
        return self.get_nic_vendor() == NICVendor.Intel

    @abstractmethod
    def get_mac_address(self):
        """ Get the MAC address of the NIC of the host """
        pass

    @abstractmethod
    def fetch_results(self, local_dir):
        """ Fetch the results from the host to the local directory """
        pass

    def sync(self, local_workspace, prog_dir_name):
        """ Synchrnoize the code to the host

        Args:
            local_workspace (str): Local workspace path
            prog_dir_name (str): Program directory name

        Returns:
            bool: True if success, False otherwise
        """
        remote_path = self.conf['workspace']
        local_path = os.path.join(local_workspace, prog_dir_name)
        target_dir = os.path.join(remote_path, prog_dir_name)

        try:
            self.upload_files(local_path, remote_path)
        except:
            logging.error("Failed to copy code from %s to %s:%s" % (local_path, self.hostname, target_dir))
            self.disconnect()
            return False

        logging.info("Successfully copy code to %s:%s" % (self.hostname, target_dir))
        return True

    def sync_and_compile(self, local_workspace, prog_dir_name, prog_file_name):
        """ Synchrnoize the code to the host and compile it

        Args:
            local_workspace (str): Local workspace path
            prog_dir_name (str): Program directory name
            prog_file_name (str): Program file name

        Returns:
            bool: True if success, False otherwise
        """
        remote_path = self.conf['workspace']
        local_path = os.path.join(local_workspace, prog_dir_name)

        try:
            self.upload_files(local_path, remote_path)
        except:
            logging.error("Failed to copy code to the remote server")
            self.disconnect()
            return False

        target_dir = os.path.join(remote_path, prog_dir_name)
        command = "cd %s; make clean; rm -f *.log; make > %s_compile.log" % (target_dir, prog_file_name)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to compile code at %s" % target_dir)
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        logging.info("Successfully copy and compile code at %s:%s" % (self.hostname, target_dir))
        return True

class RDMAHost(Host):
    """ Class to control the host for RDMA traffic generation """
    def __init__(self, config):
        """ Constructor """
        Host.__init__(self, config)

    def traffic_gen_dir_name(self):
        """ Get the traffic generation directory name """
        return "my-ib-traffic-gen"

    def traffic_gen_client_name(self, rdma_verb):
        """ Get the traffic generation client name

        Args:
            rdma_verb (str): RDMA verb (e.g., send, write, read, send_read)

        Returns:
            str: Traffic generation client name
        """
        return "ib_%s_client" % rdma_verb

    def traffic_gen_server_name(self, rdma_verb):
        """ Get the traffic generation server name

        Args:
            rdma_verb (str): RDMA verb (e.g., send, write, read, send_read)

        Returns:
            str: Traffic generation server name
        """
        return "ib_%s_server" % rdma_verb

    def get_mac_address(self):
        """ Get the MAC address of the NIC of the host and store it in self.conf['nic']['mac']

        Returns:
            bool: True if success, False otherwise
        """
        nic_conf = self.conf['nic']
        nic_name = nic_conf['if-name']
        command = "ethtool -P %s | awk -F 'Permanent address:' '{print $2}'" % (nic_name)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Get MAC address failed")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        self.conf['nic']['mac'] = ret_val[0]
        return True

    def config_ip_address(self):
        """ Configure the IP address of the NIC of the host

        Returns:
            bool: True if success, False otherwise
        """
        ## delete other ip addresses and add ip address in the ip-list
        ip_list = self.conf['nic']['ip-list']
        nic_name = self.conf['nic']['if-name']

        command = "sudo ip addr flush dev %s; sudo ip -6 addr flush dev %s; " % (nic_name, nic_name)
        for ip in ip_list:
            command = command +  "sudo ip addr replace %s dev %s; " % (ip, nic_name)

        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to add ip addrs for dev %s", (nic_name))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        return True

    def config_mlnx_traffic_classes(self):
        """ Configure the traffic classes of the Mellanox NIC of the host, including:
            - DSCP-to-priority mapping
            - QoS to realize fair bandwidth allocation

        Returns:
            bool: True if success, False otherwise
        """
        if 'prio-dscp-map' not in self.conf['nic']:
            logging.info("No traffic class mapping found, using default DSCP mapping.")
            prio2dscp = DEFAULT_PRIO2DSCP_MAP
        else:
            prio2dscp = self.conf['nic']['prio-dscp-map']

        nic_name = self.conf['nic']['if-name']
        command = "sudo mlnx_qos -i %s --trust=dscp" % nic_name
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to set trust=dscp for %s" % (nic_name))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        prio_list = prio2dscp.keys()
        for prio in prio_list:
            dscp_list = prio2dscp[prio].split(',')
            for dscp_str in dscp_list:
                if not dscp_str.isdigit():
                    logging.error("Illegal setting for prio-dscp-map (DSCP should be an integer).")
                    return False
                dscp_int = int(dscp_str)
                if dscp_int < MIN_DSCP or dscp_int > MAX_DSCP:
                    logging.error("Illegal dscp2prio mapping (DSCP should be in [%d,%d])." % (MIN_DSCP, MAX_DSCP))
                    return False
            for dscp_str in dscp_list:
                dscp_int = int(dscp_str)
                command = "sudo mlnx_qos -i %s --dscp2prio=set,%d,%d" % (nic_name, dscp_int, prio)
                ret_val, err_info, exit_status = self.execute_command(command)
                if exit_status != 0:
                    logging.error("Failed to set dscp2prio mapping for dscp %d->prio %d on %s" % (dscp_int, prio, nic_name))
                    logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
                    return False

        ## Configure QoS to realize fair bandwidth allocation
        ## Map priorities 0-7 to traffic classes 0-7 respectively
        prio_to_tc_str = "0,1,2,3,4,5,6,7"
        ## Use ETS (essentially DWRR) to schedule packet transmissions of all the traffic classes
        schedule_algo_str = "ets,ets,ets,ets,ets,ets,ets,ets"
        ## Set minimum gurantee bandwidth (weight) of 8 traffic classes to 12%,13%...
        min_bw_str = "12,13,12,13,12,13,12,13"

        command = "sudo mlnx_qos -i %s -p %s -s %s -t %s" % (nic_name, prio_to_tc_str, schedule_algo_str, min_bw_str)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to configue Enhanced Transmission Selection (ETS) on %s" % (nic_name))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        return True

    def get_intel_current_tc_mapping(self, lldptool_retry_limit=10):
        """ Get the current traffic class mapping of the Intel NIC of the host

        Args:
            lldptool_retry_limit (int, optional): maximum times of LLDPtool retriment on timeout, default 10

        Returns:
            list: A list of (priority, dscp) pairs, or None on failure
        """
        nic_name = self.conf['nic']['if-name']

        for rtrycnt in range(lldptool_retry_limit):
            if rtrycnt:
                logging.info("lldptool query mapping timed out, retry in 5 seconds.")
                time.sleep(5)

            command = "sudo lldptool -t -i %s -V APP -c" % nic_name
            ret_val, err_info, exit_status = self.execute_command(command)

            if not (exit_status != 0 and len(ret_val) > 0 and ret_val[0].find("timeout") != -1):
                break

        if exit_status != 0:
            logging.error("Failed to check current dscp2prio mapping for %s" % (nic_name))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return None

        # ret_val: list of 'id:(prio,5,dscp) local  hw (status)'
        # e.g. ['0:(1,5,9) local  hw (set)', '1:(1,5,8) local  hw (set)', '2:(2,5,23) local  hw (set)', ...]
        pattern = r"(\d+)\:\((\d+),(\d+),(\d+)\) +local +hw.*"
        ret_list = []
        for ret_line in ret_val:
            match_obj = re.match(pattern, ret_line)
            if match_obj:
                prio = int(match_obj.group(2))
                dscp = int(match_obj.group(4))
                ret_list.append((prio, dscp))

        return ret_list

    def modify_intel_tc_mapping(self, prio, dscp, lldptool_retry_limit=10, is_insert=True):
        """ Modify the traffic class mapping of the Intel NIC of the host

        Args:
            prio (int): priority
            dscp (int): DSCP
            lldptool_retry_limit (int, optional): maximum times of LLDPtool retriment on timeout, default 10
            is_insert (bool, optional): True if insert the mapping (prio, dscp), False if delete the mapping

        Returns:
            bool: True if success, False otherwise
        """
        operation = "remove old" if not is_insert else "insert"
        nic_name = self.conf['nic']['if-name']

        for rtrycnt in range(lldptool_retry_limit):

            if rtrycnt:
                logging.info("lldptool %s mapping timed out, retry in 5 seconds." % operation)
                time.sleep(5)

                tmp_map_list = self.get_intel_current_tc_mapping()
                if tmp_map_list == None:
                    logging.info("Failed to recover from timeout, abort.")
                    logging.info("Failed to %s DSCP-priority mappings." % operation)
                    return False
                if ((prio, dscp) in tmp_map_list) == is_insert:
                    exit_status = 0
                    break

            command = "sudo lldptool -T -i %s -V APP %sapp=%d,5,%d" % (nic_name, "" if is_insert else "-d ", prio, dscp)
            ret_val, err_info, exit_status = self.execute_command(command)

            if not (exit_status != 0 and len(ret_val) > 0 and ret_val[0].find("timeout") != -1):
                break

        if exit_status != 0:
            logging.error("Failed to %s dscp2prio mapping for %s" % (operation, nic_name))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        return True


    def config_intel_traffic_classes(self, lldptool_workload_limit=5, lldptool_retry_limit=10):
        """ Configure the traffic classes of the Intel NIC of the host, including:
            - DSCP-to-priority mapping
            - QoS to realize fair bandwidth allocation

        Args:
            lldptool_workload_limit (int, optional): limit of concurrent workload for lldptool,
                sleep 3 seconds per such number of mapping modifications.
            lldptool_retry_limit (int, optional): maximum times of LLDPtool retriment on timeout, default 10

        Returns:
            bool: True if success, False otherwise
        """
        intel_dscp_warned = False
        lldptool_workload_counter = 0

        if 'prio-dscp-map' not in self.conf['nic']:
            logging.info("No traffic class mapping found, using default DSCP mapping.")
            prio2dscp = DEFAULT_PRIO2DSCP_MAP
        else:
            prio2dscp = self.conf['nic']['prio-dscp-map']

        nic_name = self.conf['nic']['if-name']

        command = "sudo ethtool --set-priv-flags %s fw-lldp-agent off" % nic_name
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to disable FW-LLDP for %s" % (nic_name))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        prev_map_list = self.get_intel_current_tc_mapping(lldptool_retry_limit)
        if prev_map_list == None:
            logging.info("Failed to read current DSCP-priority mappings.")
            return False

        target_map_list = []
        prio_list = prio2dscp.keys()
        for prio in prio_list:
            dscp_list = prio2dscp[prio].split(',')
            for dscp_str in dscp_list:
                if not dscp_str.isdigit():
                    logging.error("Illegal setting for prio-dscp-map (DSCP should be an integer).")
                    return False
                dscp_int = int(dscp_str)
                if dscp_int < MIN_DSCP or dscp_int > MAX_DSCP:
                    logging.error("Illegal dscp2prio mapping (DSCP should be in [%d,%d])." % (MIN_DSCP, MAX_DSCP))
                    return False
                if dscp_int > INTEL_MAX_DSCP:
                    if not intel_dscp_warned:
                        logging.info("Intel NICs only support DSCP 0-%d." % (INTEL_MAX_DSCP))
                        intel_dscp_warned = True
                    continue
                target_map_list.append((prio, dscp_int))

        for prio, dscp in prev_map_list:
            if (prio, dscp) in target_map_list:
                continue

            modify_ret = self.modify_intel_tc_mapping(prio, dscp, lldptool_retry_limit, is_insert=False)
            if not modify_ret:
                return False

            lldptool_workload_counter += 1
            if lldptool_workload_counter >= lldptool_workload_limit:
                time.sleep(3)
                lldptool_workload_counter = 0

        time.sleep(10)      # pending delete

        ## Configure QoS to realize fair bandwidth allocation
        ## Map priorities 0-7 to traffic classes 0-3 respectively
        prio_to_tc_str = "0:0,1:1,2:2,3:3,4:0,5:1,6:2,7:3"
        ## Use ETS (essentially DWRR) to schedule packet transmissions of all the traffic classes
        schedule_algo_str = "0:ets,1:ets,2:ets,3:ets,4:strict,5:strict,6:strict,7:strict"
        ## Set minimum gurantee bandwidth (weight) of 8 traffic classes to 25%,25%...
        min_bw_str = "25,25,25,25,0,0,0,0"

        for rtrycnt in range(lldptool_retry_limit):

            if rtrycnt:
                logging.info("lldptool set ETS configuration timed out, retry in 5 seconds.")
                time.sleep(5)

            command = "sudo lldptool -Ti %s -V ETS-CFG willing=no up2tc=%s tsa=%s tcbw=%s" %\
                (nic_name, prio_to_tc_str, schedule_algo_str, min_bw_str)
            ret_val, err_info, exit_status = self.execute_command(command)

            if not (exit_status != 0 and len(ret_val)>0 and ret_val[0].find("timeout") != -1):
                break

        if exit_status != 0:
            logging.error("Failed to set ETS configuration for %s" % (nic_name))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        for prio, dscp in target_map_list:
            if (prio, dscp) in prev_map_list:
                continue

            modify_ret = self.modify_intel_tc_mapping(prio, dscp, lldptool_retry_limit, is_insert=True)
            if not modify_ret:
                return False

            lldptool_workload_counter += 1
            if lldptool_workload_counter >= lldptool_workload_limit:
                time.sleep(3)
                lldptool_workload_counter = 0

        time.sleep(10)      # pending set

        return True


    def config_traffic_classes(self):
        """ Configure the traffic classes of the NIC of the host

        Returns:
            bool: True if success, False otherwise
        """
        if self.is_mlnx_nic():
            return self.config_mlnx_traffic_classes()
        elif self.is_intel_nic():
            return self.config_intel_traffic_classes()
        else:
            logging.error("Cannot configure traffic classes for unknown NIC type.")
            return False

    def config_mlnx_roce_parameter(self):
        """ Configure the RoCE parameters of the Mellanox NIC of the host, including:
            - min_time_between_cnps
            - roce_np_enable
            - roce_rp_enable
            - roce_adp_retrans_en
            - roce_slow_restart_en

        Returns:
            bool: True if success, False otherwise
        """
        nic_name = self.conf['nic']['if-name']
        pci_addr = self.conf['nic']['pci-addr']

        min_time_between_cnps = self.conf['roce-parameters']['min-time-between-cnps']
        np_enable = int(self.conf['roce-parameters']['dcqcn-np-enable'])
        rp_enable = int(self.conf['roce-parameters']['dcqcn-rp-enable'])
        adaptive_retrans = int(self.conf['roce-parameters']['adaptive-retrans'])
        slow_restart = int(self.conf['roce-parameters']['slow-restart'])

        command = "echo %d | sudo tee /sys/class/net/%s/ecn/roce_np/min_time_between_cnps" % (min_time_between_cnps, nic_name)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to config min_time_between_cnps for dev %s", (nic_name))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        command = "echo %d | sudo tee /sys/class/net/%s/ecn/roce_rp/enable/*" % (rp_enable, nic_name)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to set roce_rp enable/disable status for dev %s", (nic_name))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        command = "echo %d | sudo tee /sys/class/net/%s/ecn/roce_np/enable/*" % (np_enable, nic_name)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to set roce_np enable/disable status for dev %s", (nic_name))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        command = "sudo mlxreg -d %s --reg_name ROCE_ACCL --set roce_adp_retrans_en=%d --yes" % (pci_addr, adaptive_retrans)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to set roce_adp_retrans_en for dev %s", (nic_name))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        command = "sudo mlxreg -d %s --reg_name ROCE_ACCL --set roce_slow_restart_en=%d --yes" % (pci_addr, slow_restart)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to set roce_slow_restart_en for dev %s", (nic_name))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        return True

    def config_intel_roce_parameter(self):
        """ Configure the RoCE parameters of the Intel NIC of the host, including:
            - dcqcn-enable

        Returns:
            bool: True if success, False otherwise
        """
        ib_dev = self.conf['nic']['ib-device']
        dcqcn_enable = int(self.conf['roce-parameters']['dcqcn-enable'])

        command = "sudo mkdir -p /sys/kernel/config/irdma/%s" % (ib_dev)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to create a new directory for dev %s under the irdma configfs", (ib_dev))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        command = "echo %d | sudo tee /sys/kernel/config/irdma/%s/roce_dcqcn_enable" % (dcqcn_enable, ib_dev)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to config roce_dcqcn_enable for dev %s", (ib_dev))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        command = "sudo rmdir /sys/kernel/config/irdma/%s" % (ib_dev)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to remove the irdma configfs directory for dev %s", (ib_dev))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        return True

    def config_roce_parameter(self):
        """ Configure the RoCE parameters of the NIC of the host

        Returns:
            bool: True if success, False otherwise
        """
        if self.is_mlnx_nic():
            return self.config_mlnx_roce_parameter()

        elif self.is_intel_nic():
            return self.config_intel_roce_parameter()

        else:
            nic_type = self.conf['nic']['type'] if ('nic' in self.conf and 'type' in self.conf['nic']) else "\"Not configured\""
            logging.error("Failed to config roce parameters: Unsupported NIC type %s.", (nic_type))
            logging.info("Available NIC types:")
            mlnx_nic_list = list(filter(lambda key:NIC_TYPE2VENDOR_MAP.get(key)==NICVendor.MLNX, NIC_TYPE2VENDOR_MAP.keys()))
            logging.info("Mellanox: %s", str(mlnx_nic_list))
            intel_nic_list = list(filter(lambda key:NIC_TYPE2VENDOR_MAP.get(key)==NICVendor.Intel, NIC_TYPE2VENDOR_MAP.keys()))
            logging.info("Intel: %s", str(intel_nic_list))
            return False

    def config_traffic_gen(self):
        """ Configure the host for RDMA traffic generation, including:
            - Configure IP addresses
            - Configure traffic classes
            - Configure RoCE parameters
            - Remove old result files

        Returns:
            bool: True if success, False otherwise
        """
        ## Stop the existing rdma apps
        command = ""
        for app_role in ['client', 'server']:
            command = command + "ps -ef | grep 'ib_.*_%s' | grep -v grep | awk '{print $2}' | xargs sudo kill -9; " % app_role
        try:
            self.execute_command(command)
        except:
            logging.error("Failed to stop existing RDMA apps")
            self.disconnect()
            return False

        ## Config multiple IPs
        if self.config_ip_address() == False:
            logging.error("Failed to configure IP addresses")
            self.disconnect()
            return False

        ## Config traffic classes
        if self.config_traffic_classes() == False:
            logging.error("Failed to configure traffic classes")
            self.disconnect()
            return False

        ## Config RoCE parameters
        if self.config_roce_parameter() == False:
            logging.error("Failed to configure RoCE parameters")
            self.disconnect()
            return False

        ## Remove old result files
        workspace = self.conf['workspace']
        result_dir = os.path.join(workspace, RDMA_RESULT_DIR)
        command = "if [ -d %s ] && [ -n \"$(ls -A %s)\" ]; then rm -f %s/*; fi" % (result_dir, result_dir, result_dir)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to remove old result files in %s, the directory may be empty" % (result_dir))
            return False

        return True

    def run_traffic_gen_server(self, traffic_conf):
        """ Run traffic generator server

        Args:
            traffic_conf (dict): traffic configuration

        Returns:
            bool: True if success, False otherwise
        """
        workspace = self.conf['workspace']
        rdma_verb = traffic_conf['rdma-verb'].strip().lower()
        if rdma_verb not in VALID_IB_VERB_LIST_LOWER:
            logging.error("Invalid RDMA verb: %s" % rdma_verb)
            return False

        traffic_gen_dir_path = os.path.join(workspace, self.traffic_gen_dir_name())
        result_dir = os.path.join(workspace, RDMA_RESULT_DIR)
        result_file_path = os.path.join(result_dir, '%s_run.log' % self.traffic_gen_server_name(rdma_verb))

        command = "sudo %s/%s -d %s -i %d -s %d -p %d -q %s %s -u %d -R %d -M %d %s > %s 2>&1 &" % \
               (traffic_gen_dir_path,
                self.traffic_gen_server_name(rdma_verb),
                self.conf['nic']['ib-device'],
                self.conf['nic']['ib-port'],
                traffic_conf['message-size'],
                traffic_conf['listen-port'],
                str(traffic_conf['num-qps']).replace(',', '_'),
                IB_OPTION_MULTI_GID if (traffic_conf['multi-gid']) else IB_OPTION_NONE,
                traffic_conf['min-retransmit-timeout'],
                traffic_conf['max-retransmit-retry'],
                traffic_conf['mtu'],
                "-D %s" % traffic_conf['dscp-list'] if 'dscp-list' in traffic_conf else "",
                result_file_path)

        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to run traffic generator (server)")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        return True

    def run_traffic_gen_client(self,
                               traffic_conf,
                               destination_ip,
                               controller_ip=None,
                               controller_listen_port=None):
        """ Run traffic generator client

        Args:
            traffic_conf (dict): traffic configuration
            destination_ip (str): destination IP address
            controller_ip (str, optional): controller IP address, default None
            controller_listen_port (int, optional): controller listen port, default None

        Returns:
            bool: True if success, False otherwise
        """
        workspace = self.conf['workspace']
        rdma_verb = traffic_conf['rdma-verb'].strip().lower()
        if rdma_verb not in VALID_IB_VERB_LIST_LOWER:
            logging.error("Invalid RDMA verb: %s" % rdma_verb)
            return False

        traffic_gen_dir_path = os.path.join(workspace, self.traffic_gen_dir_name())
        result_dir = os.path.join(workspace, RDMA_RESULT_DIR)
        result_file_path = os.path.join(result_dir, '%s_run.log' % self.traffic_gen_client_name(rdma_verb))

        command = "sudo %s/%s -d %s -i %d -s %d -p %d -n %d -q %s %s %s %s %s -t %d -u %d -R %d -M %d %s %s > %s 2>&1" % \
               (traffic_gen_dir_path,
                self.traffic_gen_client_name(rdma_verb),
                self.conf['nic']['ib-device'],
                self.conf['nic']['ib-port'],
                traffic_conf['message-size'],
                traffic_conf['listen-port'],
                traffic_conf['num-msgs-per-qp'],
                str(traffic_conf['num-qps']).replace(',', '_'),
                IB_OPTION_CONTROLLER_IP + controller_ip if controller_ip != None else IB_OPTION_NONE,
                IB_OPTION_CONTROLLER_LISTEN_PORT + str(controller_listen_port) if controller_listen_port != None else IB_OPTION_NONE,
                IB_OPTION_MULTI_GID if (traffic_conf['multi-gid']) else IB_OPTION_NONE,
                IB_OPTION_BARRIER_SYNC if (traffic_conf['barrier-sync']) else IB_OPTION_NONE,
                traffic_conf['tx-depth'],
                traffic_conf['min-retransmit-timeout'],
                traffic_conf['max-retransmit-retry'],
                traffic_conf['mtu'],
                "-D %s" % traffic_conf['dscp-list'] if 'dscp-list' in traffic_conf else "",
                destination_ip,
                result_file_path)

        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to run traffic generator (client)")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        return True

    def clean_up(self):
        """ Clean up RDMA traffic generator processes

        Returns:
            bool: True if success, False otherwise
        """
        command = ""
        for app_role in ['client', 'server']:
            command = command + "ps -ef | grep 'ib_.*_%s' | grep -v grep | awk '{print $2}' | xargs sudo kill -9; " % app_role

        try:
            self.execute_command(command)
            self.disconnect()

        except:
            logging.error("Failed to stop existing RDMA apps")
            self.disconnect()
            return False

        return True

    def dump_counters(self, file_name):
        """ Dump counters of the NIC of the host to a file

        Args:
            file_name (str): file name

        Returns:
            bool: True if success, False otherwise
        """
        prog_path = os.path.join(self.conf['workspace'], DUMP_COUNTER_DIR_NAME, DUMP_COUNTER_PROG_NAME)
        result_dir = os.path.join(self.conf['workspace'], RDMA_RESULT_DIR)
        log_path = os.path.join(self.conf['workspace'], DUMP_COUNTER_DIR_NAME, "dump_counter.log")

        command = "mkdir -p %s" % result_dir
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to create result dir")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        file_path = os.path.join(result_dir, file_name)
        ib_dev = self.conf['nic']['ib-device']
        ib_port = self.conf['nic']['ib-port']
        nic_name = self.conf['nic']['if-name']

        nic_vendor = self.get_nic_vendor().name

        command = "python %s -f %s -d %s -i %d -n %s -v %s > %s" % (prog_path, file_path, ib_dev, ib_port, nic_name, nic_vendor, log_path)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to dump counters")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        return True

    def fetch_results(self, local_dir):
        """ Fetch results from the host to a local directory

        Args:
            local_dir (str): local directory

        Returns:
            bool: True if success, False otherwise
        """
        remote_dir = os.path.join(self.conf['workspace'], RDMA_RESULT_DIR)
        try:
            self.download_file(remote_dir, local_dir)
        except:
            logging.error("Failed to download files from remote server")
            self.disconnect()
            return False

        logging.info("Successfully downloaded files to %s" % local_dir)
        return True

class MirrorHost(Host):
    """ Class to control the host to dump mirrored traffic """
    def __init__(self, config):
        Host.__init__(self, config)

    def unbind_dpdk(self):
        """ Unbind DPDK driver for the NIC (Intel NIC only)

        Returns:
            bool: True if success, False otherwise
        """
        nic_name = self.conf['nic']['if-name']
        pci_addr = self.conf['nic']['pci-addr']
        if 'type' not in self.conf['nic']:
            logging.error("Failed to unbind DPDK driver for %s as NIC type not specified.", nic_name)
            return False

        nic_type = self.conf['nic']['type']
        if nic_type not in MIRROR_LEGACY_DRIVER_MAP.keys():
            logging.error("Unsupported NIC type %s", nic_type)
            return False

        legacy_driver = MIRROR_LEGACY_DRIVER_MAP[nic_type]
        command = " sudo dpdk-devbind.py -u %s;" % pci_addr
        command = command + " sudo dpdk-devbind.py -b %s %s" % (legacy_driver, pci_addr)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to unbind DPDK driver for %s" % nic_name)
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        return True

    def bind_dpdk(self):
        """ Bind DPDK driver for the NIC (Intel NIC only)

        Returns:
            bool: True if success, False otherwise
        """
        nic_name = self.conf['nic']['if-name']
        pci_addr = self.conf['nic']['pci-addr']
        if 'type' not in self.conf['nic']:
            logging.error("Failed to bind DPDK driver for %s as NIC type not specified.", nic_name)
            return False

        nic_type = self.conf['nic']['type']
        if nic_type not in MIRROR_DPDK_DRIVER_MAP.keys():
            logging.error("Unsupported NIC type %s", nic_type)
            return False

        dpdk_driver = MIRROR_DPDK_DRIVER_MAP[nic_type]
        command = " sudo dpdk-devbind.py -u %s;" % pci_addr
        command = command + " sudo dpdk-devbind.py -b %s %s" % (dpdk_driver, pci_addr)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to bind DPDK driver for %s, please check '%s' kernel module is loaded" % (nic_name, dpdk_driver))
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            return False

        return True

    def get_mac_address(self):
        """ Get MAC address of the NIC of the host and store it in self.conf['nic']['mac']

        Returns:
            bool: True if success, False otherwise
        """
        nic_conf = self.conf['nic']
        nic_name = nic_conf['if-name']

        ## If the NIC is an Intel NIC, we should unbind its DPDK driver first
        if self.is_intel_nic():
            if 'pci-addr' not in nic_conf:
                logging.error("No pci address provided for Intel NIC")
                self.disconnect()
                return False

            if not self.unbind_dpdk():
                logging.error("Cannot unbind DPDK driver for %s" % nic_name)
                self.disconnect()
                return False

            logging.info("Successfully unbind DPDK driver for %s" % nic_name)

        command = "ethtool -P %s | awk -F 'Permanent address:' '{print $2}'" % (nic_name)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to get MAC address")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        self.conf['nic']['mac'] = ret_val[0]
        return True

    def config_packet_capture(self):
        """ Configure the host for packet capture, including:
            - Stop the existing packet capture process (if any)
            - Bind DPDK driver for Intel NIC
            - Remove old result files

        Returns:
            bool: True if success, False otherwise
        """
        ## Stop the existing packet capture process
        command = ""
        for app_name in [PKT_CAPTURE_FILE_NAME]:
            command = command + "ps -ef | grep %s | grep -v grep | awk '{print $2}' | xargs sudo kill -9; " % app_name
        try:
            self.execute_command(command)
        except:
            logging.error("Failed to stop existing packet capture process")
            self.disconnect()
            return False

        ## Bind DPDK driver if it is an Intel NIC
        nic_name = self.conf['nic']['if-name']
        if self.is_intel_nic():
            if 'pci-addr' not in self.conf['nic']:
                logging.error("No pci address provided for Intel NIC")
                self.disconnect()
                return False

            if not self.bind_dpdk():
                logging.error("Could not bind DPDK driver for %s" % nic_name)
                self.disconnect()
                return False

            logging.info("Successfully bind DPDK driver for %s" % nic_name)

        ## Remove old result files
        workspace = self.conf['workspace']
        result_dir = os.path.join(workspace, PCAP_RESULT_DIR)
        command = "if [ -d %s ] && [ -n \"$(ls -A %s)\" ]; then rm -f %s/*; fi" % (result_dir, result_dir, result_dir)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to remove old result files in %s, the directory may be empty" % (result_dir))
            self.disconnect()
            return False

        return True

    def get_nic_numa(self):
        """ Get NUMA node id of the NIC of the host

        Returns:
            int: NUMA node id of the NIC of the host if success, -1 otherwise
        """
        nic_conf=self.conf['nic']
        nic_pci_addr=nic_conf['pci-addr']
        command = "cat /sys/bus/pci/devices/0000\\:%s/numa_node" % nic_pci_addr.replace(":", "\\:")
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to get NUMA node id.")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return -1

        return int(ret_val[0])

    def get_numa_cpus(self, numa_id):
        """ Get CPUs under the specified NUMA node

        Args:
            numa_id (int): NUMA node id

        Returns:
            list: list of CPUs under the specified NUMA node (sorted) if success, empty list otherwise
        """
        command = "ls /sys/devices/system/node/node%d/ | grep cpu" % numa_id
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to list cpu under NUMA node %d."%numa_id)
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return []

        cpu_list = []
        for ret_v in ret_val:
            if re.search("^cpu\d+$", ret_v):
                cpu_list.append(int(ret_v[3:]))

        if len(cpu_list) == 0:
            logging.error("Failed to list cpu under NUMA node %d: No available cpu found."%numa_id)
            self.disconnect()
            return []

        cpu_list.sort()
        return cpu_list

    def run_packet_capture(self):
        """ Run packet capture application to dump mirrored traffic

        Returns:
            bool: True if success, False otherwise
        """
        #sudo ./dpdk-pkt-dump -l 0 -- -t
        workspace = self.conf['workspace']
        result_dir = os.path.join(workspace, PCAP_RESULT_DIR)

        command = "mkdir -p %s" % result_dir
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to create result dir")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        pkt_capture_file_path = os.path.join(workspace, PKT_CAPTURE_DIR_NAME, PKT_CAPTURE_FILE_NAME)
        nic_numa_id = self.get_nic_numa()
        numa_cpu_list = self.get_numa_cpus(nic_numa_id)
        lcores_str = "%d" % numa_cpu_list[0]
        for i in range(1, min(len(numa_cpu_list), NUM_LCORES_CAPTURE_PKTS)):
            lcores_str += ",%d" % numa_cpu_list[i]
        command = "sudo %s --lcores %s -- -p %d -u %d -f %s -s %d -n %d > %s.log 2>&1 &" % \
            (pkt_capture_file_path,
             lcores_str,
             self.conf['nic']['rte-port-id'],
             self.conf['pkt-dump-conf']['rewrite-udp-dst-port'],
             os.path.join(result_dir, self.conf['pkt-dump-conf']['dump-filename']),
             self.conf['pkt-dump-conf']['snap-len'],
             self.conf['pkt-dump-conf']['num-pkts'],
             pkt_capture_file_path)

        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to run packet capture")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        return True

    def clean_up(self):
        """ Clean up, including:
            - Stop the existing packet capture process (if any)
            - Unbind DPDK driver for Intel NIC
            - Disconnect from the host

        Returns:
            bool: True if success, False otherwise
        """
        ## Stop the existing packet capture process (send a SIGTERM signal)
        command = ""
        for app_name in [PKT_CAPTURE_FILE_NAME]:
            command = command + "ps -ef | grep %s | grep -v grep | awk '{print $2}' | xargs sudo kill; " % app_name
        self.execute_command(command)

        ## Unbind DPDK driver if it is an Intel NIC
        nic_conf = self.conf['nic']
        nic_name = nic_conf['if-name']
        if self.is_intel_nic():
            if 'pci-addr' not in nic_conf:
                logging.error("No pci address provided for Intel NIC")
                self.disconnect()
                return False

            if not self.unbind_dpdk():
                logging.error("Could not unbind DPDK driver for %s" % nic_name)
                self.disconnect()
                return False

            logging.info("Successfully unbinded DPDK driver for %s" % nic_name)

        self.disconnect()
        return True

    def fetch_results(self, local_dir, max_wait_time_sec=5):
        """ Fetch results from the host to a local directory

        Args:
            local_dir (str): local directory
            max_wait_time_sec (int, optional): max wait time in seconds for the result files to be
                generated, default 5

        Returns:
            bool: True if success, False otherwise
        """
        remote_dir = os.path.join(self.conf['workspace'], PCAP_RESULT_DIR)
        find_pcap_cmd = 'find %s -type f -name \"*.pcap\"' % remote_dir
        find_pcap = False
        wait_time_sec = 0

        while True:
            ret_value, err_info, exit_status = self.execute_command(find_pcap_cmd)
            if exit_status == 0 and len(ret_value) > 0:
                find_pcap = True
                break

            wait_time_sec += 1
            if wait_time_sec > max_wait_time_sec:
                break
            else:
                time.sleep(1)

        if find_pcap == False:
            logging.error("Failed to find pcap files in %s" % remote_dir)
            self.disconnect()
            return False

        try:
            self.download_file(remote_dir, local_dir)
        except:
            logging.error("Failed to download files from remote server")
            self.disconnect()
            return False

        logging.info("Successfully downloaded files to %s" % local_dir)
        return True
