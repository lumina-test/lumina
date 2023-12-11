import sys, yaml, os, logging
from lumina.orchestrator.remote_control import RemoteClient

SWITCH_PROG_DIR_NAME  = "switch"
SWITCH_PROG_FILE_NAME = "inject_switch"
SWITCH_CONFIG_FILE_NAME = "switch_config.yml"

P4_BUILD_SH = "p4_build.sh"
RUN_TOFINO_MODEL_SH = "run_tofino_model.sh"
RUN_SWITCHD_SH = "run_switchd.sh"
RUN_P4_TESTS_SH = "run_p4_tests.sh"
SWITCH_RESULT_DIR = "switch-result"

SWITCH_MESSAGE_SNAPSHOT = "switch_message_snapshot.yml"
SWITCH_STATE_SNAPSHOT   = "switch_state_snapshot.yml"

def export_cmd(variable, value=None):
    """ Return a command to export environment variable

    Args:
        variable (str): environment variable name
        value (str, optional): environment variable value

    Returns:
        str: command to export environment variable
    """
    if value != None and value != "":
        cmd = "export %s=%s;" % (variable, value)
    else:
        cmd = "export %s;" % (variable)
    return cmd

class Dumper(yaml.Dumper):
    """ Override the default indent for yaml dump """
    def increase_indent(self, flow=False, *args, **kwargs):
        ## Set indent for yaml dump
        return super(Dumper, self).increase_indent(flow=flow, indentless=False)

class Switch(RemoteClient):
    """ Class to control the switch """
    def __init__(self, config):
        """ Constructor for Switch

        Args:
            config (dict): switch config

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
        self._switch_conf = config

    @property
    def conf(self):
        return self._switch_conf

    def compile_cmd(self, envir_path, file_name, p4_name):
        """ Return a command to compile p4 program

        Args:
            envir_path (str): path to SDE environment
            file_name (str): p4 program source file name
            p4_name (str): p4 program name

        Returns:
            str: command to compile p4 program
        """
        p4_build = envir_path + P4_BUILD_SH
        cmd = export_cmd("SDE", envir_path)
        cmd = cmd + export_cmd("SDE_INSTALL", "$SDE/install")
        cmd = cmd + export_cmd("PATH", "$SDE_INSTALL/bin/:$PATH")
        cmd = cmd + "%s %s > /var/log/%s_compile.log 2>&1" % (p4_build, file_name, p4_name)
        return cmd

    def run_p4_app_cmd(self, envir_path, p4_name):
        """ Return a command to run p4 program

        Args:
            envir_path (str): path to SDE environment
            p4_name (str): p4 program name

        Returns:
            str: command to run p4 program
        """
        run_switchd = envir_path + RUN_SWITCHD_SH
        cmd = export_cmd("SDE", envir_path)
        cmd = cmd + export_cmd("SDE_INSTALL", "$SDE/install")
        cmd = cmd + export_cmd("PATH", "$SDE_INSTALL/bin/:$PATH")
        cmd = cmd + "%s -p %s > /var/log/%s_run_switchd.log 2>&1 &" % (run_switchd, p4_name, p4_name)
        return cmd

    def run_controller_cmd(self,
                           envir_path,
                           workspace,
                           p4_name,
                           config_filepath,
                           mode,
                           snapshot=None):
        """ Return a command to run controller

        Args:
            envir_path (str): path to SDE environment
            workspace (str): path to workspace
            p4_name (str): p4 program name
            config_filepath (str): path to switch config file
            mode (str): controller mode
            snapshot (str, optional): path to snapshot file. Defaults to None.

        Returns:
            str: command to run controller
        """
        cmd = export_cmd("SDE", envir_path)
        cmd = cmd + export_cmd("SDE_INSTALL", "$SDE/install")
        cmd = cmd + export_cmd("PATH", "$SDE_INSTALL/bin/:$PATH")

        cmd = cmd + "PYTHON_VER=`python --version 2>&1 | awk {'print $2'} | awk -F\".\" {'print $1\".\"$2'}`;"
        cmd = cmd + export_cmd("PYTHONPATH", "$SDE_INSTALL/lib/python$PYTHON_VER/site-packages/p4testutils:$SDE_INSTALL/lib/python$PYTHON_VER/site-packages/tofinopd/:$SDE_INSTALL/lib/python$PYTHON_VER/site-packages/tofino:$SDE_INSTALL/lib/python$PYTHON_VER/site-packages/:$PYTHONPATH")
        if snapshot == None:
            cmd = cmd + "python %s/controller/controller.py -n %s -f %s -m %s > /var/log/%s_run_controller_%s.log 2>&1" % \
                                (workspace, p4_name, config_filepath, mode, p4_name, mode)
        else:
            cmd = cmd + "python %s/controller/controller.py -n %s -f %s -m %s -s %s > /var/log/%s_run_controller_%s.log 2>&1" % \
                                (workspace, p4_name, config_filepath, mode, snapshot, p4_name, mode)
        if mode == 'event':
            ## Only block for init mode
            cmd = cmd + " &"
        return cmd

    def stop_p4_app_cmd(self):
        """ Return a command to stop the p4 program """
        return("ps -ef | grep tofino | grep -v grep | awk '{print $2}' | xargs -r sudo kill -9")

    def stop_controller_cmd(self, dir_name):
        """ Return a command to stop the controller """
        return("ps -ef | grep controller | grep %s | grep -v grep | awk '{print $2}' | xargs -r sudo kill -9" % dir_name)

    def sync_and_compile(self, local_workspace, prog_dir_name, prog_file_name):
        """ Sync and compile the p4 program on switch

        Args:
            local_workspace (str): path to local workspace
            prog_dir_name (str): p4 program directory name on switch
            prog_file_name (str): p4 program file name

        Returns:
            bool: True if successful, False otherwise
        """
        logging.info("Start to copy and compile on switch %s" % self.hostname)
        sde_path = self.conf['sde-path']
        remote_path = self.conf['workspace']
        local_path = os.path.join(local_workspace, prog_dir_name)

        try:
            self.upload_files(local_path, remote_path)
        except:
            logging.error("Failed to copy code from %s to switch %s:%s" %
                          (local_path, self.hostname, remote_path))
            self.disconnect()
            return False

        prog_file_path = os.path.join(remote_path, prog_dir_name, 'p4src', prog_file_name + ".p4")
        command = self.compile_cmd(sde_path, prog_file_path, prog_file_name)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to compile on switch %s" % self.hostname)
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        logging.info("Successfully copied and compiled the P4 code on switch %s" % self.hostname)
        return True

    def dump_controller_config(self, local_workspace):
        """ Dump the switch configuration into a yaml file and copy to switch

        Args:
            local_workspace (str): path to local workspace

        Returns:
            bool: True if successful, False otherwise
        """
        dump_config = {}

        try:
            dump_config['port-speed']           = self.conf['port-speed']
            dump_config['fec-type']             = self.conf['fec-type']
            dump_config['listen-port']          = self.conf['listen-port']
            dump_config['rewrite-udp-dst-port'] = self.conf['rewrite-udp-dst-port']
            dump_config['forward']              = self.conf['forward-table']
            dump_config['mirror']               = self.conf['mirror-table']
            dump_config['arp']                  = self.conf['arp-table']
            dump_config['traffic']              = self.conf['traffic']
            local_path = self.conf['local-switch-config-path']

            with open(local_path, 'w') as file:
                yaml.dump(dump_config, file, sort_keys=False, Dumper=Dumper)

        except:
            logging.error("Failed to dump switch config")
            self.disconnect()
            return False

        ## Copy the switch config file to the remote directory
        remote_path = os.path.join(self.conf['workspace'], SWITCH_PROG_DIR_NAME, "controller")
        try:
            self.upload_files(local_path, remote_path)
        except:
            logging.error("Failed to copy switch config file from %s to switch %s:%s" %
                          (local_path, self.hostname, remote_path))
            self.disconnect()
            return False

        logging.info("Successfully dumped yaml file (%s) for switch controller and copy to switch (%s)" %
                (local_path, remote_path))
        return True

    def run_switch(self):
        """ Run programs on switch, including data plane and control plane

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            remote_path = self.conf['workspace']
            sde_path = self.conf['sde-path']
            switch_config_filepath = self.conf['local-switch-config-path']
        except:
            logging.error("Failed to read the switch config")
            return False

        ## Stop the tofino program
        command = self.stop_p4_app_cmd() + "; " + self.stop_controller_cmd(SWITCH_PROG_DIR_NAME)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to stop the tofino program")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        ## Run our P4 program (data plane)
        command = self.run_p4_app_cmd(sde_path, SWITCH_PROG_FILE_NAME)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to run data plane module on switch")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        ## Run switch control plane - init
        mode = 'init'
        remote_switch_config_filepath = os.path.join(remote_path, SWITCH_PROG_DIR_NAME, 'controller', switch_config_filepath.split('/')[-1])
        remote_switch_workspace = os.path.join(remote_path, SWITCH_PROG_DIR_NAME)
        command = self.run_controller_cmd(envir_path = sde_path,
                                          workspace = remote_switch_workspace,
                                          p4_name = SWITCH_PROG_FILE_NAME,
                                          config_filepath = remote_switch_config_filepath,
                                          mode = mode)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to do initialization on switch")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        ## Run switch control plane - setup event table
        mode = 'event'
        result_dir = os.path.join(remote_path, SWITCH_RESULT_DIR)
        command = "mkdir -p %s" % result_dir
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to create result dir")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        switch_message_snapshot = os.path.join(result_dir, SWITCH_MESSAGE_SNAPSHOT)
        command = self.run_controller_cmd(envir_path = sde_path,
                                          workspace = remote_switch_workspace,
                                          p4_name = SWITCH_PROG_FILE_NAME,
                                          config_filepath = remote_switch_config_filepath,
                                          mode = mode,
                                          snapshot = switch_message_snapshot)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to setup event table on switch")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        return True

    def dump_results(self):
        """ Dump results on switch

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            remote_path = self.conf['workspace']
            sde_path = self.conf['sde-path']
            switch_config_filepath = self.conf['local-switch-config-path']
        except:
            logging.error("Failed to read the switch config")
            return False

        result_dir = os.path.join(remote_path, SWITCH_RESULT_DIR)
        command = "mkdir -p %s" % result_dir
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to create result dir")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        mode = 'dump'
        remote_switch_config_filepath = os.path.join(remote_path, SWITCH_PROG_DIR_NAME, 'controller', switch_config_filepath.split('/')[-1])
        remote_switch_workspace = os.path.join(remote_path, SWITCH_PROG_DIR_NAME)
        switch_state_snapshot = os.path.join(result_dir, SWITCH_STATE_SNAPSHOT)
        command = self.run_controller_cmd(envir_path = sde_path,
                                          workspace = remote_switch_workspace,
                                          p4_name = SWITCH_PROG_FILE_NAME,
                                          config_filepath = remote_switch_config_filepath,
                                          mode = mode,
                                          snapshot = switch_state_snapshot)
        ret_val, err_info, exit_status = self.execute_command(command)
        if exit_status != 0:
            logging.error("Failed to dump results on switch")
            logging.error("[Command return info]: %s %s" % (', '.join(ret_val), ', '.join(err_info)))
            self.disconnect()
            return False

        return True

    def clean_up(self):
        """ Clean up the switch """
        ## Stop the tofino program
        command = self.stop_p4_app_cmd() + "; " + self.stop_controller_cmd(SWITCH_PROG_DIR_NAME)

        try:
            self.execute_command(command)
            self.disconnect()

        except:
            logging.error("Failed to clean up the switch")
            return False

        return True

    def fetch_results(self, local_dir):
        """ Fetch results from switch to local directory

        Args:
            local_dir (str): path to local directory to store the results

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            remote_dir = os.path.join(self.conf['workspace'], SWITCH_RESULT_DIR)
            self.download_file(remote_dir, local_dir)
        except:
            logging.error("Failed to download files from remote server")
            self.disconnect()
            return False

        logging.info("Successfully downloaded files to %s" % local_dir)
        return True
