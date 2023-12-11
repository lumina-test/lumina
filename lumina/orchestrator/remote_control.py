import sys, logging
from paramiko import AutoAddPolicy, RSAKey, SSHClient
from paramiko.auth_handler import AuthenticationException
from scp import SCPClient, SCPException

class RemoteClient:
    """ Class to manage remote hosts """
    def __init__(self,
                 hostname,
                 username,
                 ssh_key_filepath,
                 remote_path = None,
                 local_path = "./"
                 ):
        """ Constructor for RemoteClient

        Args:
            hostname (str): hostname of the remote host
            username (str): username of the remote host
            ssh_key_filepath (str): path to the ssh key file
            remote_path (str): path to the remote directory
            local_path (str): path to the local directory

        Returns:
            N/A
        """
        self.hostname = hostname
        self.username = username
        self.ssh_key_filepath = ssh_key_filepath
        self.remote_path = remote_path
        self.local_path = local_path
        self.client = None

    def _connection(self):
        """ Create an SSH connection to the remote host

        Returns:
            SSHClient: an SSH connection to the remote host if successful
        """
        if self.client != None and self.client.get_transport() != None:
            return self.client

        try:
            self.client = SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(AutoAddPolicy())
            self.client.connect(
                self.hostname,
                username=self.username,
                key_filename=self.ssh_key_filepath,
                timeout=5000,
            )
            return self.client

        except AuthenticationException as e:
            print(f"Authentication failed: did you remember to create an SSH key? ({e})")
            sys.exit(-1)

    def _scp(self):
        """ Create an SCP connection to the remote host """
        conn = self._connection()
        return SCPClient(conn.get_transport())

    def disconnect(self):
        """ Disconnect the SSH connection """
        if (self.client != None) and (self.client.get_transport() != None):
            self.client.close()

    def execute_command(self, command):
        """ Execute a command on the remote host

        Args:
            command (str): command to execute

        Returns:
            ret_value (list): list of strings of the stdout
            err_info (list): list of strings of the stderr
            exit_status (int): exit status of the command
        """
        ret_value = []
        err_info = []

        logging.info("[%s] Execute: %s" % (self.hostname, command))
        stdin, stdout, stderr = self._connection().exec_command(command)
        exit_status = stdout.channel.recv_exit_status()

        for line in stdout.readlines():
            ret_value.append(line.strip())
        for line in stderr.readlines():
            err_info.append(line.strip())

        return ret_value, err_info, exit_status

    def upload_files(self, files, remote_path=None):
        """ Upload files to a remote directory

        Args:
            files (str): path to the files to be uploaded
            remote_path (str, optional): path to the remote directory to store the files, defaults to None

        Returns:
            N/A
        """
        try:
            if remote_path == None:
                remote_path = self.remote_path

            self.execute_command("mkdir -p %s" % remote_path)
            self._scp().put(files, remote_path = remote_path, recursive=True)
            logging.info(f"Finished uploading {files} to {self.hostname}:{remote_path}")

        except SCPException as e:
            logging.error(f"Failed to scp the files to {self.hostname}:{remote_path}({e})")

    def download_file(self, file, local_path = "./"):
        """ Download a file from the remote host

        Args:
            file (str): path to the file to be downloaded
            local_path (str, optional): path to the local directory to store the file, defaults to "./"

        Returns:
            N/A
        """
        try:
            self._scp().get(file, local_path = local_path, recursive = True)
            logging.info(f"Finished downloading file to {local_path} from {self.hostname}")

        except SCPException as e:
            logging.error(f"Failed to scp the files from remote {self.hostname} ({e})")
