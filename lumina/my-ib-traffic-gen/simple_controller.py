#!/usr/bin/python3

import socket
import re
import sys

"""
This script is a simple controller for the RDMA traffic generator. The controller is
used to parse the runtime metadata, e.g., the queue pair number and the packet sequence
number of each queue pair, sent from the RDMA traffic generator. If the controller can
parse the metadata successfully, it will send the metadata back to the traffic generator.
"""

def str_to_int(str):
    """ Convert a string to an integer

    Args:
        str (str): The string to be converted

    Returns:
        int: The converted integer
    """
    m = re.search(r'\d+', str)
    numeric = m.group()
    return int(numeric)

def parse_data(msg):
    """ Parse the runtime metadata sent from the RDMA traffic generator

    Note:
        The runtime metadata is sent from the traffic generator in the following format:
        [verb];[number of QPs];[local QPN],[local PSN],[local GID];[remote QPN],[remote PSN],[remote GID];...&

    Args:
        msg (str): The runtime metadata sent from the RDMA traffic generator

    Returns:
        list: A list of tuples, each tuple contains the queue pair number and the packet
        sequence number of the sender and the receiver of a queue pair
    """
    msg = msg.strip('\0').strip("&")
    words = msg.split(";")

    if len(words) < 2:
        print("incomplete message %s" % (msg))
        return None

    verb = words[0]
    if '_' in verb:
        verb_a, verb_b = words[0].split('_')
        num_qps_verb_a, num_qps_verb_b = words[1].split('_')
        num_qps_verb_a = int(num_qps_verb_a)
        num_qps_verb_b = int(num_qps_verb_b)
        num_qps = num_qps_verb_a + num_qps_verb_b
        print("RDMA verbs: %s %s" % (verb_a, verb_b))
        print("Number of queue pairs: %d (%d for %s, %d for %s)" % \
              (num_qps, num_qps_verb_a, verb_a, num_qps_verb_b, verb_b))
    else:
        num_qps = int(words[1])
        print("RDMA verb: %s" % (verb))
        print("Number of queue pairs: %d" % (num_qps))

    if len(words) != 2 + 2 * num_qps:
        print("incomplete message %s" % (msg))
        return None

    qpn_psn_list = []
    for i in range(num_qps):
        qpn_snd = str_to_int(words[2*i + 2].split(",")[0])
        psn_snd = str_to_int(words[2*i + 2].split(",")[1])
        ip_snd  = words[2*i + 2].split(",")[2].split(":")[3]
        qpn_rcv = str_to_int(words[2*i + 3].split(",")[0])
        psn_rcv = str_to_int(words[2*i + 3].split(",")[1])
        ip_rcv  = words[2*i + 3].split(",")[2].split(":")[3]
        qpn_psn_list.append((qpn_snd, psn_snd, qpn_rcv, psn_rcv))
        print("Local QPN: %s, PSN: %s, IP: %s" % (hex(qpn_snd), hex(psn_snd), ip_snd))
        print("Remote QPN: %s, PSN: %s, IP: %s" % (hex(qpn_rcv), hex(psn_rcv), ip_rcv))

    return qpn_psn_list

def print_usage():
    """ Print the usage of the script """
    print("Usage: ")
    print(sys.argv[0] + " port_number")
    return

def main():
    """ The main function of the script

    Raises:
        Exception: If the number of arguments is not 2 or the port number is invalid
    """
    try:
        if len(sys.argv) != 2:
            raise Exception("Only one argument can be taken.")

        port = int(sys.argv[1])
        if port > 65535 or port < 0:
            raise Exception("Please input a valid port number.")
    except:
        print_usage()
        sys.exit(-1)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    print("Listening...")
    server.listen(5)
    conn, addr = server.accept()
    print("Accepted a connection request from %s:%s" % (addr[0], addr[1]))
    msg = ""
    while True:
        data = conn.recv(1024)
        msg = msg + data.decode()
        if '&' in msg:
            break

    qpn_psn_list = parse_data(msg)
    if qpn_psn_list:
        for i in range(len(qpn_psn_list)):
            print(qpn_psn_list[i])

    conn.sendall(msg.encode())
    conn.close()

if __name__ == "__main__":
    main()
