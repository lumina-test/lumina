import importlib, time, sys, six, datetime, socket
from pal_rpc.ttypes import *
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.protocol import TMultiplexedProtocol

def wait_for_switchd_ready(dev_ids, host='localhost', port=7777, timeout=300):
    """ Wait for the bf_switchd to be ready

    Args:
        dev_ids (list): Device IDs to query
        host (str): Host to query, default is localhost
        port (int): Port number bf_switchd is listening on, default is 7777
        timeout (int): Timeout (in seconds) before giving up

    Returns:
        True if all devices are ready, False otherwise
    """
    s = None
    start_time = datetime.datetime.now()
    timeout_time = start_time + datetime.timedelta(seconds=timeout)
    is_timeout = timeout_time <= datetime.datetime.now()

    six.print_("Connecting to", host, "port", port, "to check status on these devices:", dev_ids)

    last_dev_id = None
    while len(dev_ids) and not is_timeout:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect( (host, port) )
            s.settimeout(1)
            dev_id = dev_ids[0]
            if last_dev_id != dev_id:
                last_dev_id = dev_id
                six.print_("Waiting for device", dev_id, "to be ready")
            s.sendall(str(dev_id).encode())
            r = s.recv(1)
            s.close()
            s = None
            if r.decode() == '1':
                dev_ids.remove(dev_id)
            else:
                time.sleep(1)
        except:
            if s:
                s.close()
                s = None
            time.sleep(1)
        is_timeout = timeout_time <= datetime.datetime.now()
    if len(dev_ids):
        six.print_("Timeout or error while waiting for devices to be ready")
        return False
    return True

def add_ports(dev_id, port_list, bf_speed, bf_fec, thrift_server, thrift_port = 9090):
    """ Add and enable the ports

    Args:
        dev_id (int): Device ID
        port_list (list): The list of ports to add and enable
        bf_speed (int): Port speed
        bf_fec (int): Port fec type
        thrift_server (str): Thrift server IP address
        thrift_port (int): Thrift server Port (default: 9090)

    Returns:
        True if all ports are up, False otherwise
    """
    transport = TSocket.TSocket(thrift_server, thrift_port)
    transport = TTransport.TBufferedTransport(transport)
    bprotocol = TBinaryProtocol.TBinaryProtocol(transport)
    try:
        pal_client_module = importlib.import_module(".".join(["pal_rpc", "pal"]))
    except:
        pal_client_module = None

    if pal_client_module:
        pal_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "pal")
    else:
        pal_protocol = None
    if pal_client_module:
        pal = pal_client_module.Client(pal_protocol)
    else:
        pal = None

    transport.open()

    for p in port_list:
        pal.pal_port_add(dev_id, p, bf_speed, bf_fec)
    pal.pal_port_enable_all(dev_id)
    ports_not_up = True
    print("Waiting for ports to come up...")
    num_tries = 12
    i = 0
    while ports_not_up:
        ports_not_up = False
        for p in port_list:
            x = pal.pal_port_oper_status_get(dev_id, p)
            if x == pal_oper_status_t.BF_PORT_DOWN:
                ports_not_up = True
                print("  port " + str(p) + " is down")
                sys.stdout.flush()
                time.sleep(3)
                break
        i = i + 1
        if i >= num_tries:
            break
    if ports_not_up == True:
        print("Ports not up.")
    else:
        print("All ports up.")
    transport.close()
    return not ports_not_up
