"""
    Dump the port counters and hw counters of RDMA NIC
    Refer to https://community.mellanox.com/s/article/understanding-mlx5-linux-counters-and-status-parameters
"""
import argparse, sys, os, subprocess

def dump_rdma_counters(dump_file, dir_name):
    file_names = [f for f in os.listdir(dir_name) if os.path.isfile(os.path.join(dir_name, f))]
    for file_name in file_names:
        counter_key = file_name
        with open(os.path.join(dir_name, file_name), 'r') as read_file:
            counter_value = read_file.readline().strip()
            dump_file.write("  %s: %s\n" % (counter_key, counter_value))

def dump_ethtool_counters(dump_file):
    command = "ethtool -S %s | grep -v 'NIC'" % (args.interface_name)
    result = subprocess.check_output(command, shell=True)
    if (sys.version_info > (3, 0)):
        result = result.decode()
    counter_list = result.strip('\n').split('\n')
    for counter in counter_list:
        counter = counter.strip(' ')
        dump_file.write("  %s\n" % counter)

def dump_mlnx(args):
    ib_dev = args.ib_dev
    ib_port = args.ib_port
    file_name = args.file_name
    with open(file_name, 'w') as dump_file:
        if os.path.exists("/sys/class/infiniband/%s/ports/%d/counters" % (ib_dev, ib_port)):
            dump_file.write("port-counters:\n")
            port_counter_dir_name = "/sys/class/infiniband/%s/ports/%d/counters" % (ib_dev, ib_port)
            dump_rdma_counters(dump_file, port_counter_dir_name)
        if os.path.exists("/sys/class/infiniband/%s/ports/%d/hw_counters" % (ib_dev, ib_port)):
            dump_file.write("hw-counters:\n")
            hw_counter_dir_name =  "/sys/class/infiniband/%s/ports/%d/hw_counters" % (ib_dev, ib_port)
            dump_rdma_counters(dump_file, hw_counter_dir_name)
        dump_file.write("ethtool-counters:\n")
        dump_ethtool_counters(dump_file)

def dump_intel(args):
    ib_dev = args.ib_dev
    ib_port = args.ib_port
    file_name = args.file_name
    with open(file_name, 'w') as dump_file:
        if os.path.exists("/sys/class/infiniband/%s/ports/%d/hw_counters" % (ib_dev, ib_port)):
            dump_file.write("hw-counters:\n")
            hw_counter_dir_name =  "/sys/class/infiniband/%s/ports/%d/hw_counters" % (ib_dev, ib_port)
            dump_rdma_counters(dump_file, hw_counter_dir_name)
        dump_file.write("ethtool-counters:\n")
        dump_ethtool_counters(dump_file)

def main(args):
    if args.vendor == "MLNX":
        dump_mlnx(args)
    elif args.vendor == "Intel":
        dump_intel(args)
    else:
        raise ValueError("Unsupported vendor %s. Available vendors: [\"MLNX\", \"Intel\"]." % args.vendor)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'Dump the port counters and hw counters of RDMA NIC')
    parser.add_argument('-f', '--file_name', type=str, help='The file to dump the results', required=True)
    parser.add_argument('-d', '--ib_dev', type=str, help='The target IB device', required=True)
    parser.add_argument('-i', '--ib_port', type=int, help='The target port of IB device', required=True)
    parser.add_argument('-n', '--interface_name', type=str, help='The target interface name', required=True)
    list_of_vendors = ["MLNX", "Intel"]
    parser.add_argument('-v', '--vendor', type=str, help='Vendor of the target NIC', required=True, choices=list_of_vendors)
    args = parser.parse_args()
    main(args)
