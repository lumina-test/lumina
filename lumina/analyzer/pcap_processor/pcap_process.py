import dpkt, sys, logging, time
import lumina.analyzer.packet_parser.roce_packet as roce_packet

class PcapWriter(dpkt.pcap.Writer):
    """ Override the writepkt method to support original packet length (different from cap_len) """
    def writepkt(self, pkt, ts=None, orig_len=None):
        if ts is None:
            ts = time.time()
        s = bytes(pkt)
        n = len(s)
        sec = int(ts)
        usec = int(round(ts % 1 * 10 ** self._precision))
        if orig_len == None:
            orig_len = n
        if sys.byteorder == 'little':
            ph = dpkt.pcap.LEPktHdr(tv_sec=sec,
                                    tv_usec=usec,
                                    caplen=n,
                                    len=orig_len)
        else:
            ph = dpkt.pcap.PktHdr(tv_sec=sec,
                                  tv_usec=usec,
                                  caplen=n,
                                  len=orig_len)
        self._Writer__f.write(bytes(ph))
        self._Writer__f.write(s)

def dump_pkts_to_pcap(output_filename, packet_list):
    """ Dump the list of packets to a pcap file

    Args:
        output_filename (str): The output pcap file name
        packet_list (list): The list of packets to dump

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(output_filename, 'wb') as file_dump:
            writer = PcapWriter(file_dump)
            for ppacket in packet_list:
                writer.writepkt(ppacket.get_buffer(), ppacket.get_switch_timestamp(), ppacket.get_orig_len())

    except IOError:
        logging.error("Failed to open pcap file %s. Please check your filename." % output_filename)
        return False

    except:
        logging.error("Failed to dump packets to pcap file.")
        return False

    logging.info("Successfully dumped %d packets to %s." % (len(packet_list), output_filename))
    return True

def merge_pcaps(pcap_file_list):
    """ Merge a list of pcap files into a single list of packets and sort them by switch sequence number

    Args:
        pcap_file_list (list): The list of pcap files to merge

    Returns:
        list: The list of packets sorted by switch sequence number if successful, None otherwise
    """
    packet_list = []

    try:
        for pcap_path in pcap_file_list:
            packet_list = packet_list + get_packet_list(pcap_path)
    except:
        logging.error("Failed to merge pcap files %s." % pcap_file_list)
        return None

    packet_list.sort(key=lambda x:x.get_switch_seqnum())
    return packet_list

def get_packet_list(pcap_file):
    """ Read a pcap file and return a list of packets

    Args:
        pcap_file (str): The pcap file to read

    Returns:
        list: The list of packets if successful, empty list otherwise

    Raises:
        IOError: If the pcap file cannot be opened for reading
        Exception: If the pcap file cannot be read
    """
    packet_list = []
    try:
        with open(pcap_file, 'rb') as file_read:
            pcap = dpkt.pcap.Reader(file_read)
            for packet in pcap:
                packet_list.append(roce_packet.RRoCEPacket(packet))
    except IOError:
        logging.error("Unable to open pcap file %s. Please check your filename." % pcap_file)
        raise IOError

    except:
        logging.error("Failed to read pcap file %s." % pcap_file)
        raise Exception

    logging.info("Successfully read %d packets from %s." % (len(packet_list), pcap_file))
    return packet_list
