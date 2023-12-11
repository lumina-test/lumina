#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <pcap/pcap.h>

#include <rte_eal.h>
#include <rte_ethdev.h>

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 1024

#define NUM_MBUFS 16383
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 64

#define SEC_TO_NSEC 1000000000

#define ROCE_UDP_DST_PORT 4791

#define RSS_HASH_KEY_LENGTH 40

static uint8_t rss_key[RSS_HASH_KEY_LENGTH] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = rss_key,
            .rss_key_len = sizeof(rss_key),
            .rss_hf = ETH_RSS_NONFRAG_IPV4_UDP,
        }
    }
};

#define EVENT_TYPE_ECN 2

// DPDK port to receive packets
static uint16_t rx_port = 0;
static char *dump_file_name = "mirror-roce-pkts.pcap";
static uint16_t filter_udp_dst_port = ROCE_UDP_DST_PORT;
// Max lengh of per-packet snapshot
static uint16_t snap_len = 128;
// Max # of packets to dump. Optimal size is (2^q - 1)
static uint32_t max_nb_pkts = 16383;
// Packets to dump
struct rte_mbuf ***dump_pkts = NULL;

// If the program is receiving packets
static volatile int keep_receiving = 1;

static struct rte_mempool *rx_mbuf_pool;

// Statistics
static volatile uint32_t nb_rx_pkts[RTE_MAX_LCORE] = {0};
static volatile uint32_t nb_dump_pkts[RTE_MAX_LCORE] = {0};

// Print usage of the program
static void usage(const char *prgname);
// Parse program arguments
static int parse_args(int argc, char **argv);
// Parse devie port
static int parse_port(char *arg);
// Parse UDP destination port
static int parse_udp_dst_port(char *arg);
// Parse snapshot length
static int parse_snap_len(char *arg);
// Parse max # of packets to dump
static int parse_max_nb_pkts(char *arg);
// Print program configuration
static void print_config();
// Print I/O statistics of an Ethernet device
static void print_stats(struct rte_eth_stats *eth_stats);
// Initialize a DPDK port
static int port_init(uint16_t port,
                     struct rte_mempool *mbuf_pool,
                     uint16_t nb_tx_rings,
                     uint16_t nb_rx_rings,
                     uint16_t tx_ring_size,
                     uint16_t rx_ring_size);
// Main thread function
static int32_t lcore_main();
// Handle signal and stop receiving
static void stop_receiving(int sig);
// Return if the packet is a RoCEv2 packet.
// If yes, recover its modified fields and return its original length in orig_len
static bool is_roce_pkt(struct rte_mbuf *mb, uint16_t udp_dst_port, uint16_t *orig_len);
// Get hardware timestamp attached by the switch ASIC
static uint64_t get_hw_tstamp(struct rte_mbuf *mb);
// Dump packet trace to file
static void dump_to_file();

int main(int argc, char **argv)
{
    // Initialize Environment Abstraction Layer (EAL)
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    }

    argc -= ret;
    argv += ret;

    // Parse application arguments
    ret = parse_args(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Invalid parameters\n");
    }

    print_config();

    unsigned int lcore_count = rte_lcore_count();
    rx_mbuf_pool = rte_pktmbuf_pool_create("RX_MBUF_POOL",
                                            lcore_count * NUM_MBUFS,
                                            MBUF_CACHE_SIZE,
                                            0,
                                            RTE_MBUF_DEFAULT_BUF_SIZE,
                                            rte_socket_id());
    if (!rx_mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Cannot create rx_mbuf_pool\n");
    }

    struct rte_mempool *dump_mbuf_pool = rte_pktmbuf_pool_create("DUMP_MBUF_POOL",
                                                                 lcore_count * max_nb_pkts,
                                                                 MBUF_CACHE_SIZE,
                                                                 0,
                                                                 snap_len + RTE_PKTMBUF_HEADROOM,
                                                                 rte_socket_id());

    if (!dump_mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Cannot create dump_mbuf_pool\n");
    }

    if (port_init(rx_port, rx_mbuf_pool, 0, lcore_count, 0, RX_RING_SIZE) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", rx_port);
    }

    dump_pkts = (struct rte_mbuf***)malloc(lcore_count * sizeof(struct rte_mbuf **));
    if (!dump_pkts) {
        rte_exit(EXIT_FAILURE, "Fail to allocate dump_pkts\n");
    }

    for (unsigned int i = 0; i < lcore_count; i++) {
        dump_pkts[i] = (struct rte_mbuf**)malloc(max_nb_pkts * sizeof(struct rte_mbuf*));
        if (!dump_pkts[i]) {
            rte_exit(EXIT_FAILURE, "Fail to allocate dump_pkts for lcore %u\n", i);
        }
    }

    for (unsigned int i = 0; i < lcore_count; i++) {
        ret = rte_pktmbuf_alloc_bulk(dump_mbuf_pool, dump_pkts[i], max_nb_pkts);
        if (ret != 0) {
            rte_exit(EXIT_FAILURE, "Fail to allocate %u mbufs for lcore %u in dump_mbuf_pool\n", max_nb_pkts, i);
        }
    }

    signal(SIGTERM, stop_receiving);
    signal(SIGINT, stop_receiving);
    keep_receiving = 1;

    rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MAIN);
    rte_eal_mp_wait_lcore();

    dump_to_file();

    struct rte_eth_stats eth_stats;
    if (rte_eth_stats_get(rx_port, &eth_stats) != 0) {
        rte_exit(EXIT_FAILURE, "Fail to get I/O statistics\n");
    }
    print_stats(&eth_stats);

    rte_eal_cleanup();
    return 0;
}

static void usage(const char *prgname)
{
    printf("%s [EAL options] -- [--port PORT] [--udp-dst-port UDP_PORT] [--file FILE]\n"
           "[--snap-len SNAP_LEN] [--num-pkts NB_PKTS]\n\n"
           "    --port          PORT: RX port to capture packets (default %hu)\n"
           "    --udp-dst-port  UDP_PORT: UDP destination port of mirrored RoCE packet (default %hu)\n"
           "    --file          FILE: name of file to store packets (default %s)\n"
           "    --snap-len      SNAP_LEN: maximum lengh of packet snapshot (default %hu)\n"
           "    --num-pkts      NB_PKTS: maximum number of packets to dump (default %u)\n",
           prgname, rx_port, filter_udp_dst_port, dump_file_name, snap_len, max_nb_pkts);
}

static struct option long_options[] = {
    {"port",        required_argument,  0,  'p'},
    {"udp-dst-port",required_argument,  0,  'u'},
    {"file",        required_argument,  0,  'f'},
    {"snap-len",    required_argument,  0,  's'},
    {"num-pkts",    required_argument,  0,  'n'},
    {0,             0,                  0,  0}
};

static int parse_args(int argc, char **argv)
{
    char *prgname = argv[0];
    const char short_options[] = "p:u:f:s:n:";
    char c;
    int ret;

    while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != EOF) {
        switch (c) {
            case 'p':
                ret = parse_port(optarg);
                if (ret < 0) {
                    return -1;
                }
                break;

            case 'u':
                ret = parse_udp_dst_port(optarg);
                if (ret < 0) {
                    return -1;
                }
                break;

            case 'f':
                dump_file_name = optarg;
                break;

            case 's':
                ret = parse_snap_len(optarg);
                if (ret < 0) {
                    return -1;
                }
                break;

            case 'n':
                ret = parse_max_nb_pkts(optarg);
                if (ret < 0) {
                    return -1;
                }
                break;

            default:
                usage(prgname);
                return -1;
        }
    }

    if (optind >= 0) {
        argv[optind-1] = prgname;
    }

    // reset getopt lib
    optind = 1;
    return 0;
}

static int parse_port(char *arg)
{
    long n;
    char **endptr;

    n = strtol(arg, endptr, 10);
    if (n < 0) {
        fprintf(stderr, "PORT should be a non-negative integer argument\n");
        return -1;
    }

    rx_port = (uint16_t)n;
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (rx_port >= nb_ports) {
        fprintf(stderr, "PORT should be smaller than %hu (# of available ports)\n", nb_ports);
        return -1;
    }

    return 0;
}

static int parse_udp_dst_port(char *arg)
{
    long n;
    char **endptr;

    n = strtol(arg, endptr, 10);
    #define MIN_UDP_PORT 1
    #define MAX_UDP_PORT 65535

    if (n < MIN_UDP_PORT || n > MAX_UDP_PORT) {
        fprintf(stderr, "UDP_PORT should be in [%d, %d]\n", MIN_UDP_PORT, MAX_UDP_PORT);
        return -1;
    }

    filter_udp_dst_port = n;
    return 0;
}

static int parse_snap_len(char *arg)
{
    long n;
    char **endptr;

    n = strtol(arg, endptr, 10);
    if (n <= 0) {
        fprintf(stderr, "SNAP_LEN should be a positive integer argument\n");
        return -1;
    }

    snap_len = n;
    return 0;
}

static int parse_max_nb_pkts(char *arg)
{
    long n;
    char **endptr;

    n = strtol(arg, endptr, 10);
    if (n <= 0) {
        fprintf(stderr, "NB_PKTS should be a positive integer argument\n");
        return -1;
    }

    if ((n & (n+1)) != 0) {
        fprintf(stderr, "NB_PKTS should be 2^n-1 (n>=1)\n");
        return -1;
    }

    max_nb_pkts = n;
    return 0;
}

static void print_config()
{
    printf("NB_LCORES： %u\n",  rte_lcore_count());
    printf("PORT:       %hu\n", rx_port);
    printf("UDP_PORT:   %hu\n", filter_udp_dst_port);
    printf("FILE:       %s\n",  dump_file_name);
    printf("SNAP_LEN:   %hu\n", snap_len);
    printf("NB_PKTS:    %u\n",  max_nb_pkts);
}

static void print_stats(struct rte_eth_stats *eth_stats)
{
    printf("Rx pkts:     %"PRIu64"\n", eth_stats->ipackets);
    printf("Tx pkts:     %"PRIu64"\n", eth_stats->opackets);
    printf("Rx missed:   %"PRIu64"\n", eth_stats->imissed);
    printf("Rx errors:   %"PRIu64"\n", eth_stats->ierrors);
    printf("Tx errors:   %"PRIu64"\n", eth_stats->oerrors);
    printf("Mbuf errors: %"PRIu64"\n", eth_stats->rx_nombuf);
}

// Initialzie a port. Return 0 on success.
//  port: ID of the port to initialize
//  mbuf_pool: packet buffer pool for RX packets
//  nb_tx_rings: number of TX rings
//  nb_rx_rings: number of RX rings
//  tx_ring_size: number of descriptors to allocate for the TX ring
//  rx_ring_size: number of descriptors to allocate for the RX ring
static int port_init(uint16_t port,
                     struct rte_mempool *mbuf_pool,
                     uint16_t nb_tx_rings,
                     uint16_t nb_rx_rings,
                     uint16_t tx_ring_size,
                     uint16_t rx_ring_size)
{
    struct rte_eth_conf port_conf = port_conf_default;
    uint16_t nb_txd = tx_ring_size;
    uint16_t nb_rxd = rx_ring_size;
    int retval;
    struct rte_eth_dev_info dev_info;

    printf("Init port %hu\n", port);

    if (!rte_eth_dev_is_valid_port(port)) {
        return -1;
    }

    // Get device information
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        fprintf(stderr, "Error during getting device (port %u) info: %s\n", port, strerror(-retval));
        return retval;
    }
    printf("PCI address: %s\n", dev_info.device->name);

    // Configure RSS
    port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
    if (port_conf.rx_adv_conf.rss_conf.rss_hf !=
        port_conf_default.rx_adv_conf.rss_conf.rss_hf) {
            printf("Port %u modifies RSS hash function based on hardware support,"
                   "requested:%#"PRIx64" configured:%#"PRIx64"\n",
                   port,
                   port_conf_default.rx_adv_conf.rss_conf.rss_hf,
                   port_conf.rx_adv_conf.rss_conf.rss_hf);
    }

    // Configure the Ethernet device
    retval = rte_eth_dev_configure(port, nb_rx_rings, nb_tx_rings, &port_conf);
    if (retval != 0) {
        fprintf(stderr, "Error during rte_eth_dev_configure\n");
        return retval;
    }

    // Adjust # of descriptors for each TX/RX ring
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) {
        fprintf(stderr, "Error during rte_eth_dev_adjust_nb_rx_tx_desc\n");
        return retval;
    }

    int socket_id = rte_eth_dev_socket_id(port);
    //printf("Socket ID = %d\n", socket_id);

    // TX setup
    for (uint16_t q = 0; q < nb_tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd, socket_id, NULL);
        if (retval < 0) {
            fprintf(stderr, "Error during rte_eth_tx_queue_setup for queue %hu\n", q);
            return retval;
        }
    }
    printf("Set up %hu TX rings (%hu descriptors per ring)\n", nb_tx_rings, nb_txd);

    // RX setup
    for (uint16_t q = 0; q < nb_rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd, socket_id, NULL, mbuf_pool);
        if (retval < 0) {
            fprintf(stderr, "Error during rte_eth_rx_queue_setup for queue %hu\n", q);
            return retval;
        }
    }
    printf("Set up %hu RX rings (%hu descriptors per ring)\n", nb_rx_rings, nb_rxd);

    // Reset the general I/O statistics
    rte_eth_stats_reset(port);

    // Start the Ethernet port.
    retval = rte_eth_dev_start(port);
    if (retval < 0) {
        fprintf(stderr, "Error during rte_eth_dev_start\n");
        return retval;
    }

    // Display the port MAC address
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0) {
        fprintf(stderr, "Error during rte_eth_macaddr_get\n");
        return retval;
    }
    printf("Port %hu MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
           port, addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
           addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5]);

    // Enable RX in promiscuous mode for the Ethernet device.
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0) {
        fprintf(stderr, "Error during rte_eth_promiscuous_enable\n");
        return retval;
    }

    return 0;
}

static void stop_receiving(int sig)
{
    keep_receiving = 0;
}

static bool is_roce_pkt(struct rte_mbuf *mb, uint16_t udp_dst_port, uint16_t *orig_len)
{
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mb, struct rte_ether_hdr *);
    uint16_t ether_type = eth_hdr->ether_type;

    if (ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        return false;
    }

    size_t ipv4_hdr_offset = sizeof(struct rte_ether_hdr);
    struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(mb,
                                                            struct rte_ipv4_hdr*,
                                                            ipv4_hdr_offset);
    uint8_t l4_proto = ipv4_hdr->next_proto_id;
    if (l4_proto != IPPROTO_UDP) {
        return false;
    }

    size_t udp_hdr_offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
    struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(mb,
                                                          struct rte_udp_hdr*,
                                                          udp_hdr_offset);
    if (rte_be_to_cpu_16(udp_hdr->dst_port) != udp_dst_port) {
        return false;
    }

    // If this packet is supposed to be marked by the switch
    if (ipv4_hdr->time_to_live == EVENT_TYPE_ECN) {
        uint8_t dscp = ipv4_hdr->type_of_service & 0xfc;
        uint8_t ecn = ipv4_hdr->type_of_service & 0x03;

        if (ecn == 0) {
            fprintf(stderr, "The Non-ECT packet cannot be marked\n");
        }
        // ECN-capable transport
        if (ecn == 1 || ecn == 2) {
            ecn = 3;
        }
        ipv4_hdr->type_of_service = dscp + ecn;
    }

    *orig_len = rte_be_to_cpu_16(ipv4_hdr->total_length) + RTE_ETHER_HDR_LEN;
    udp_hdr->src_port = udp_hdr->dgram_cksum;
    udp_hdr->dst_port = rte_be_to_cpu_16(ROCE_UDP_DST_PORT);

    // Fix IP and UDP checksum
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);
    return true;
}

static uint64_t get_hw_tstamp(struct rte_mbuf *mb)
{
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mb, struct rte_ether_hdr *);
    struct rte_ether_addr dst_addr = eth_hdr->d_addr;
    uint64_t tstamp = 0;

    for (unsigned int i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
        tstamp = (tstamp << 8) + dst_addr.addr_bytes[i];
    }

    return tstamp;
}

static void dump_to_file()
{
    // Dump packet trace to file
    uint32_t nb_dump_roce_pkts = 0;

    pcap_t *pd = pcap_open_dead_with_tstamp_precision(DLT_EN10MB, 65535, PCAP_TSTAMP_PRECISION_NANO);
    if (!pd) {
        fprintf(stderr, "Fail to set nanosecond timestamp\n");
        return;
    }

    pcap_dumper_t *pdumper = pcap_dump_open(pd, dump_file_name);
    if (!pdumper) {
        fprintf(stderr, "Fail to open %s\n", dump_file_name);
        return;
    }

    unsigned int lcore_count = rte_lcore_count();
    struct pcap_pkthdr pkt_hdr;
    uint16_t orig_len;

    for (unsigned int lcore_index = 0; lcore_index < lcore_count; lcore_index ++) {
        printf("Lcore index %u: receive %u packets and dump %u packets\n",
                lcore_index, nb_rx_pkts[lcore_index], nb_dump_pkts[lcore_index]);
        for (uint16_t i = 0; i < nb_dump_pkts[lcore_index]; i++) {
            if (is_roce_pkt(dump_pkts[lcore_index][i], filter_udp_dst_port, &orig_len)) {
                uint64_t tstamp_ns = get_hw_tstamp(dump_pkts[lcore_index][i]);
                pkt_hdr.ts.tv_sec = tstamp_ns / SEC_TO_NSEC;
                // Use usec field to store nanosecond
                pkt_hdr.ts.tv_usec = tstamp_ns % SEC_TO_NSEC;
                pkt_hdr.caplen = rte_pktmbuf_pkt_len(dump_pkts[lcore_index][i]);
                pkt_hdr.len = orig_len;
                pcap_dump((u_char*)pdumper, &pkt_hdr, rte_pktmbuf_mtod(dump_pkts[lcore_index][i], u_char*));
                nb_dump_roce_pkts++;
            }
            rte_pktmbuf_free(dump_pkts[lcore_index][i]);
        }
        free(dump_pkts[lcore_index]);
    }
    free(dump_pkts);
    pcap_close(pd);
    pcap_dump_close(pdumper);
    printf("Dump %u RoCE packets to %s\n", nb_dump_roce_pkts, dump_file_name);
}

static int32_t lcore_main()
{
    unsigned int lcore_id = rte_lcore_id();
    uint32_t lcore_index = rte_lcore_index(lcore_id);
    printf("lcore ID %u Index %u\n", lcore_id, lcore_index);

    nb_dump_pkts[lcore_index] = 0;
    nb_rx_pkts[lcore_index] = 0;
    uint32_t cur_nb_dump_pkts = 0;
    struct rte_mbuf *rx_mbufs[BURST_SIZE];

    while (keep_receiving) {
        uint16_t nb_rx = rte_eth_rx_burst(rx_port, lcore_index, rx_mbufs, BURST_SIZE);
        if (nb_rx == 0) {
            continue;
        }

        for (uint16_t i = 0; i < nb_rx; i++) {
            nb_rx_pkts[lcore_index]++;
            if (unlikely(nb_dump_pkts[lcore_index] >= max_nb_pkts)) {
                continue;
            }

            const void *src = rte_pktmbuf_mtod(rx_mbufs[i], void*);
            void *dst = rte_pktmbuf_mtod(dump_pkts[lcore_index][cur_nb_dump_pkts], void*);
            size_t copy_len = RTE_MIN(rx_mbufs[i]->data_len, snap_len);

            rte_memcpy(dst, src, copy_len);
            dump_pkts[lcore_index][cur_nb_dump_pkts]->data_len = copy_len;
            dump_pkts[lcore_index][cur_nb_dump_pkts]->pkt_len = copy_len;

            rte_pktmbuf_free(rx_mbufs[i]);
            cur_nb_dump_pkts++;
        }
        nb_dump_pkts[lcore_index] = cur_nb_dump_pkts;
    }

    printf("Stop receiving packets\n");
    sleep(1);
}
