#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include "common.h"

static void print_usage(char *app);
static bool parse_args(int argc, char **argv);
// Send iters to the server
static bool send_iters(int sockfd);

static uint16_t server_port     = DEFAULT_SERVER_PORT;
static char *ib_dev_name        = NULL;
static int ib_port              = DEFAULT_IB_PORT;
static unsigned int msg_size    = DEFAULT_MSG_SIZE;
static unsigned int iters       = DEFAULT_ITERS;
static unsigned int num_qps     = DEFAULT_NUM_QPS;
static unsigned int tx_depth    = DEFAULT_TX_DEPTH;
static uint8_t qp_timeout       = DEFAULT_QP_TIMEOUT;
static uint8_t qp_retry_cnt     = DEFAULT_QP_RETRY_CNT;
static uint16_t mtu             = DEFAULT_MTU;
static uint8_t *dscp_values     = NULL;
static size_t num_dscp_values   = 0;

static bool inline_msg          = false;
static bool use_event           = false;
static bool validate_buf        = false;
static bool use_multi_gid       = false;
static bool barrier_sync        = false;
static char *server_ip          = NULL;
static char *controller_ip      = NULL;
static uint16_t controller_port = DEFAULT_CONTROLLER_PORT;

int main(int argc, char **argv)
{
    int server_sockfd = -1;

    if (!parse_args(argc, argv)) {
        goto err;
    }

    struct dev_context device = {
        .ib_dev_name = ib_dev_name,
        .dev_port = ib_port,
        .ctx = NULL,
        .channel = NULL,
        .pd = NULL,
        .cq = NULL,
        .use_event = use_event,
        .user_mtu= mtu
    };

    if (!init_dev_ctx(&device)) {
        fprintf(stderr, "Fail to initialize device context\n");
        goto err;
    }
    print_dev_ctx(&device);

    unsigned int tx_depth_limit = (unsigned int)(device.dev_attr.max_qp_wr) / 4;
    if (tx_depth > tx_depth_limit) {
        fprintf(stderr, "TX depth %u > limit %u\n", tx_depth, tx_depth_limit);
        goto destroy_device;
    }

    printf("Initialize %u queue pairs\n", num_qps);
    unsigned int num_qps_init = 0;
    struct conn_context *connections = (struct conn_context*)malloc(num_qps * sizeof(struct conn_context));
    if (!connections) {
        goto destroy_device;
    }

    for (unsigned int i = 0; i < num_qps; i++) {
        connections[i].id = i;
        connections[i].dev_ctx = &device;
        connections[i].qp = NULL;
        connections[i].data_mr = NULL;
        connections[i].data_buf = NULL;
        connections[i].data_buf_size = msg_size;
        connections[i].validate_buf = validate_buf;
        connections[i].inline_msg = inline_msg;
        connections[i].use_multi_gid = use_multi_gid;
        connections[i].timeout = qp_timeout;
        connections[i].retry_cnt = qp_retry_cnt;
        connections[i].max_rd_atomic = 1;
        connections[i].max_dest_rd_atomic = 1;
        connections[i].dscp = dscp_values? dscp_values[i] : DEFAULT_DSCP;

        if (!init_conn_ctx(&connections[i])) {
            fprintf(stderr, "Fail to initialize connection %u\n", i);
            goto destroy_connections;
        }

        num_qps_init++;
        print_conn_ctx(&connections[i]);
    }

    // Build a TCP connection to the server
    server_sockfd = connect_socket(server_ip, server_port);
    if (server_sockfd < 0) {
        fprintf(stderr, "Fail to connect to the server\n");
        goto destroy_connections;
    }

    // Exchange metadata with server
    if (!exchange_metadata_with_server(server_sockfd, connections, num_qps, false)) {
        fprintf(stderr, "Fail to exchange RDMA metadata with the server\n");
        goto destroy_socket;
    }
    printf("Exchange RDMA metadata with the server\n");

    // Send iters to the server
    if (!send_iters(server_sockfd)) {
        fprintf(stderr, "Fail to send iters to the server\n");
        goto destroy_socket;
    }
    printf("Send iters to the server\n");

    // Wait for ready message from server
    if (!wait_ready(server_sockfd)) {
        fprintf(stderr, "Fail to get ready message from the server\n");
        goto destroy_socket;
    }
    printf("The server is ready\n");
    close(server_sockfd);

    if (controller_ip &&
        !notify_controller(controller_ip, controller_port, connections, num_qps, SEND_VERB)) {
        fprintf(stderr, "Fail to notify the controller\n");
    }

    if (barrier_sync) {
        if (!gen_req_barrier_sync_traffic(SEND_VERB, connections, num_qps, iters, use_event)) {
            fprintf(stderr, "Fail to generate barrier synchronized traffic\n");
            goto destroy_connections;
        }
    } else if (!gen_req_traffic(SEND_VERB, connections, num_qps, iters, tx_depth, use_event)) {
        fprintf(stderr, "Fail to generate traffic\n");
        goto destroy_connections;
    }

    printf("Experiment completes\n");
    for (unsigned int i = 0; i < num_qps; i++) {
        destroy_conn_ctx(&connections[i]);
    }

    free(connections);
    destroy_dev_ctx(&device);
    free(dscp_values);

    return EXIT_SUCCESS;

destroy_socket:
    close(server_sockfd);

destroy_connections:
    for (unsigned int i = 0; i < num_qps_init; i++) {
        destroy_conn_ctx(&connections[i]);
    }
    free(connections);

destroy_device:
    destroy_dev_ctx(&device);

err:
    free(dscp_values);
    return EXIT_FAILURE;
}

/*
 * Print the usage of the application
 * @param app: the name of the application
 * @return: void
 */
static void print_usage(char *app)
{
    if (!app) {
        return;
    }

    fprintf(stderr, "Usage: %s [options] host\n", app);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --port=<port>            listen on/connect to port <port> (default %d)\n", DEFAULT_SERVER_PORT);
    fprintf(stderr, "  -d, --ib-dev=<dev>           use IB device <dev>\n");
    fprintf(stderr, "  -i, --ib-port=<port>         use port <port> of IB device (default %d)\n", DEFAULT_IB_PORT);
    fprintf(stderr, "  -C, --controller=<ip>        IP address of the controller\n");
    fprintf(stderr, "  -P, --controller-port=<port> connect to port <port> of controller (default %d)\n", DEFAULT_CONTROLLER_PORT);
    fprintf(stderr, "  -s, --size=<size>            size of message to exchange (default %d)\n", DEFAULT_MSG_SIZE);
    fprintf(stderr, "  -n, --iters=<iters>          number of exchanges per queue pair (default %d)\n", DEFAULT_ITERS);
    fprintf(stderr, "  -q, --qp=<num of qp's>       number of queue pairs (default %d)\n", DEFAULT_NUM_QPS);
    fprintf(stderr, "  -t  --tx-depth=<dep>         size of tx queue of each queue pair (default %d)\n", DEFAULT_TX_DEPTH);
    fprintf(stderr, "  -u, --qp-timeout=<timeout>   QP timeout value is 4usec * (2^timeout) (default %hhu)\n", DEFAULT_QP_TIMEOUT);
    fprintf(stderr, "  -R, --qp-retry-cnt=<cnt>     QP retry count (default %hhu)\n", DEFAULT_QP_RETRY_CNT);
    fprintf(stderr, "  -M, --mtu=<mtu>              MTU size: 256 - 4096  (default %hu)\n", DEFAULT_MTU);
    fprintf(stderr, "  -D, --dscp=<DSCP list>       list of per-QP DSCP values. Format: <d1>[-d2][,d3[-d4],...]\n");
    fprintf(stderr, "  -l, --inline                 inline message with the work request\n");
    fprintf(stderr, "  -e, --events                 sleep on CQ events\n");
    fprintf(stderr, "  -c, --chk                    validate received buffer\n");
    fprintf(stderr, "  -m, --multi-gid              use multiple GIDs associated with the IB interface\n");
    fprintf(stderr, "  -b, --barrier                barrier synchronization among QPs\n");
    fprintf(stderr, "  -h, --help                   show this help screen\n");
}

/*
 * Parse command line arguments
 * @param argc number of arguments
 * @param argv array of arguments
 * @return true if success, false otherwise
 */
static bool parse_args(int argc, char **argv)
{
    while (1) {
        static struct option long_options[] = {
            { .name = "port",            .has_arg = 1, .val = 'p' },
            { .name = "ib-dev",          .has_arg = 1, .val = 'd' },
            { .name = "ib-port",         .has_arg = 1, .val = 'i' },
            { .name = "controller",      .has_arg = 1, .val = 'C' },
            { .name = "controller-port", .has_arg = 1, .val = 'P' },
            { .name = "size",            .has_arg = 1, .val = 's' },
            { .name = "iters",           .has_arg = 1, .val = 'n' },
            { .name = "qps",             .has_arg = 1, .val = 'q' },
            { .name = "tx-depth",        .has_arg = 1, .val = 't' },
            { .name = "timeout",         .has_arg = 1, .val = 'u' },
            { .name = "retry-cnt",       .has_arg = 1, .val = 'R' },
            { .name = "mtu",             .has_arg = 1, .val = 'M' },
            { .name = "dscp",            .has_arg = 1, .val = 'D' },
            { .name = "inline",          .has_arg = 0, .val = 'l' },
            { .name = "events",          .has_arg = 0, .val = 'e' },
            { .name = "chk",             .has_arg = 0, .val = 'c' },
            { .name = "multi-gid",       .has_arg = 0, .val = 'm' },
            { .name = "barrier",         .has_arg = 0, .val = 'b' },
            { .name = "help",            .has_arg = 0, .val = 'h' },
            {}
        };

        int c = getopt_long(argc, argv, "p:d:i:C:P:s:n:q:t:u:R:M:D:lecmbh", long_options, NULL);

        //printf("%d\n", c);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'p':
                server_port = (uint16_t)strtoul(optarg, NULL, 0);
                break;

            case 'd':
                ib_dev_name = optarg;
                break;

            case 'i':
                ib_port = (int)strtol(optarg, NULL, 0);
                if (ib_port < 1) {
                    print_usage(argv[0]);
                    return false;
                }
                break;

            case 's':
                msg_size = (unsigned int)strtoul(optarg, NULL, 0);
                if (msg_size < 1) {
                    fprintf(stderr, "Invalid message size (%u)\n", msg_size);
                    print_usage(argv[0]);
                    return false;
                }
                break;

            case 'C':
                controller_ip = optarg;
                break;

            case 'P':
                controller_port = (uint16_t)strtoul(optarg, NULL, 0);
                break;

            case 'n':
			    iters = (unsigned int)strtoul(optarg, NULL, 0);
			    break;

            case 'q':
                num_qps = (unsigned int)strtoul(optarg, NULL, 0);
                if (num_qps < 1) {
                    fprintf(stderr, "Invalid number of QPs (%u)\n", num_qps);
                    print_usage(argv[0]);
                    return false;
                }
                break;

            case 't':
                tx_depth = (unsigned int)strtoul(optarg, NULL, 0);
                break;

            case 'u':
                qp_timeout = (uint8_t)strtoul(optarg, NULL, 0);
                break;

            case 'R':
                qp_retry_cnt = (uint8_t)strtoul(optarg, NULL, 0);
                break;

            case 'M':
                mtu = (uint16_t)strtoul(optarg, NULL, 0);
                break;

            case 'D':
                dscp_values = get_dscp_list(optarg, &num_dscp_values);
                if (!dscp_values) {
                    fprintf(stderr, "Fail to get DSCP values\n");
                    return false;
                }
                break;

            case 'l':
                inline_msg = true;
                break;

            case 'e':
                use_event = true;
                break;

            case 'c':
                validate_buf = true;
                break;

            case 'm':
                use_multi_gid = true;
                break;

            case 'b':
                barrier_sync = true;
                break;

            case 'h':
            default:
                print_usage(argv[0]);
                return false;
        }
    }

    //printf("optind %d argc %d\n", optind, argc);
    if (optind == argc - 1) {
        server_ip = argv[optind];
    }

    if (!server_ip || !ib_dev_name) {
        if (!server_ip) {
            fprintf(stderr, "Fail to get host\n");
        }
        if (!ib_dev_name) {
            fprintf(stderr, "Fail to get IB device\n");
        }
        print_usage(argv[0]);
        return false;
    }

    if (barrier_sync && tx_depth != 1) {
        fprintf(stderr, "Barrier synchronization must be used with tx_depth = 1\n");
        return false;
    }

    if (dscp_values && num_dscp_values != num_qps) {
        fprintf(stderr, "# of DSCP values (%lu) != # of Queue Pairs (%u)\n", num_dscp_values, num_qps);
        return false;
    }

    return true;
}

/*
 * Send the number of iterations to the server
 * @param sockfd The socket to send the data to
 * @return true if the data was sent successfully, false otherwise
 */
static bool send_iters(int sockfd)
{
    size_t buf_size = sizeof(iters);
    return write_exact(sockfd, (char*)&iters, buf_size) == buf_size;
}
