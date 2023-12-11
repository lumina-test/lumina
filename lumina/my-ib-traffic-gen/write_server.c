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
static bool parse_args(int argc, char **argv);;

static uint16_t server_port     = DEFAULT_SERVER_PORT;
static char *ib_dev_name        = NULL;
static int ib_port              = DEFAULT_IB_PORT;
static unsigned int msg_size    = DEFAULT_MSG_SIZE;
static unsigned int num_qps     = DEFAULT_NUM_QPS;
static uint8_t qp_timeout       = DEFAULT_QP_TIMEOUT;
static uint8_t qp_retry_cnt     = DEFAULT_QP_RETRY_CNT;
static uint16_t mtu             = DEFAULT_MTU;
static uint8_t *dscp_values     = NULL;
static size_t num_dscp_values   = 0;
static bool validate_buf        = false;
static bool use_multi_gid       = false;

int main(int argc, char **argv)
{
    int server_sockfd = -1;
    int client_sockfd = -1;

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
        .use_event = false,
        .user_mtu= mtu
    };

    // Initialize the device context
    if (!init_dev_ctx(&device)) {
        fprintf(stderr, "Fail to initialize device context\n");
        goto err;
    }

    print_dev_ctx(&device);

    printf("Initialize %u queue pairs\n", num_qps);
    unsigned int num_qps_init = 0;
    struct conn_context *connections = (struct conn_context*)malloc(num_qps * sizeof(struct conn_context));
    if (!connections) {
        goto destroy_device;
    }

    // Initialize the connection contexts
    for (unsigned int i = 0; i < num_qps; i++) {
        connections[i].id = i;
        connections[i].dev_ctx = &device;
        connections[i].qp = NULL;
        connections[i].data_mr = NULL;
        connections[i].data_buf = NULL;
        connections[i].data_buf_size = msg_size;
        connections[i].validate_buf = false;
        connections[i].inline_msg = false;
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

    // Start the socket server to accept the connection from the client
    server_sockfd = start_socket_server(server_port);
    if (server_sockfd < 0) {
        fprintf(stderr, "Fail to initialize socket server on port %hu\n", server_port);
        goto destroy_connections;
    }
    printf("Start socket server on port %hu\n", server_port);

    // Wait for the connection from the client
    client_sockfd = accept_connection(server_sockfd);
    if (client_sockfd < 0) {
        fprintf(stderr, "Fail to accept a connection\n");
        goto destroy_socket_server;
    }
    printf("Accept a connection\n");

    // Exchange the RDMA metadata with the client
    if (!exchange_metadata_with_client(client_sockfd, connections, num_qps, true)) {
        fprintf(stderr, "Fail to exchange RDMA metadata with the client\n");
        goto destroy_socket_client;
    }
    printf("Exchange RDMA metadata with the client\n");

    // Wait for the completion notification from the client
    if (!wait_completion(client_sockfd)) {
        fprintf(stderr, "Fail to get the completion notification\n");
        goto destroy_socket_client;
    }

    close(client_sockfd);
    close(server_sockfd);

    printf("Experiment completes\n");
    if (validate_buf) {
        if (!validate_buffer(connections, num_qps)) {
            fprintf(stderr, "Invalid buffer content\n");
            goto destroy_connections;
        } else {
            printf("Validate buffer\n");
        }
    }

    for (unsigned int i = 0; i < num_qps; i++) {
        destroy_conn_ctx(&connections[i]);
    }

    free(connections);
    destroy_dev_ctx(&device);
    free(dscp_values);

    return EXIT_SUCCESS;

destroy_socket_client:
    close(client_sockfd);

destroy_socket_server:
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
        // should never happen
        return;
    }

    fprintf(stderr, "Usage: %s [options]\n", app);
    fprintf(stderr, "Options:\n");

    fprintf(stderr, "  -p, --port=<port>            listen on/connect to port <port> (default %d)\n", DEFAULT_SERVER_PORT);
    fprintf(stderr, "  -d, --ib-dev=<dev>           use IB device <dev>\n");
    fprintf(stderr, "  -i, --ib-port=<port>         use port <port> of IB device (default %d)\n", DEFAULT_IB_PORT);
    fprintf(stderr, "  -s, --size=<size>            size of message to exchange (default %d)\n", DEFAULT_MSG_SIZE);
    fprintf(stderr, "  -q, --qp=<num of qp's>       number of queue pairs (default %d)\n", DEFAULT_NUM_QPS);
    fprintf(stderr, "  -u, --qp-timeout=<timeout>   QP timeout value is 4usec * (2^timeout) (default %hhu)\n", DEFAULT_QP_TIMEOUT);
    fprintf(stderr, "  -R, --qp-retry-cnt=<cnt>     QP retry count (default %hhu)\n", DEFAULT_QP_RETRY_CNT);
    fprintf(stderr, "  -M, --mtu=<mtu>              MTU size: 256 - 4096  (default %hu)\n", DEFAULT_MTU);
    fprintf(stderr, "  -D, --dscp=<DSCP list>       list of per-QP DSCP values. Format: <d1>[-d2][,d3[-d4],...]\n");
    fprintf(stderr, "  -c, --chk                    validate received buffer\n");
    fprintf(stderr, "  -m, --multi-gid              use multiple GIDs associated with the IB interface\n");
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
            { .name = "port",       .has_arg = 1, .val = 'p' },
            { .name = "ib-dev",     .has_arg = 1, .val = 'd' },
            { .name = "ib-port",    .has_arg = 1, .val = 'i' },
            { .name = "size",       .has_arg = 1, .val = 's' },
            { .name = "qps",        .has_arg = 1, .val = 'q' },
            { .name = "timeout",    .has_arg = 1, .val = 'u' },
            { .name = "retry-cnt",  .has_arg = 1, .val = 'R' },
            { .name = "mtu",        .has_arg = 1, .val = 'M' },
            { .name = "dscp",       .has_arg = 1, .val = 'D' },
            { .name = "chk",        .has_arg = 0, .val = 'c' },
            { .name = "multi-gid",  .has_arg = 0, .val = 'm' },
            { .name = "help",       .has_arg = 0, .val = 'h' },
            {}
        };

        int c = getopt_long(argc, argv, "p:d:i:s:q:u:R:M:D:cmh", long_options, NULL);

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

            case 'q':
                num_qps = (unsigned int)strtoul(optarg, NULL, 0);
                if (num_qps < 1) {
                    fprintf(stderr, "Invalid number of QPs (%u)\n", num_qps);
                    print_usage(argv[0]);
                    return false;
                }
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

            case 'c':
                validate_buf = true;
                break;

            case 'm':
                use_multi_gid = true;
                break;

            case 'h':
            default:
                print_usage(argv[0]);
                return false;
        }
    }

    if (!ib_dev_name) {
        fprintf(stderr, "Fail to get IB device name\n");
        print_usage(argv[0]);
        return false;
    }

    // Check if the number of DSCP values matches the number of QPs
    if (dscp_values && num_dscp_values != num_qps) {
        fprintf(stderr, "# of DSCP values (%lu) != # of Queue Pairs (%u)\n", num_dscp_values, num_qps);
        return false;
    }

    return true;
}
