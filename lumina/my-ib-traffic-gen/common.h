#ifndef COMMON_H
#define COMMON_H

#include <infiniband/verbs.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>

#define DEFAULT_IB_PORT 1

#define DEFAULT_MSG_SIZE 4096

#define DEFAULT_ITERS 100

#define DEFAULT_SERVER_PORT 12345

#define DEFAULT_CONTROLLER_PORT 12345

#define DEFAULT_NUM_QPS 1

#define DEFAULT_TX_DEPTH 1

#define DEFAULT_RX_DEPTH 50

#define DEFAULT_QP_TIMEOUT 14

#define DEFAULT_QP_RETRY_CNT 7

#define DEFAULT_MTU 1024

#define DEFAULT_DSCP 0

#define MIN_DSCP 0

#define MAX_DSCP 63

#define COMPLETE_MSG "Complete"

#define READY_MSG "Ready"

#define MAX_GID_COUNT 128

/*
 * Test method
 * RUN_REGULAR: run the test for a fixed number of iterations
 * RUN_INFINITELY: run the test infinitely until the user stops it
 */
enum TEST_METHOD {
    RUN_REGULAR = 0,
    RUN_INFINITELY = 1,
};

/*
 * RDMA operation type (verbs)
 * RECV_VERB: RDMA Receive
 * SEND_VERB: RDMA Send
 * WRITE_VERB: RDMA Write
 * READ_VERB: RDMA Read
 * SEND_READ_VERBS: RDMA Send and Read. This is a special verb combination to create bi-directional traffic.
 * It means using SEND for the first half of QPs and READ for the rest of QPs
 */
enum VERB {
    RECV_VERB = 0,
    SEND_VERB = 1,
    WRITE_VERB = 2,
    READ_VERB = 3,
    SEND_READ_VERBS = 4,
};

// Device context
struct dev_context
{
    // IB device name
    char                    *ib_dev_name;
    // IB device port
    int                     dev_port;

    // Global identifier
    int                     gid_index_list[MAX_GID_COUNT];
    union ibv_gid           gid_list[MAX_GID_COUNT];
    size_t                  gid_count;

    // GUID (Global Unique IDentifier)
    uint64_t                guid;

    // IB device context
    struct ibv_context      *ctx;
    // IB device attribute
    struct ibv_device_attr  dev_attr;
    // IB port attribute
    struct ibv_port_attr    port_attr;

    // Completion channel
    struct ibv_comp_channel *channel;
    // Protection domain
    struct ibv_pd           *pd;
    // Completion queue
    struct ibv_cq           *cq;
    // Whether to use event notification
    bool                    use_event;

    // Maximum Transmission Unit (MTU) from user
    uint16_t                user_mtu;
    // MTU enum (IBV_MTU_[N] where N = 256, 512, ... 4096)
    enum ibv_mtu            curr_mtu;
};

// Destination information
struct conn_dest {
    // Local identifier
    uint16_t        lid;
    // Queue pair number
    uint32_t        qpn;
    // Packet sequence number
    uint32_t        psn;
    // Global identifier
    union ibv_gid   gid;
    // GUID
    uint64_t        guid;
};

// Memory information
struct conn_mem {
    uint64_t    addr;
    uint32_t    key;
} __attribute__((packed));

// Connection context
struct conn_context
{
    unsigned int            id;
    struct dev_context      *dev_ctx;
    // Queue pair
    struct ibv_qp           *qp;

    // Memory region for data
    struct ibv_mr           *data_mr;

    // Memory for data
    unsigned char           *data_buf;
    size_t                  data_buf_size;
    bool                    validate_buf;

    // Work request send flags
    bool                    inline_msg;
    int                     send_flags;

    // Local Destination information
    struct conn_dest        local_dest;
    // Remote Destination information
    struct conn_dest        rem_dest;

    // Remote memory information
    struct conn_mem         rem_mem;

    // Index of GID to use
    unsigned int            gid_index;
    // Whether to use multiple GIDs (e.g., multiple IP addresses)
    bool                    use_multi_gid;

    // Remote GUID
    uint64_t                rem_guid;

    // Minimum timeout: 4us * (2 ^ (timeout))
    uint8_t                 timeout;

    // Maximum retry count (retransmission)
    uint8_t                 retry_cnt;

    // Max # of outstanding RDMA reads & atomic operations handled by this QP as an initiator
    uint8_t                 max_rd_atomic;
    // Max # of outstanding RDMA reads & atomic operations handled by this QP as an responder
    uint8_t                 max_dest_rd_atomic;

    // DSCP value
    uint8_t                 dscp;

    // Statistics for the connection
    // # of posted requests
    volatile unsigned int   post_reqs;
    // # of completed requests
    volatile unsigned int   complete_reqs;
    // # of completed requests recorded last time
    volatile unsigned int   last_complete_reqs;
    // End time of the test on this connection
    struct timeval          end_tv;
};

/*
 * Initialize device context
 * @param ctx device context
 * @return true on success and false on failure
 */
bool init_dev_ctx(struct dev_context *ctx);

/*
 * Destroy device context
 * @param ctx device context
 * @return: void
 */
void destroy_dev_ctx(struct dev_context *ctx);

/*
 * Print information of device context
 * @param ctx device context
 * @return: void
 */
void print_dev_ctx(struct dev_context *ctx);

/*
 * Initialize connection context
 * @param ctx connection context
 * @return true on success and false on failure
 */
bool init_conn_ctx(struct conn_context *ctx);

/*
 * Destroy connection context
 * @param ctx connection context
 * @return: void
 */
void destroy_conn_ctx(struct conn_context *ctx);

/*
 * Print information of connection context
 * @param ctx connection context
 * @return: void
 */
void print_conn_ctx(struct conn_context *ctx);

/*
 * Print information of destination
 * @param dest destination
 * @return: void
 */
void print_dest(struct conn_dest *dest);

/*
 * Print information of memory
 * @param mem memory
 * @return: void
 */
void print_mem(struct conn_mem *mem);

/*
 * Connect a queue pair (QP) with a remote destination
 * @param ctx connection (QP) context
 * @param dest remote destination
 * @return true on success and false on failure
 */
bool connect_qp(struct conn_context *ctx, struct conn_dest *dest);

/*
 * Post 'n' RDMA write requests on a connection (QP)
 * @param ctx connection context
 * @param n # of write requests to post
 * @return # of write requests that are successfully posted
 */
unsigned int post_write(struct conn_context *ctx, unsigned int n);

/*
 * Post 'n' RDMA send requests on a connection (QP)
 * @param ctx connection context
 * @param n # of send requests to post
 * @return # of send requests that are successfully posted
 */
unsigned int post_send(struct conn_context *ctx, unsigned int n);

/*
 * Post 'n' RDMA receive requests on a connection (QP)
 * @param ctx connection context
 * @param n # of receive requests to post
 * @return # of receive requests that are successfully posted
 */
unsigned int post_recv(struct conn_context *ctx, unsigned int n);

/*
 * Post 'n' RDMA read requests on a connection (QP)
 * @param ctx connection context
 * @param n # of read requests to post
 * @return # of read requests that are successfully posted
 */
unsigned int post_read(struct conn_context *ctx, unsigned int n);

/*
 * Wait for a work completion (WC) on a completion queue (CQ).
 * The returned WC is stored in @wc.
 *
 * @param cq completion queue
 * @param wc work completion (WC) to be returned
 * @return true on success and false on failure
 */
bool wait_for_wc(struct ibv_cq *cq, struct ibv_wc *wc);

/*
 * Parse a work completion (WC) for a RDMA write request
 * @param wc work completion (WC)
 * @return true on success and false on failure
 */
bool parse_write_wc(struct ibv_wc *wc);

/*
 * Parse a work completion (WC) for a RDMA send request
 * @param wc work completion (WC)
 * @return true on success and false on failure
 */
bool parse_send_wc(struct ibv_wc *wc);

/*
 * Parse a work completion (WC) for a RDMA receive request
 * @param wc work completion (WC)
 * @return true on success and false on failure
 */
bool parse_recv_wc(struct ibv_wc *wc);

/*
 * Parse a work completion (WC) for a RDMA read request
 * @param wc work completion (WC)
 * @return true on success and false on failure
 */
bool parse_read_wc(struct ibv_wc *wc);

/*
 * Write exactly 'count' bytes storing in buffer 'buf' into the file descriptor 'fd'.
 * @param fd file descriptor
 * @param buf buffer
 * @param count # of bytes to write
 * @return the number of bytes sucsessfully written
 */
size_t write_exact(int fd, char *buf, size_t count);

/*
 * Read exactly 'count' bytes storing in buffer 'buf' from the file descriptor 'fd'.
 * @param fd file descriptor
 * @param buf buffer
 * @param count # of bytes to read
 * @return the number of bytes sucsessfully read
 */
size_t read_exact(int fd, char *buf, size_t count);

/*
 * Connect to a socket server with the given IP address and port number
 * @param ip IP address
 * @param port port number
 * @return socket file descriptor on success and -1 on failure
 */
int connect_socket(char *ip, uint16_t port);

/*
 * Start a socket server listening on the given port number
 * @param listen_port port number to listen on
 * @return socket file descriptor on success and -1 on failure
 */
int start_socket_server(uint16_t listen_port);

/*
 * Accept a connection from a socket client
 * @param serv_sockfd socket file descriptor of the server
 * @return socket file descriptor on success and -1 on failure
 */
int accept_connection(int serv_sockfd);

/*
 * Notify the controller of run-time information of the experiment
 * @param ip IP address of the controller
 * @param port port number of the controller
 * @param connections connection context array
 * @param num_qps # of queue pairs (QPs)
 * @param verb RDMA verb
 * @return true on success and false on failure
 */
bool notify_controller(char *ip,
                       uint16_t port,
                       struct conn_context *connections,
                       unsigned int num_qps,
                       unsigned int verb);

/*
 * Notify the controller of run-time information of the experiment when using two verbs
 * @param ip IP address of the controller
 * @param port port number of the controller
 * @param connections_verb_a connection context array of the first verb
 * @param connections_verb_b connection context array of the second verb
 * @param num_qps_verb_a # of queue pairs (QPs) of the first verb
 * @param num_qps_verb_b # of queue pairs (QPs) of the second verb
 * @param verb_a_verb_b combination of the first and second verbs
 * @return true on success and false on failure
 */
bool notify_controller_dual_verbs(char *ip,
                                  uint16_t port,
                                  struct conn_context *connections_verb_a,
                                  struct conn_context *connections_verb_b,
                                  unsigned int num_qps_verb_a,
                                  unsigned int num_qps_verb_b,
                                  unsigned int verb_a_verb_b);

/*
 * Validate the buffer content
 * @param connections connection context array
 * @param num_qps # of queue pairs (QPs)
 * @return true on success and false on failure
 */
bool validate_buffer(struct conn_context *connections, unsigned int num_qps);

/*
 * Exchange RDMA metadata with the server (QP numbers, packet sequence numbers, etc.)
 * @param serv_sockfd socket file descriptor of the server
 * @param connections connection context array
 * @param num_qps # of queue pairs (QPs)
 * @param exchange_memory whether to exchange information about the memory region
 * @return true on success and false on failure
 */
bool exchange_metadata_with_server(int serv_sockfd,
                                   struct conn_context *connections,
                                   unsigned int num_qps,
                                   bool exchange_memory);

/*
 * Exchange RDMA metadata of with the server when using two verbs
 * @param serv_sockfd socket file descriptor of the server
 * @param connections_verb_a connection context array of the first verb
 * @param connections_verb_b connection context array of the second verb
 * @param num_qps_verb_a # of queue pairs (QPs) of the first verb
 * @param num_qps_verb_b # of queue pairs (QPs) of the second verb
 * @param exchange_memory whether to exchange information about the memory region
 * @return true on success and false on failure
 */
bool exchange_dual_verbs_metadata_with_server(int serv_sockfd,
                                              struct conn_context *connections_verb_a,
                                              struct conn_context *connections_verb_b,
                                              unsigned int num_qps_verb_a,
                                              unsigned int num_qps_verb_b,
                                              bool exchange_memory);

/*
 * Exchange RDMA metadata with the client (QP numbers, packet sequence numbers, etc.)
 * @param cli_sockfd socket file descriptor of the client
 * @param connections connection context array
 * @param num_qps # of queue pairs (QPs)
 * @param exchange_memory whether to exchange information about the memory region
 * @return true on success and false on failure
 */
bool exchange_metadata_with_client(int cli_sockfd,
                                   struct conn_context *connections,
                                   unsigned int num_qps,
                                   bool exchange_memory);

/*
 * Exchange RDMA metadata of with the client when using two verbs
 * @param cli_sockfd socket file descriptor of the client
 * @param connections_verb_a connection context array of the first verb
 * @param connections_verb_b connection context array of the second verb
 * @param num_qps_verb_a # of queue pairs (QPs) of the first verb
 * @param num_qps_verb_b # of queue pairs (QPs) of the second verb
 * @param exchange_memory whether to exchange information about the memory region
 * @return true on success and false on failure
 */
bool exchange_dual_verbs_metadata_with_client(int cli_sockfd,
                                              struct conn_context *connections_verb_a,
                                              struct conn_context *connections_verb_b,
                                              unsigned int num_qps_verb_a,
                                              unsigned int num_qps_verb_b,
                                              bool exchange_memory);

/*
 * Generate RDMA request traffic
 * @param verb RDMA verb to use
 * @param connections connection context array
 * @param num_qps # of queue pairs (QPs)
 * @param iters # of iterations
 * @param tx_depth transmit depth
 * @param use_event whether to use event notification
 * @return true on success and false on failure
 */
bool gen_req_traffic(unsigned int verb,
                     struct conn_context *connections,
                     unsigned int num_qps,
                     unsigned int iters,
                     unsigned int tx_depth,
                     bool use_event);

/*
 * Generate RDMA request traffic in a barrier synchronization fashion.
 * Barrier synchronization means that all the QPs will be synchronized for each iteration.
 *
 * @param verb RDMA verb to use
 * @param connections connection context array
 * @param num_qps # of queue pairs (QPs)
 * @param iters # of iterations
 * @param use_event whether to use event notification
 * @return true on success and false on failure
 */
bool gen_req_barrier_sync_traffic(unsigned int verb,
                                  struct conn_context *connections,
                                  unsigned int num_qps,
                                  unsigned int iters,
                                  bool use_event);

/*
 * Generate RDMA request traffic infinitely (until the user presses Ctrl+C)
 * @param verb RDMA verb to use
 * @param connections connection context array
 * @param num_qps # of queue pairs (QPs)
 * @param tx_depth transmit depth
 * @param use_event whether to use event notification
 * @return true on success and false on failure
 */
bool gen_req_traffic_infinitely(unsigned int verb,
                                struct conn_context *connections,
                                unsigned int num_qps,
                                unsigned int tx_depth,
                                bool use_event);

/*
 * Generate RDMA request traffic using two verbs
 * @param verb_a first RDMA verb to use
 * @param verb_b second RDMA verb to use
 * @param connections connection context array
 * @param num_qps_verb_a # of queue pairs (QPs) of the first verb
 * @param num_qps_verb_b # of queue pairs (QPs) of the second verb
 * @param iters # of iterations
 * @param tx_depth transmit depth
 * @param use_event whether to use event notification
 * @return true on success and false on failure
 */
bool gen_req_traffic_dual_verbs(unsigned int verb_a,
                                unsigned int verb_b,
                                struct conn_context *connections,
                                unsigned int num_qps_verb_a,
                                unsigned int num_qps_verb_b,
                                unsigned int iters,
                                unsigned int tx_depth,
                                bool use_event);

/*
 * Post RECV requests to receive RDMA traffic
 * @param connections connection context array
 * @param num_qps # of queue pairs (QPs)
 * @param iters # of iterations
 * @param use_event whether to use event notification
 * @return true on success and false on failure
 */
bool recv_traffic(struct conn_context *connections,
                  unsigned int num_qps,
                  unsigned int iters,
                  bool use_event);

/*
 * Send a ready notification to the peer
 * @param sockfd socket file descriptor of the peer
 * @return true on success and false on failure
 */
bool send_ready(int sockfd);

/*
 * Wait for a ready notification from the peer
 * @param sockfd socket file descriptor of the peer
 * @return true on success and false on failure
 */
bool wait_ready(int sockfd);

/*
 * Send a completion notification to the peer
 * @param sockfd socket file descriptor of the peer
 * @return true on success and false on failure
 */
bool send_completion(int sockfd);

/*
 * Wait for a completion notification from the peer
 * @param sockfd socket file descriptor of the peer
 * @return true on success and false on failure
 */
bool wait_completion(int sockfd);

/*
 * Extract DSCP array from the string. Set *size to the number of DSCP values extracted.
 * DSCP values are between 0 and 63. Examples: "1-2,5-7" -> [1,2,5,6,7]
 *
 * @param str string to parse. Format: <d1>[-d2][,d3[-d4],...] where d1, d2, etc are DSCP values.
 * @param size pointer to the number of DSCP values extracted
 * @return pointer to the DSCP array on success and NULL on failure
 */
uint8_t* get_dscp_list(char *str, size_t *size);

struct range {
    unsigned long start;
    unsigned long end;
};

/*
 * Extract range from the string and store the range in *r.
 * Examples: "1-2" -> {.start=1, .end=2}, "1" -> {.start=1, .end=1}
 *
 * @param str string to parse. Format: <d1>[-d2] where d1 and d2 are numbers.
 * @param r pointer to the range struct
 * @return true on success and false on failure
 */
bool str2range(char *str, struct range *r);

#endif
