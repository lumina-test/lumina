#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <inttypes.h>
#include <dirent.h>
#include <x86intrin.h>
#include <pthread.h>
#include <signal.h>
#include "common.h"

// The number of microseconds in a second
#define USEC_PER_SEC 1000000L

// String representation of the verbs
static const char *VERB_STRING[] = {
    "RECV", "SEND", "WRITE", "READ", "SEND_READ"
};

/*
 * Return time duration from b to a (a-b) in microsecond
 * @param a: the later time
 * @param b: the earlier time
 * @return: the time duration in microsecond
 */
static inline uint64_t timeval_subtract_to_usec(struct timeval a, struct timeval b)
{
    return (a.tv_sec - b.tv_sec) * USEC_PER_SEC + a.tv_usec - b.tv_usec;
}

/*
 * Return the index of the IB device whose name is ib_dev_name
 * @param ib_dev_name: the name of the IB device
 * @param dev_list: the list of IB devices
 * @param num_devices: the number of IB devices
 * @return: the index of the IB device whose name is ib_dev_name if found, -1 otherwise
 */
static inline int ib_dev_id_by_name(char *ib_dev_name,
                                    struct ibv_device **dev_list,
                                    int num_devices)
{
    for (int i = 0; i < num_devices; i++) {
        if (strcmp(ibv_get_device_name(dev_list[i]), ib_dev_name) == 0) {
            return i;
        }
    }

    return -1;
}

// Compare function used by qsort to sort numbers in ascending order
static int cmpfunc(const void * a, const void * b) {
   return (*(int*)a - *(int*)b);
}

/*
 * Check if the gid referenced by gid_index is a ipv4-gid
 * @param ctx: the device context
 * @param gid_index: the index of the gid
 * @return: true if the gid is a ipv4-gid, false otherwise
 */
static bool is_ipv4_gid(struct dev_context *ctx, int gid_index) {
    char file_name[384] = {0};
    static const char ipv4_gid_prefix[] = "0000:0000:0000:0000:0000:ffff:";
    FILE * fp = NULL;
    ssize_t read;
    char * line = NULL;
    size_t len = 0;
    snprintf(file_name, sizeof(file_name), "/sys/class/infiniband/%s/ports/%d/gids/%d",
             ctx->ib_dev_name, ctx->dev_port, gid_index);
    fp = fopen(file_name, "r");
    if (!fp) {
        return false;
    }
    read = getline(&line, &len, fp);
    fclose(fp);
    if (!read) {
        return false;
    }
    return strncmp(line, ipv4_gid_prefix, strlen(ipv4_gid_prefix)) == 0;
}

/*
 * Get the index of all the GIDs whose types are RoCE v2, and store them in ctx->gid_index_list
 * Reference: https://docs.mellanox.com/pages/viewpage.action?pageId=12013422#RDMAoverConvergedEthernet(RoCE)-RoCEv2
 *
 * @param ctx: the device context
 * @return: void
 */
static void get_rocev2_gid_index(struct dev_context *ctx)
{
    const size_t max_gid_count = sizeof(ctx->gid_index_list) / sizeof(ctx->gid_index_list[0]);
    int gid_index_list[max_gid_count];
    int gid_count = 0;

    ctx->gid_count = 0;

    char dir_name[128] = {0};
    snprintf(dir_name, sizeof(dir_name), "/sys/class/infiniband/%s/ports/%d/gid_attrs/types",
             ctx->ib_dev_name, ctx->dev_port);
    DIR *dir = opendir(dir_name);
    if (!dir) {
        fprintf(stderr, "Fail to open folder %s\n", dir_name);
        return;
    }

    struct dirent *dp = NULL;
    char file_name[384] = {0};
    FILE *fp = NULL;
    ssize_t read;
    char *line = NULL;
    size_t len = 0;
    int gid_index;
    char *rocev2_str = "RoCE v2";
    size_t rocev2_str_len = strlen(rocev2_str);

    while ((dp = readdir(dir)) && gid_count < max_gid_count) {
        gid_index = atoi(dp->d_name);
        snprintf(file_name, sizeof(file_name), "%s/%s", dir_name, dp->d_name);
        fp = fopen(file_name, "r");
        if (!fp) {
            continue;
        }

        read = getline(&line, &len, fp);
        fclose(fp);
        if (read <= 0) {
            continue;
        }

        if (strncmp(line, rocev2_str, rocev2_str_len) != 0) {
            continue;
        }

        if (!is_ipv4_gid(ctx, gid_index)) {
            continue;
        }

        gid_index_list[gid_count++] = gid_index;
    }

    closedir(dir);

    qsort(gid_index_list, gid_count, sizeof(int), cmpfunc);
    ctx->gid_count = gid_count;
    for (int i = 0; i < gid_count; i++) {
        ctx->gid_index_list[i] = gid_index_list[i];
    }
    //Debug
    //printf("Get %lu RoCE V2 GIDs\n", ctx->gid_count);
}

/*
 * Initialize the device context
 * @param ctx: the device context
 * @return: true if the device context is initialized successfully, false otherwise
 */
bool init_dev_ctx(struct dev_context *ctx)
{
    if (!ctx || !(ctx->ib_dev_name)) {
        goto err;
    }

    struct ibv_device **dev_list = NULL;
    int num_devices;

    // Get IB device list
    dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list) {
        fprintf(stderr, "Fail to get IB device list\n");
        goto err;

    } else if (num_devices == 0) {
        fprintf(stderr, "No IB devices found\n");
        goto clean_dev_list;
    }

    int ib_dev_id = -1;
    ib_dev_id = ib_dev_id_by_name(ctx->ib_dev_name, dev_list, num_devices);
    if (ib_dev_id < 0) {
        fprintf(stderr, "Fail to find IB device %s\n", ctx->ib_dev_name);
        goto clean_dev_list;
    }

    // Create a context for the RDMA device
    ctx->ctx = ibv_open_device(dev_list[ib_dev_id]);
    if (ctx->ctx) {
        printf("Open IB device %s\n", ibv_get_device_name(dev_list[ib_dev_id]));
    } else {
        fprintf(stderr, "Fail to open IB device %s\n", ibv_get_device_name(dev_list[ib_dev_id]));
        goto clean_dev_list;
    }

    // Get GUID (Node global unique identifier)
    ctx->guid = ibv_get_device_guid(dev_list[ib_dev_id]);

    // Get the index of GIDs whose types are RoCE v2
    get_rocev2_gid_index(ctx);
    if (ctx->gid_count == 0) {
        fprintf(stderr, "Cannot find any RoCE v2 GID\n");
        goto clean_device;
    }

    // Get RoCE v2 GIDs
    for (size_t i = 0; i < ctx->gid_count; i++) {
        if (ibv_query_gid(ctx->ctx, ctx->dev_port, ctx->gid_index_list[i], &(ctx->gid_list[i])) != 0) {
            fprintf(stderr, "Cannot read GID of index %d\n", ctx->gid_index_list[i]);
            goto clean_device;
        }
    }

    // Create a completion channel
    if (ctx->use_event) {
        ctx->channel = ibv_create_comp_channel(ctx->ctx);
        if (!(ctx->channel)) {
            fprintf(stderr, "Cannot create completion channel\n");
            goto clean_device;
        }
    } else {
        ctx->channel = NULL;
    }

    // Allocate protection domain
    ctx->pd = ibv_alloc_pd(ctx->ctx);
    if (!(ctx->pd)) {
        fprintf(stderr, "Fail to allocate protection domain\n");
        goto clean_comp_channel;
    }

    // Query device attributes
    if (ibv_query_device(ctx->ctx, &(ctx->dev_attr)) != 0) {
        fprintf(stderr, "Fail to query device attributes\n");
        goto clean_pd;
    }

    // Query port attributes
    if (ibv_query_port(ctx->ctx, ctx->dev_port, &(ctx->port_attr)) != 0) {
        fprintf(stderr, "Fail to query port attributes\n");
        goto clean_pd;
    }

    // Create a completion queue
    ctx->cq = ibv_create_cq(ctx->ctx, ctx->dev_attr.max_cqe, NULL, ctx->channel, 0);
    if (!(ctx->cq)) {
        fprintf(stderr, "Fail to create the completion queue\n");
        goto clean_pd;
    }

    if (ctx->use_event) {
        if (ibv_req_notify_cq(ctx->cq, 0)) {
            fprintf(stderr, "Cannot request CQ notification\n");
            goto clean_cq;
        }
    }

    // Parse user MTU
    switch (ctx->user_mtu) {
        case 256:
            ctx->curr_mtu = IBV_MTU_256;
            break;

        case 512:
            ctx->curr_mtu = IBV_MTU_512;
            break;

        case 1024:
            ctx->curr_mtu = IBV_MTU_1024;
            break;

        case 2048:
            ctx->curr_mtu = IBV_MTU_2048;
            break;

        case 4096:
            ctx->curr_mtu = IBV_MTU_4096;
            break;

        default:
            fprintf(stderr," Invalid MTU - %hu \n", ctx->user_mtu);
            fprintf(stderr," Please choose mtu from {256,512,1024,2048,4096}\n");
            goto clean_cq;
    }

    if (ctx->curr_mtu > ctx->port_attr.active_mtu) {
        fprintf(stdout, "Requested MTU is higher than active MTU\n");
        goto clean_cq;
    }

    ibv_free_device_list(dev_list);
    return true;

clean_cq:
    ibv_destroy_cq(ctx->cq);

clean_pd:
	ibv_dealloc_pd(ctx->pd);

clean_comp_channel:
    if (ctx->channel) {
        ibv_destroy_comp_channel(ctx->channel);
    }

clean_device:
	ibv_close_device(ctx->ctx);

clean_dev_list:
    ibv_free_device_list(dev_list);

err:
    return false;
}

/*
 * Destroy device context
 * @param ctx device context
 * @return: void
 */
void destroy_dev_ctx(struct dev_context *ctx)
{
    if (!ctx) {
        return;
    }

    // Destroy completion queue
    if (ctx->cq) {
        ibv_destroy_cq(ctx->cq);
    }

    // Destroy protection domain
    if (ctx->pd) {
        ibv_dealloc_pd(ctx->pd);
    }

    // Desotry completion channel
    if (ctx->channel) {
        ibv_destroy_comp_channel(ctx->channel);
    }

    // Close RDMA device context
    if (ctx->ctx) {
        ibv_close_device(ctx->ctx);
    }
}

/*
 * Print device context
 * @param ctx device context
 * @return: void
 */
void print_dev_ctx(struct dev_context *ctx)
{
    if (!ctx) {
        return;
    }

    printf("================ Device Context ================\n");
    printf("Device name: %s\n", ctx->ib_dev_name);
    printf("Device port: %d\n", ctx->dev_port);
    printf("MTU: %hu (enum: %d)\n", ctx->user_mtu, (int)(ctx->curr_mtu));
    printf("RoCE v2 GID count: %lu (Index:", ctx->gid_count);

    for (size_t i = 0; i < ctx->gid_count; i++) {
        printf(" %d", ctx->gid_index_list[i]);
    }
    printf(")\n");
}

/*
 * Initialize connection context
 * @param ctx connection context
 * @return: true on success, false on failure
 */
bool init_conn_ctx(struct conn_context *ctx)
{
    if (!ctx || !(ctx->dev_ctx)) {
        goto err;
    }

    // Allocate memory
    ctx->data_buf = (unsigned char*)memalign(sysconf(_SC_PAGESIZE), ctx->data_buf_size);
    if (!(ctx->data_buf)) {
        fprintf(stderr, "Fail to allocate memory\n");
        goto err;
    }

    if (ctx->validate_buf) {
        for (size_t i = 0; i < ctx->data_buf_size; i++) {
            ctx->data_buf[i] = i & 0xFF;
        }
    }

    // Register memory region for data
    int access_flags = IBV_ACCESS_LOCAL_WRITE |
                       IBV_ACCESS_REMOTE_WRITE |
                       IBV_ACCESS_REMOTE_READ;

    ctx->data_mr = ibv_reg_mr(ctx->dev_ctx->pd, ctx->data_buf, ctx->data_buf_size, access_flags);
    if (!(ctx->data_mr)) {
        fprintf(stderr, "Fail to register memory region\n");
        goto clean_data_buf;
    }

    // Create a queue pair (QP)
    struct ibv_qp_attr attr;
    struct ibv_qp_init_attr init_attr = {
        .send_cq = ctx->dev_ctx->cq,
        .recv_cq = ctx->dev_ctx->cq,
        .cap = {
            .max_send_wr = ctx->dev_ctx->dev_attr.max_qp_wr / 4,
            .max_recv_wr = ctx->dev_ctx->dev_attr.max_qp_wr / 4,
            .max_send_sge = 1,
            .max_recv_sge = 1,
        },
        .qp_type = IBV_QPT_RC,
    };

    ctx->qp = ibv_create_qp(ctx->dev_ctx->pd, &init_attr);
    if (!(ctx->qp)) {
        fprintf(stderr, "Fail to create QP\n");
        goto clean_data_mr;
    }

    ctx->send_flags = IBV_SEND_SIGNALED;
    if (ctx->inline_msg) {
        ibv_query_qp(ctx->qp, &attr, IBV_QP_CAP, &init_attr);

        if (init_attr.cap.max_inline_data >= ctx->data_buf_size) {
			ctx->send_flags |= IBV_SEND_INLINE;
	    } else {
            fprintf(stderr, "Fail to set IBV_SEND_INLINE because max inline data size is %d < %ld\n",
                    init_attr.cap.max_inline_data, ctx->data_buf_size);
            goto clean_qp;
        }
    }

    attr.qp_state        = IBV_QPS_INIT;
    attr.pkey_index      = 0;
    attr.port_num        = ctx->dev_ctx->dev_port;
    // Allow incoming RDMA writes and reads on this QP
    attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;

    if (ibv_modify_qp(ctx->qp, &attr,
				      IBV_QP_STATE          |
				      IBV_QP_PKEY_INDEX     |
				      IBV_QP_PORT           |
				      IBV_QP_ACCESS_FLAGS)) {

        fprintf(stderr, "Fail to modify QP to INIT\n");
        goto clean_qp;
    }

    srand48(getpid() * time(NULL) + ctx->id);
    // local identifier
    ctx->local_dest.lid = ctx->dev_ctx->port_attr.lid;
    // QP number
    ctx->local_dest.qpn = ctx->qp->qp_num;
    // packet sequence number
    ctx->local_dest.psn = lrand48() & 0xffffff;

    // global identifier
    unsigned int index = (ctx->use_multi_gid)? ctx->id % ctx->dev_ctx->gid_count : 0;
    ctx->gid_index = ctx->dev_ctx->gid_index_list[index];
    ctx->local_dest.gid = ctx->dev_ctx->gid_list[index];

    // Get the GUID of the device
    ctx->local_dest.guid = ctx->dev_ctx->guid;

    ctx->post_reqs = 0;
    ctx->complete_reqs = 0;

    return true;

clean_qp:
    ibv_destroy_qp(ctx->qp);

clean_data_mr:
    ibv_dereg_mr(ctx->data_mr);

clean_data_buf:
    free(ctx->data_buf);

err:
    return false;
}

/*
 * Destroy connection context
 * @param ctx connection context
 * @return: void
 */
void destroy_conn_ctx(struct conn_context *ctx)
{
    if (!ctx) {
        return;
    }

    // Destroy queue pair
    if (ctx->qp) {
        ibv_destroy_qp(ctx->qp);
    }

    // Un-register memory region
    if (ctx->data_mr) {
        ibv_dereg_mr(ctx->data_mr);
    }

    // Free memory
    if (ctx->data_buf) {
        free(ctx->data_buf);
    }
}

/*
 * Print connection context
 * @param ctx connection context
 * @return: void
 */
void print_conn_ctx(struct conn_context *ctx)
{
    if (!ctx) {
        // This should not happen
        return;
    }

    char gid[33] = {0};
    inet_ntop(AF_INET6, &( ctx->local_dest.gid), gid, sizeof(gid));

    printf("================ Connection Context ================\n");
    printf("Connection ID:              %u\n", ctx->id);
    printf("Data buffer size:           %lu\n", ctx->data_buf_size);
    printf("Send messages as inline:    %d\n", ctx->inline_msg);
    printf("Local identifier:           %hu\n", ctx->local_dest.lid);
    printf("Queue pair number:          %u\n", ctx->local_dest.qpn);
    printf("Packet sequence number:     %u\n", ctx->local_dest.psn);
    printf("Global Identifier:          %s\n", gid);
    printf("GUID:                       %lx\n", ctx->local_dest.guid);
    printf("Timeout:                    %hhu\n", ctx->timeout);
    printf("Retry count:                %hhu\n", ctx->retry_cnt);
    printf("MTU:                        %hu\n", ctx->dev_ctx->user_mtu);
    printf("Max read & atomic as src:   %hhu\n", ctx->max_rd_atomic);
    printf("Max read & atomic as dest:  %hhu\n", ctx->max_dest_rd_atomic);
    printf("DSCP:                       %u\n", ctx->dscp);
}

/*
 * Print destination information
 * @param dest destination information
 * @return: void
 */
void print_dest(struct conn_dest *dest)
{
    if (!dest) {
        return;
    }

    char gid[33] = {0};
    inet_ntop(AF_INET6, &(dest->gid), gid, sizeof(gid));
    printf("LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s, GUID %016lx\n",
	       dest->lid, dest->qpn, dest->psn, gid, dest->guid);
}

/*
 * Print memory information
 * @param mem memory information
 * @return: void
 */
void print_mem(struct conn_mem *mem)
{
    printf("Addr %" PRIu64 ", Key %" PRIu32 "\n", mem->addr, mem->key);
}

/*
 * Connect a queue pair (QP) with a remote destination
 * @param ctx connection (QP) context
 * @param dest remote destination
 * @return true on success and false on failure
 */
bool connect_qp(struct conn_context *ctx, struct conn_dest *dest)
{
    struct ibv_qp_attr attr = {
		.qp_state		    = IBV_QPS_RTR,
		.path_mtu		    = ctx->dev_ctx->curr_mtu,
        // Remote QP number
		.dest_qp_num		= dest->qpn,
        // Packet Sequence Number of the received packets
		.rq_psn			    = dest->psn,
		.max_dest_rd_atomic	= ctx->max_dest_rd_atomic,
		.min_rnr_timer		= 12,
        // Address vector
		.ah_attr		    = {
			.is_global	    = 0,
			.dlid		    = dest->lid,
			.sl		        = 0,
			.src_path_bits	= 0,
			.port_num	    = ctx->dev_ctx->dev_port
		}
	};

    if (dest->gid.global.interface_id) {
        attr.ah_attr.is_global = 1;
        // Set attributes of the Global Routing Headers (GRH)
        // When using RoCE, GRH must be configured!
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.dgid = dest->gid;
        attr.ah_attr.grh.flow_label = 0;
        attr.ah_attr.grh.sgid_index = ctx->gid_index;
        attr.ah_attr.grh.traffic_class = (ctx->dscp << 2);
    }

    if (ibv_modify_qp(ctx->qp, &attr,
			          IBV_QP_STATE              |
			          IBV_QP_AV                 |
			          IBV_QP_PATH_MTU           |
			          IBV_QP_DEST_QPN           |
			          IBV_QP_RQ_PSN             |
			          IBV_QP_MAX_DEST_RD_ATOMIC |
			          IBV_QP_MIN_RNR_TIMER)) {
		fprintf(stderr, "Fail to modify QP to RTR\n");
		return false;
	}

    attr.qp_state	    = IBV_QPS_RTS;
    // The minimum time that a QP waits for ACK/NACK from remote QP
    attr.timeout	    = ctx->timeout;
    attr.retry_cnt	    = ctx->retry_cnt;
    // Retry infinite number of times to send the message
    // when RNR Nack is being sent by remote side
    attr.rnr_retry	    = 7;
    attr.sq_psn	        = ctx->local_dest.psn;
    attr.max_rd_atomic  = ctx->max_rd_atomic;

    if (ibv_modify_qp(ctx->qp, &attr,
			          IBV_QP_STATE              |
			          IBV_QP_TIMEOUT            |
			          IBV_QP_RETRY_CNT          |
			          IBV_QP_RNR_RETRY          |
			          IBV_QP_SQ_PSN             |
			          IBV_QP_MAX_QP_RD_ATOMIC)) {
		fprintf(stderr, "Failed to modify QP to RTS\n");
		return false;
	}

    return true;
}

/*
 * Post 'n' RDMA write requests on a connection (QP)
 * @param ctx connection context
 * @param n # of write requests to post
 * @return # of write requests that are successfully posted
 */
unsigned int post_write(struct conn_context *ctx, unsigned int n)
{
    struct ibv_sge list = {
		.addr	= (uintptr_t)(ctx->data_buf),
		.length = ctx->data_buf_size,
		.lkey	= ctx->data_mr->lkey
	};

	struct ibv_send_wr wr = {
        .wr_id	            = ctx->id,
        .sg_list            = &list,
        .num_sge            = 1,
        .opcode             = IBV_WR_RDMA_WRITE,
        .send_flags         = ctx->send_flags,
        .wr.rdma.remote_addr= ctx->rem_mem.addr,
        .wr.rdma.rkey       = ctx->rem_mem.key
	};

    struct ibv_send_wr *bad_wr;
    unsigned int i;
    for (i = 0; i < n; i++) {
        if (ibv_post_send(ctx->qp, &wr, &bad_wr) != 0) {
            break;
        }
    }

    return i;
}

/*
 * Post 'n' RDMA send requests on a connection (QP)
 * @param ctx connection context
 * @param n # of send requests to post
 * @return # of send requests that are successfully posted
 */
unsigned int post_send(struct conn_context *ctx, unsigned int n)
{
    struct ibv_sge list = {
		.addr	= (uintptr_t)(ctx->data_buf),
		.length = ctx->data_buf_size,
		.lkey	= ctx->data_mr->lkey
	};

	struct ibv_send_wr wr = {
        .wr_id          = ctx->id,
        .sg_list        = &list,
        .num_sge        = 1,
        .opcode         = IBV_WR_SEND,
        .send_flags     = ctx->send_flags
	};

    struct ibv_send_wr *bad_wr;
    unsigned int i;
    for (i = 0; i < n; i++) {
        if (ibv_post_send(ctx->qp, &wr, &bad_wr) != 0) {
            break;
        }
    }

    return i;
}

/*
 * Post 'n' RDMA receive requests on a connection (QP)
 * @param ctx connection context
 * @param n # of receive requests to post
 * @return # of receive requests that are successfully posted
 */
unsigned int post_recv(struct conn_context *ctx, unsigned int n)
{
    struct ibv_sge list = {
		.addr	= (uintptr_t)(ctx->data_buf),
		.length = ctx->data_buf_size,
		.lkey	= ctx->data_mr->lkey
	};

	struct ibv_recv_wr wr = {
        .wr_id      = ctx->id,
        .sg_list    = &list,
        .num_sge    = 1
	};

    struct ibv_recv_wr *bad_wr;
    unsigned int i;
    for (i = 0; i < n; i++) {
        if (ibv_post_recv(ctx->qp, &wr, &bad_wr) != 0) {
            break;
        }
    }

    return i;
}

/*
 * Post 'n' RDMA read requests on a connection (QP)
 * @param ctx connection context
 * @param n # of read requests to post
 * @return # of read requests that are successfully posted
 */
unsigned int post_read(struct conn_context *ctx, unsigned int n)
{
    struct ibv_sge list = {
		.addr	= (uintptr_t)(ctx->data_buf),
		.length = ctx->data_buf_size,
		.lkey	= ctx->data_mr->lkey
	};

	struct ibv_send_wr wr = {
        .wr_id	            = ctx->id,
        .sg_list            = &list,
        .num_sge            = 1,
        .opcode             = IBV_WR_RDMA_READ,
        .send_flags         = ctx->send_flags,
        .wr.rdma.remote_addr= ctx->rem_mem.addr,
        .wr.rdma.rkey       = ctx->rem_mem.key
	};

    struct ibv_send_wr *bad_wr;
    unsigned int i;
    for (i = 0; i < n; i++) {
        if (ibv_post_send(ctx->qp, &wr, &bad_wr) != 0) {
            break;
        }
    }

    return i;
}

/*
 * Post 'n' work requests on a connection (QP)
 * @param verb type of work request
 * @param ctx connection context
 * @param n # of work requests to post
 * @return # of work requests that are successfully posted
 */
static inline unsigned int post_req(unsigned int verb, struct conn_context *ctx, unsigned int n)
{
    switch(verb) {
        case RECV_VERB:
            return post_recv(ctx, n);

        case SEND_VERB:
            return post_send(ctx, n);

        case WRITE_VERB:
            return post_write(ctx, n);

        case READ_VERB:
            return post_read(ctx, n);

        default:
            break;
    }

    return 0;
}

/*
 * Wait for a work completion (WC) on a completion queue (CQ).
 * The returned WC is stored in @wc.
 *
 * @param cq completion queue
 * @param wc work completion (WC) to be returned
 * @return true on success and false on failure
 */
bool wait_for_wc(struct ibv_cq *cq, struct ibv_wc *wc)
{
    while (true) {
        int ne = ibv_poll_cq(cq, 1, wc);
        if (ne < 0) {
            fprintf(stderr, "Fail to poll CQ (%d)\n", ne);
			return false;

        } else if (ne > 0) {
            return true;

        } else {
            //printf("Return 0\n");
            continue;
        }
    }

    // We should never reach here
    return false;
}

/*
 * Parse a work completion (WC) for a RDMA write request
 * @param wc work completion (WC)
 * @return true on success and false on failure
 */
bool parse_write_wc(struct ibv_wc *wc)
{
    if (wc->status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Work request status is %s\n", ibv_wc_status_str(wc->status));
        return false;
    }

    if (wc->opcode != IBV_WC_RDMA_WRITE) {
        fprintf(stderr, "Work request opcode is not IBV_WC_RDMA_WRITE (%d)\n", wc->opcode);
        return false;
    }

    return true;
}

/*
 * Parse a work completion (WC) for a RDMA send request
 * @param wc work completion (WC)
 * @return true on success and false on failure
 */
bool parse_send_wc(struct ibv_wc *wc)
{
    if (wc->status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Work request status is %s\n", ibv_wc_status_str(wc->status));
        return false;
    }

    if (wc->opcode != IBV_WC_SEND) {
        fprintf(stderr, "Work request opcode is not IBV_WC_SEND (%d)\n", wc->opcode);
        return false;
    }

    return true;
}

/*
 * Parse a work completion (WC) for a RDMA receive request
 * @param wc work completion (WC)
 * @return true on success and false on failure
 */
bool parse_recv_wc(struct ibv_wc *wc)
{
    if (wc->status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Work request status is %s\n", ibv_wc_status_str(wc->status));
        return false;
    }

    if (wc->opcode != IBV_WC_RECV) {
        fprintf(stderr, "Work request opcode is not IBV_WC_RECV (%d)\n", wc->opcode);
        return false;
    }

    return true;
}

/*
 * Parse a work completion (WC) for a RDMA read request
 * @param wc work completion (WC)
 * @return true on success and false on failure
 */
bool parse_read_wc(struct ibv_wc *wc)
{
    if (wc->status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Work request status is %s\n", ibv_wc_status_str(wc->status));
        return false;
    }

    if (wc->opcode != IBV_WC_RDMA_READ) {
        fprintf(stderr, "Work request opcode is not IBV_WC_RDMA_READ (%d)\n", wc->opcode);
        return false;
    }

    return true;
}

/*
 * Parse a work completion (WC) based on the verb type
 * @param verb type of work request
 * @param wc work completion (WC)
 * @return true on success and false on failure
 */
static inline bool parse_wc(unsigned int verb, struct ibv_wc *wc)
{
    switch (verb) {
        case RECV_VERB:
            return parse_recv_wc(wc);

        case SEND_VERB:
            return parse_send_wc(wc);

        case WRITE_VERB:
            return parse_write_wc(wc);

        case READ_VERB:
            return parse_read_wc(wc);

        default:
            break;
    }

    return false;
}

/*
 * Write exactly 'count' bytes storing in buffer 'buf' into the file descriptor 'fd'.
 * @param fd file descriptor
 * @param buf buffer
 * @param count # of bytes to write
 * @return the number of bytes sucsessfully written
 */
size_t write_exact(int fd, char *buf, size_t count)
{
    // current buffer loccation
    char *cur_buf = NULL;
    // # of bytes that have been written
    size_t bytes_wrt = 0;
    int n;

    if (!buf) {
        return 0;
    }

    cur_buf = buf;

    while (count > 0) {
        n = write(fd, cur_buf, count);

        if (n <= 0) {
            fprintf(stderr, "write error\n");
            break;

        } else {
            bytes_wrt += n;
            count -= n;
            cur_buf += n;
        }
    }

    return bytes_wrt;
}

/*
 * Read exactly 'count' bytes storing in buffer 'buf' from the file descriptor 'fd'.
 * @param fd file descriptor
 * @param buf buffer
 * @param count # of bytes to read
 * @return the number of bytes sucsessfully read
 */
size_t read_exact(int fd, char *buf, size_t count)
{
    // current buffer loccation
    char *cur_buf = NULL;
    // # of bytes that have been read
    size_t bytes_read = 0;
    int n;

    if (!buf) {
        return 0;
    }

    cur_buf = buf;

    while (count > 0) {
        n = read(fd, cur_buf, count);

        if (n <= 0) {
            fprintf(stderr, "read error\n");
            break;

        } else {
            bytes_read += n;
            count -= n;
            cur_buf += n;
        }
    }

    return bytes_read;
}

/*
 * Connect to a socket server with the given IP address and port number
 * @param ip IP address
 * @param port port number
 * @return socket file descriptor on success and -1 on failure
 */
int connect_socket(char *ip, uint16_t port)
{
    // Create socket file descriptor
    int sockfd;
    if ((sockfd =  socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "TCP socket creation error\n");
        goto err;
    }

    // Initialize server socket address
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server address %s\n", ip);
        goto err;
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Fail to connect to %s:%hu\n", ip, port);
        goto err;
    }

    return sockfd;

err:
    if (sockfd >= 0) {
        close(sockfd);
    }
    return -1;
}

/*
 * Start a socket server listening on the given port number
 * @param listen_port port number to listen on
 * @return socket file descriptor on success and -1 on failure
 */
int start_socket_server(uint16_t listen_port)
{
    // Create socket file descriptor
    int sockfd = 0;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Socket creation error\n");
        goto err;
    }

    // To allow reuse of local addresses
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, &opt, sizeof(opt))) {
        fprintf(stderr, "Set socket option error\n");
        goto err;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(listen_port);
    if (bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Bind error\n");
        goto err;
    }

    if (listen(sockfd, 5) < 0) {
        fprintf(stderr, "Listen error\n");
        goto err;
    }

    return sockfd;

err:
    if (sockfd >= 0) {
        close(sockfd);
    }
    return -1;
}

/*
 * Accept a connection from a socket client
 * @param serv_sockfd socket file descriptor of the server
 * @return socket file descriptor on success and -1 on failure
 */
int accept_connection(int serv_sockfd)
{
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);
    int cli_sockfd = accept(serv_sockfd, (struct sockaddr*)&addr, (socklen_t*)&addrlen);
    return cli_sockfd;
}

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
                       unsigned int verb)
{
    const size_t max_ibverb_len = 16;
    const size_t max_num_qp_len = 4;
    const size_t max_qp_info_len = 64;
    const size_t max_msg_size = max_ibverb_len +
                                max_num_qp_len +
                                max_qp_info_len * num_qps * 2;
    char *send_msg = NULL;
    char *recv_msg = NULL;
    char local_gid[33] = {0};
    char remote_gid[33] = {0};

    int sockfd = connect_socket(ip, port);
    if (sockfd < 0) {
        return false;
    }

    send_msg = (char*)calloc(max_msg_size, sizeof(char));
    recv_msg = (char*)calloc(max_msg_size, sizeof(char));
    if (!send_msg || !recv_msg) {
        fprintf(stderr, "Fail to allocate send or recv message buffer\n");
        goto err;
    }

    sprintf(send_msg, "%s;%u", VERB_STRING[verb], num_qps);

    for (unsigned int i = 0; i < num_qps; i++) {
        struct conn_dest local_dest = connections[i].local_dest;
        struct conn_dest remote_dest = connections[i].rem_dest;
        inet_ntop(AF_INET6, &(local_dest.gid), local_gid, sizeof(local_gid));
        inet_ntop(AF_INET6, &(remote_dest.gid), remote_gid, sizeof(remote_gid));
        sprintf(send_msg + strlen(send_msg), ";%u,%u,%s;%u,%u,%s",
                local_dest.qpn,
                local_dest.psn,
                local_gid,
                remote_dest.qpn,
                remote_dest.psn,
                remote_gid);
    }
    sprintf(send_msg + strlen(send_msg), "&");

    size_t msg_len = strlen(send_msg) + 1;
    if (write_exact(sockfd, send_msg, msg_len) != msg_len) {
        fprintf(stderr, "Fail to send a %lu-byte message to the controller\n", msg_len);
        goto err;
    } else {
        printf("Send a %lu-byte message to the controller\n", msg_len);
    }

    if (read_exact(sockfd, recv_msg, msg_len) != msg_len ||
        strncmp(recv_msg, send_msg, msg_len) != 0) {
        fprintf(stderr, "Fail to receive the echo from the controller\n");
        goto err;
    } else {
        printf("Receive the echo from the controller\n");
    }

    free(send_msg);
    free(recv_msg);
    close(sockfd);
    return true;

err:
    free(send_msg);
    free(recv_msg);
    close(sockfd);
    return false;
}

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
                                  unsigned int verb_a_verb_b)
{
    const unsigned int num_qps = num_qps_verb_a + num_qps_verb_b;
    const size_t max_ibverb_len = 16;
    const size_t max_num_qp_len = 4;
    const size_t max_qp_info_len = 64;
    const size_t max_msg_size = max_ibverb_len +
                                max_num_qp_len +
                                max_qp_info_len * num_qps * 2;
    char *send_msg = NULL;
    char *recv_msg = NULL;
    char local_gid[33] = {0};
    char remote_gid[33] = {0};
    struct conn_dest local_dest, remote_dest;

    int sockfd = connect_socket(ip, port);
    if (sockfd < 0) {
        return false;
    }

    send_msg = (char*)calloc(max_msg_size, sizeof(char));
    recv_msg = (char*)calloc(max_msg_size, sizeof(char));
    if (!send_msg || !recv_msg) {
        fprintf(stderr, "Fail to allocate send or recv message buffer\n");
        goto err;
    }

    sprintf(send_msg, "%s;%u_%u", VERB_STRING[verb_a_verb_b], num_qps_verb_a, num_qps_verb_b);

    // QPN and PSN for QPs of verb A
    for (unsigned int i = 0; i < num_qps_verb_a; i++) {
        local_dest = connections_verb_a[i].local_dest;
        remote_dest = connections_verb_a[i].rem_dest;
        inet_ntop(AF_INET6, &(local_dest.gid), local_gid, sizeof(local_gid));
        inet_ntop(AF_INET6, &(remote_dest.gid), remote_gid, sizeof(remote_gid));
        sprintf(send_msg + strlen(send_msg), ";%u,%u,%s;%u,%u,%s",
                local_dest.qpn,
                local_dest.psn,
                local_gid,
                remote_dest.qpn,
                remote_dest.psn,
                remote_gid);
    }

    // QPN and PSN for QPs of verb B
    for (unsigned int i = 0; i < num_qps_verb_b; i++) {
        local_dest = connections_verb_b[i].local_dest;
        remote_dest = connections_verb_b[i].rem_dest;
        inet_ntop(AF_INET6, &(local_dest.gid), local_gid, sizeof(local_gid));
        inet_ntop(AF_INET6, &(remote_dest.gid), remote_gid, sizeof(remote_gid));
        sprintf(send_msg + strlen(send_msg), ";%u,%u,%s;%u,%u,%s",
                local_dest.qpn,
                local_dest.psn,
                local_gid,
                remote_dest.qpn,
                remote_dest.psn,
                remote_gid);
    }

    sprintf(send_msg + strlen(send_msg), "&");

    size_t msg_len = strlen(send_msg) + 1;
    if (write_exact(sockfd, send_msg, msg_len) != msg_len) {
        fprintf(stderr, "Fail to send a %lu-byte message to the controller\n", msg_len);
        goto err;
    } else {
        printf("Send a %lu-byte message to the controller\n", msg_len);
    }

    if (read_exact(sockfd, recv_msg, msg_len) != msg_len ||
        strncmp(recv_msg, send_msg, msg_len) != 0) {
        fprintf(stderr, "Fail to receive the echo from the controller\n");
        goto err;
    } else {
        printf("Receive the echo from the controller\n");
    }

    free(send_msg);
    free(recv_msg);
    close(sockfd);
    return true;

err:
    free(send_msg);
    free(recv_msg);
    close(sockfd);
    return false;
}

/*
 * Validate the buffer content
 * @param connections connection context array
 * @param num_qps # of queue pairs (QPs)
 * @return true on success and false on failure
 */
bool validate_buffer(struct conn_context *connections, unsigned int num_qps)
{
    bool result = true;

    for (unsigned int i = 0; i < num_qps; i++) {
        for (size_t j = 0; j < connections[i].data_buf_size; j++) {
            if (connections[i].data_buf[j] != (j & 0xFF)) {
                fprintf(stderr, "Invalid data in byte %lu of QP %u\n", j, connections[i].id);
                result = false;
                break;
            }
        }
    }

    return result;
}

/*
 * Exchange metadata with the server
 * @param serv_sockfd socket file descriptor for the server
 * @param connections connection context array
 * @param num_qps # of queue pairs (QPs)
 * @param exchange_memory true if exchanging memory region information
 * @return true on success and false on failure
 */
bool exchange_metadata_with_server(int serv_sockfd,
                                   struct conn_context *connections,
                                   unsigned int num_qps,
                                   bool exchange_memory)
{
    if (serv_sockfd < 0 || !connections) {
        return false;
    }

    size_t msg_size = sizeof(num_qps);
    // Exchange # of connections with the server
    if (write_exact(serv_sockfd, (char*)&num_qps, msg_size) != msg_size) {
        fprintf(stderr, "Fail to send num_qps\n");
        return false;
    }

    unsigned int serv_num_qps;
    msg_size = sizeof(serv_num_qps);
    if (read_exact(serv_sockfd, (char*)&serv_num_qps, msg_size) != msg_size) {
        fprintf(stderr, "Fail to receive num_qps from the server\n");
        return false;
    }

    if (num_qps != serv_num_qps) {
        fprintf(stderr, "The client and server have different numbers of QPs (%u and %u)\n",
                num_qps, serv_num_qps);
        return false;
    }

    struct conn_dest rem_dest;
    struct conn_mem rem_mem;
    size_t dest_size = sizeof(struct conn_dest);
    size_t mem_size = sizeof(struct conn_mem);

    printf("================ Exchange Metadata ================\n");

    // Exchange destination and memory with the server and connect QPs
    for (unsigned int i = 0; i < num_qps; i++) {
        if (write_exact(serv_sockfd, (char*)&(connections[i].local_dest), dest_size) != dest_size) {
            fprintf(stderr , "Fail to send destination information of QP %u\n", i);
            return false;
        }

        if (read_exact(serv_sockfd, (char*)&rem_dest, dest_size) != dest_size) {
            fprintf(stderr , "Fail to receive destination information of QP %u\n", i);
            return false;
        }

        connections[i].rem_dest = rem_dest;

        if (exchange_memory) {
            if (read_exact(serv_sockfd, (char*)&rem_mem, mem_size) != mem_size) {
                fprintf(stderr, "Fail to receive memory information of QP %u\n", i);
                return false;
            } else{
                connections[i].rem_mem = rem_mem;
            }
        }

        if (!connect_qp(&connections[i], &rem_dest)) {
            fprintf(stderr, "Fail to connect QP %u to the server\n", i);
            return false;
        }

        printf("Queue pair %u\n", i);
        printf("local addr: ");
        print_dest(&(connections[i].local_dest));
        printf("remote addr: ");
        print_dest(&rem_dest);
        if (exchange_memory) {
            printf("remote memory: ");
            print_mem(&rem_mem);
        }
    }

    return true;
}

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
                                              bool exchange_memory)
{
    bool ret = true;

    printf("===================== Verb A ======================\n");
    ret = exchange_metadata_with_server(serv_sockfd, connections_verb_a, num_qps_verb_a, exchange_memory);
    if (!ret) {
        return false;
    }

    printf("===================== Verb B ======================\n");
    ret = exchange_metadata_with_server(serv_sockfd, connections_verb_b, num_qps_verb_b, exchange_memory);
    printf("===================================================\n");
    return ret;
}

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
                                   bool exchange_memory)

{
    if (cli_sockfd < 0 || !connections) {
        return false;
    }

    // Exchange # of connections with the client
    unsigned int cli_num_qps;
    if (read_exact(cli_sockfd, (char*)&cli_num_qps, sizeof(cli_num_qps)) != sizeof(cli_num_qps)) {
        fprintf(stderr, "Fail to receive num_qps from the client\n");
        return false;
    }

    if (write_exact(cli_sockfd, (char*)&num_qps, sizeof(num_qps)) != sizeof(num_qps)) {
        fprintf(stderr, "Fail to send num_qps\n");
        return false;
    }

    if (num_qps != cli_num_qps) {
        fprintf(stderr, "The server and client have different numbers of QPs (%u and %u)\n",
                num_qps, cli_num_qps);
        return false;
    }

    struct conn_dest rem_dest;
    struct conn_mem local_mem;
    size_t dest_size = sizeof(struct conn_dest);
    size_t mem_size = sizeof(struct conn_mem);

    printf("================ Exchange Metadata ================\n");

    // Exchange per-connection address and memory information
    for (unsigned int i = 0; i < num_qps; i++) {
        if (read_exact(cli_sockfd, (char*)&rem_dest, dest_size) != dest_size) {
            fprintf(stderr , "Fail to read destination information of QP %u\n", i);
            return false;
        }
        connections[i].rem_dest = rem_dest;

        if (write_exact(cli_sockfd, (char*)&(connections[i].local_dest), dest_size) != dest_size) {
            fprintf(stderr , "Fail to send destination information of QP %u\n", i);
            return false;
        }

        if (!connect_qp(&connections[i], &rem_dest)) {
            fprintf(stderr, "Fail to connect QP %u to the client\n", i);
            return false;
        }

        if (exchange_memory) {
            local_mem.addr = (uint64_t)(connections[i].data_mr->addr);
            local_mem.key = connections[i].data_mr->rkey;
            if (write_exact(cli_sockfd, (char*)&local_mem, mem_size) != mem_size) {
                fprintf(stderr , "Fail to send destination information of QP %u\n", i);
                return false;
            }
        }

        printf("Queue pair %u\n", i);
        printf("local addr: ");
        print_dest(&(connections[i].local_dest));
        printf("remote addr: ");
        print_dest(&rem_dest);

        if (exchange_memory) {
            printf("local memory: ");
            print_mem(&local_mem);
        }
    }

    return true;
}

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
                                              bool exchange_memory)
{
    bool ret = true;

    printf("===================== Verb A ======================\n");
    ret = exchange_metadata_with_client(cli_sockfd, connections_verb_a, num_qps_verb_a, exchange_memory);
    if (!ret) {
        return false;
    }

    printf("===================== Verb B ======================\n");
    ret = exchange_metadata_with_client(cli_sockfd, connections_verb_b, num_qps_verb_b, exchange_memory);
    printf("===================================================\n");
    return ret;
}

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
                     bool use_event)
{
    unsigned int init_num_reqs = (tx_depth < iters)? tx_depth : iters;
    // # of QPs that have completed all the requests
    unsigned int num_complete_qps = 0;
    struct ibv_cq *cq = connections[0].dev_ctx->cq;
    struct ibv_comp_channel *channel = connections[0].dev_ctx->channel;
    struct ibv_wc wc;
    struct ibv_cq *ev_cq = NULL;
    void *ev_ctx = NULL;
    int ne;
    struct timeval start, end;

    if (gettimeofday(&start, NULL)) {
        fprintf(stderr, "Cannot get current time\n");
        return false;
    }

    for (unsigned int i = 0; i < num_qps; i++) {
        if (post_req(verb, &connections[i], init_num_reqs) != init_num_reqs) {
            fprintf(stderr, "Could not post %u %s requests on QP %u\n", init_num_reqs, VERB_STRING[verb], i);
            return false;
        }
        connections[i].post_reqs = init_num_reqs;
        connections[i].complete_reqs = 0;
    }

    // If any QPs have not completed all the requests
    while (num_complete_qps < num_qps) {
        // Wait for completion events.
        // If we use busy polling, this step is skipped.
        if (use_event) {
            if (ibv_get_cq_event(channel, &ev_cq, &ev_ctx)) {
                fprintf(stderr, "Fail to get cq_event\n");
                return false;
            }

            if (ev_cq != cq) {
                fprintf(stderr, "CQ event for unknown CQ %p\n", ev_cq);
                return false;
            }

            ibv_ack_cq_events(cq, 1);

            if (ibv_req_notify_cq(cq, 0)) {
                fprintf(stderr, "Cannot request CQ notification\n");
                return false;
            }
        }

        // Empty the completion queue
        while (true) {
            ne = ibv_poll_cq(cq, 1, &wc);
            if (ne < 0) {
                fprintf(stderr, "Fail to poll CQ (%d)\n", ne);
			    return false;

            } else if (ne == 0) {
                break;
            }

            if (!parse_wc(verb, &wc)) {
                fprintf(stderr, "Fail to get the completion event\n");
                return false;
            }

            unsigned int qp = wc.wr_id;
            connections[qp].complete_reqs++;

            if (connections[qp].complete_reqs == iters) {
                num_complete_qps++;
                if (gettimeofday(&(connections[qp].end_tv), NULL)) {
                    fprintf(stderr, "Cannot get current time\n");
		            return false;
                }
            } else if (connections[qp].post_reqs < iters) {
                if (post_req(verb, &connections[qp], 1) != 1) {
                    fprintf(stderr, "Could not post %s on QP %u\n", VERB_STRING[verb], qp);
                    return false;
                }
                connections[qp].post_reqs++;
            }
        }
    }

    if (gettimeofday(&end, NULL)) {
        fprintf(stderr, "Cannot get current time\n");
        return false;
    }

    float total_usec = timeval_subtract_to_usec(end, start);
    float total_bytes = num_qps * iters * connections[0].data_buf_size;
    float tput_gbps = total_bytes * 8 / total_usec / 1e3;
    printf("Throughput: %.2f Gbps\n", tput_gbps);

    for (unsigned int i = 0; i < num_qps; i++) {
        printf("QP %u: post %u requests, complete %u requests",
                i, connections[i].post_reqs, connections[i].complete_reqs);

        if (tx_depth == 1) {
            float usec = timeval_subtract_to_usec(connections[i].end_tv, start);
            printf(", %.2f usec/iter\n", usec / iters);
        } else {
            printf("\n");
        }
    }

    return true;
}

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
                                  bool use_event)
{
    // # of QPs that have compeleted in this iteration
    unsigned int num_complete_qps = 0;
    struct ibv_cq *cq = connections[0].dev_ctx->cq;
    struct ibv_comp_channel *channel = connections[0].dev_ctx->channel;
    struct ibv_wc wc;
    struct ibv_cq *ev_cq = NULL;
    void *ev_ctx = NULL;
    int ne;
    struct timeval start_tv, end_tv;
    uint64_t start_tsc, end_tsc;
    uint64_t *req_complete_tsc = NULL, *iter_start_tsc = NULL;

    iter_start_tsc = (uint64_t*)malloc(sizeof(uint64_t) * iters);
    req_complete_tsc = (uint64_t*)malloc(sizeof(uint64_t) * num_qps * iters);

    if (!iter_start_tsc || !req_complete_tsc) {
        fprintf(stderr, "Cannot allocate TSC array\n");
        free(iter_start_tsc);
        free(req_complete_tsc);
        return false;
    }

    if (gettimeofday(&start_tv, NULL)) {
        fprintf(stderr, "Cannot get current time\n");
        return false;
    }
    start_tsc = _rdtsc();

    for (unsigned int i = 0; i < iters; i++) {
        iter_start_tsc[i] = _rdtsc();
        for (unsigned int qp = 0; qp < num_qps; qp++) {
            if (post_req(verb, &connections[qp], 1) != 1) {
                fprintf(stderr, "Could not post a request on QP %u\n", qp);
                return false;
            } else {
                connections[qp].post_reqs++;
            }
        }

        num_complete_qps = 0;
        // If any QPs have not completed in this iteration
        while (num_complete_qps < num_qps) {
            // Wait for completion events.
            // If we use busy polling, this step is skipped.
            if (use_event) {
                if (ibv_get_cq_event(channel, &ev_cq, &ev_ctx)) {
                    fprintf(stderr, "Fail to get cq_event\n");
                    return false;
                }

                if (ev_cq != cq) {
                    fprintf(stderr, "CQ event for unknown CQ %p\n", ev_cq);
                    return false;
                }

                ibv_ack_cq_events(cq, 1);

                if (ibv_req_notify_cq(cq, 0)) {
                    fprintf(stderr, "Cannot request CQ notification\n");
                    return false;
                }
            }

            // Empty the completion queue
            while (true) {
                ne = ibv_poll_cq(cq, 1, &wc);
                if (ne < 0) {
                    fprintf(stderr, "Fail to poll CQ (%d)\n", ne);
			        return false;

                } else if (ne == 0) {
                    break;
                }

                if (!parse_wc(verb, &wc)) {
                    fprintf(stderr, "Fail to get the completion event\n");
                    return false;
                }

                unsigned int qp = wc.wr_id;
                req_complete_tsc[i * num_qps + qp] = _rdtsc();
                connections[qp].complete_reqs++;
                num_complete_qps++;
            }
        }
    }

    if (gettimeofday(&end_tv, NULL)) {
        fprintf(stderr, "Cannot get current time\n");
        return false;
    }
    end_tsc = _rdtsc();

    uint64_t total_usec = timeval_subtract_to_usec(end_tv, start_tv);
    uint64_t total_cycles = end_tsc - start_tsc;
    float cpu_freq = (float)total_cycles * 1e6 / total_usec;
    printf("Duration: %" PRIu64 " us\n", total_usec);
    printf("CPU frequency = %.2f MHz\n", cpu_freq / 1e6);

    float total_bytes = num_qps * iters * connections[0].data_buf_size;
    float tput_gbps = total_bytes * 8.0 / total_usec / 1e3;
    printf("Throughput: %.2f Gbps\n", tput_gbps);

    // Calculate message completion times
    for (unsigned int i = 0; i < iters; i++) {
        for (unsigned int q = 0; q < num_qps; q++) {
            req_complete_tsc[i * num_qps + q] -= iter_start_tsc[i];
        }
    }

    printf("Message completion times (us)\n");
    uint64_t total_req_complete_tsc, avg_req_complete_tsc;

    // Per-QP message completion time statistics
    for (unsigned int q = 0; q < num_qps; q++) {
        total_req_complete_tsc = 0;
        for (unsigned int i = 0; i < iters; i++) {
            total_req_complete_tsc += req_complete_tsc[i * num_qps + q];
        }

        avg_req_complete_tsc = total_req_complete_tsc / iters;
        printf("QP %2u: average %.2f ", q, (float)avg_req_complete_tsc * 1e6 / cpu_freq);

        printf("(");
        for (unsigned int i = 0; i < iters; i++) {
            if (i != 0) {
                printf(" ");
            }
            printf("%.2f", (float)req_complete_tsc[i * num_qps + q] * 1e6 / cpu_freq);
        }
        printf(")\n");
    }

    free(iter_start_tsc);
    free(req_complete_tsc);
    return true;
}

static volatile int keep_running = 1;

/*
 * Signal handler for Ctrl-C
 * @param sig Signal number
 * @return void
 */
static void stop_running(int sig)
{
    keep_running = 0;
}

// Structure for passing arguments to the print_stats thread
struct stats_arg {
    struct conn_context *connections;
    unsigned int num_connections;
    unsigned int period_sec;
};

/*
 * Print statistics periodically
 * @param arg Pointer to the stats_arg structure
 * @return void
 */
static void *print_stats(void *arg)
{
    struct stats_arg *ptr = (struct stats_arg*)arg;
    struct conn_context *connections = ptr->connections;
    unsigned int num_connections = ptr->num_connections;
    unsigned int period_sec = ptr->period_sec;
    size_t msg_size = connections[0].data_buf_size;
    struct timeval curr_tv;
    float elapsed_usec;
    size_t bytes;
    unsigned int complete_reqs;
    float qp_goodput, sum_goodput;

    printf("Print interval: %u sec\n", period_sec);
    printf("====================================================================\n");

    while (keep_running) {
        sleep(period_sec);
        sum_goodput = 0;

        for (unsigned int i = 0; i < num_connections; i++) {
            if (gettimeofday(&curr_tv, NULL)) {
                fprintf(stderr, "Cannot get current time\n");
                return NULL;
            }

            elapsed_usec = timeval_subtract_to_usec(curr_tv, connections[i].end_tv);
            complete_reqs = connections[i].complete_reqs;
            bytes = msg_size * (complete_reqs - connections[i].last_complete_reqs);
            connections[i].last_complete_reqs = complete_reqs;
            connections[i].end_tv = curr_tv;

            qp_goodput = bytes / elapsed_usec / 125;
            sum_goodput += qp_goodput;
            printf("QP %u: %.2f Gbps  ", i, qp_goodput);
        }
        printf("Sum: %.2f Gbps\n", sum_goodput);
    }

    return NULL;
}

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
                                bool use_event)
{
    unsigned int init_num_reqs = tx_depth;
    struct ibv_cq *cq = connections[0].dev_ctx->cq;
    struct ibv_comp_channel *channel = connections[0].dev_ctx->channel;
    struct ibv_wc wc;
    struct ibv_cq *ev_cq = NULL;
    void *ev_ctx = NULL;
    int ne;
    pthread_t print_thread;
    struct stats_arg arg = {.connections = connections,
                            .num_connections = num_qps,
                            .period_sec = 1};

    keep_running = 1;
    signal(SIGINT, stop_running);
    printf("Press Ctrl + C to terminate traffic generation\n");

    // Initialize
    for (unsigned int i = 0; i < num_qps; i++) {
        connections[i].post_reqs = 0;
        connections[i].complete_reqs = 0;
        connections[i].last_complete_reqs = 0;

        if (gettimeofday(&connections[i].end_tv, NULL)) {
            fprintf(stderr, "Cannot get current time for QP %u\n", i);
            return false;
        }
    }

    if (pthread_create(&print_thread, NULL, print_stats, (void*)&arg) != 0) {
        fprintf(stderr, "Fail to create the thread to print statistics\n");
        return false;
    }

    for (unsigned int i = 0; i < num_qps; i++) {
        if (post_req(verb, &connections[i], init_num_reqs) != init_num_reqs) {
            fprintf(stderr, "Could not post %u %s requests on QP %u\n", init_num_reqs, VERB_STRING[verb], i);
            return false;
        }
        connections[i].post_reqs = init_num_reqs;
    }

    while (keep_running) {
        // Wait for completion events.
        // If we use busy polling, this step is skipped.
        if (use_event) {
            if (ibv_get_cq_event(channel, &ev_cq, &ev_ctx)) {
                fprintf(stderr, "Fail to get cq_event\n");
                return false;
            }

            if (ev_cq != cq) {
                fprintf(stderr, "CQ event for unknown CQ %p\n", ev_cq);
                return false;
            }

            ibv_ack_cq_events(cq, 1);

            if (ibv_req_notify_cq(cq, 0)) {
                fprintf(stderr, "Cannot request CQ notification\n");
                return false;
            }
        }

        // Empty the completion queue
        while (true) {
            ne = ibv_poll_cq(cq, 1, &wc);
            if (ne < 0) {
                fprintf(stderr, "Fail to poll CQ (%d)\n", ne);
			    return false;

            } else if (ne == 0) {
                break;
            }

            if (!parse_wc(verb, &wc)) {
                fprintf(stderr, "Fail to get the completion event\n");
                return false;
            }

            unsigned int qp = wc.wr_id;
            connections[qp].complete_reqs++;
            if (post_req(verb, &connections[qp], 1) != 1) {
                fprintf(stderr, "Could not post %s on QP %u\n", VERB_STRING[verb], qp);
                return false;
            }
            connections[qp].post_reqs++;
        }
    }

    if (pthread_join(print_thread, NULL) != 0) {
        fprintf(stderr, "Fail to wait for print_thread to terminate\n");
        return false;
    }

    return true;
}

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
                                bool use_event)
{
    // total # of QPs
    unsigned int num_qps = num_qps_verb_a + num_qps_verb_b;
    // # of QPs that have completed all the requests
    unsigned int num_complete_qps_verb_a = 0;
    unsigned int num_complete_qps_verb_b = 0;
    unsigned int init_num_reqs = (tx_depth < iters)? tx_depth : iters;
    struct ibv_cq *cq = connections[0].dev_ctx->cq;
    struct ibv_comp_channel *channel = connections[0].dev_ctx->channel;
    struct ibv_wc wc;
    struct ibv_cq *ev_cq = NULL;
    void *ev_ctx = NULL;
    int ne;
    struct timeval start_tv_verb_a, end_tv_verb_a, start_tv_verb_b, end_tv_verb_b;

    if (gettimeofday(&start_tv_verb_a, NULL)) {
        fprintf(stderr, "Cannot get current time\n");
        return false;
    }

    for (unsigned int i = 0; i < num_qps_verb_a; i++) {
        if (post_req(verb_a, &connections[i], init_num_reqs) != init_num_reqs) {
            fprintf(stderr, "Could not post %u %s requests on QP %u\n",
                    init_num_reqs, VERB_STRING[verb_a], i);
            return false;
        }
        connections[i].post_reqs = init_num_reqs;
        connections[i].complete_reqs = 0;
    }

    if (gettimeofday(&start_tv_verb_b, NULL)) {
        fprintf(stderr, "Cannot get current time\n");
        return false;
    }

    for (unsigned int i = num_qps_verb_a; i < num_qps; i++) {
        if (post_req(verb_b, &connections[i], init_num_reqs) != init_num_reqs) {
            fprintf(stderr, "Could not post %u %s requests on QP %u\n",
                    init_num_reqs, VERB_STRING[verb_b], i);
            return false;
        }
        connections[i].post_reqs = init_num_reqs;
        connections[i].complete_reqs = 0;
    }

    // If any QPs have not completed all the requests
    while (num_complete_qps_verb_a < num_qps_verb_a ||
           num_complete_qps_verb_b < num_qps_verb_b) {
        // Wait for completion events.
        // If we use busy polling, this step is skipped.
        if (use_event) {
            if (ibv_get_cq_event(channel, &ev_cq, &ev_ctx)) {
                fprintf(stderr, "Fail to get cq_event\n");
                return false;
            }

            if (ev_cq != cq) {
                fprintf(stderr, "CQ event for unknown CQ %p\n", ev_cq);
                return false;
            }

            ibv_ack_cq_events(cq, 1);

            if (ibv_req_notify_cq(cq, 0)) {
                fprintf(stderr, "Cannot request CQ notification\n");
                return false;
            }
        }

        // Empty the completion queue
        while (true) {
            ne = ibv_poll_cq(cq, 1, &wc);
            if (ne < 0) {
                fprintf(stderr, "Fail to poll CQ (%d)\n", ne);
			    return false;

            } else if (ne == 0) {
                break;
            }

            unsigned int qp = wc.wr_id;
            unsigned int verb = (qp < num_qps_verb_a)? verb_a : verb_b;

            if (!parse_wc(verb, &wc)) {
                fprintf(stderr, "Fail to get the completion event\n");
                return false;
            }

            if (++connections[qp].complete_reqs == iters) {
                if (gettimeofday(&(connections[qp].end_tv), NULL)) {
                    fprintf(stderr, "Cannot get current time\n");
		            return false;
                }

                if (verb == verb_a && ++num_complete_qps_verb_a == num_qps_verb_a) {
                    end_tv_verb_a = connections[qp].end_tv;

                } else if (verb == verb_b && ++num_complete_qps_verb_b == num_qps_verb_b) {
                    end_tv_verb_b = connections[qp].end_tv;
                }

            } else if (connections[qp].post_reqs < iters) {
                if (post_req(verb, &connections[qp], 1) != 1) {
                    fprintf(stderr, "Could not post %s on QP %u\n", VERB_STRING[verb], qp);
                    return false;
                }
                connections[qp].post_reqs++;
            }
        }
    }

    // Results analysis for verb_a
    float total_usec_verb_a = timeval_subtract_to_usec(end_tv_verb_a, start_tv_verb_a);
    float total_bytes_verb_a = num_qps_verb_a * iters * connections[0].data_buf_size;
    float tput_gbps_verb_a = total_bytes_verb_a * 8 / total_usec_verb_a / 1e3;
    printf("%s Throughput: %.2f Gbps\n", VERB_STRING[verb_a], tput_gbps_verb_a);

    for (unsigned int i = 0; i < num_qps_verb_a; i++) {
        printf("QP %u: post %u requests, complete %u requests",
                i, connections[i].post_reqs, connections[i].complete_reqs);

        if (tx_depth == 1) {
            float usec = timeval_subtract_to_usec(connections[i].end_tv, start_tv_verb_a);
            printf(", %.2f usec/iter\n", usec / iters);
        } else {
            printf("\n");
        }
    }

    // Results analysis for verb_b
    float total_usec_verb_b = timeval_subtract_to_usec(end_tv_verb_b, start_tv_verb_b);
    float total_bytes_verb_b = num_qps_verb_b * iters * connections[0].data_buf_size;
    float tput_gbps_verb_b = total_bytes_verb_b * 8 / total_usec_verb_b / 1e3;
    printf("%s Throughput: %.2f Gbps\n", VERB_STRING[verb_b], tput_gbps_verb_b);

    for (unsigned int i = num_qps_verb_a; i < num_qps; i++) {
        printf("QP %u: post %u requests, complete %u requests",
                i, connections[i].post_reqs, connections[i].complete_reqs);

        if (tx_depth == 1) {
            float usec = timeval_subtract_to_usec(connections[i].end_tv, start_tv_verb_b);
            printf(", %.2f usec/iter\n", usec / iters);
        } else {
            printf("\n");
        }
    }

    return true;
}

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
                  bool use_event)
{
    // # of QPs that have compeleted all the requests
    unsigned int num_complete_qps = 0;
    struct ibv_cq *cq = connections[0].dev_ctx->cq;
    struct ibv_comp_channel *channel = connections[0].dev_ctx->channel;
    struct ibv_wc wc;
    struct ibv_cq *ev_cq = NULL;
    void *ev_ctx = NULL;
    int ne;

    // If any QPs have not completed all the requests
    while (num_complete_qps < num_qps) {
        // Wait for completion events.
        // If we use busy polling, this step is skipped.
        if (use_event) {
            if (ibv_get_cq_event(channel, &ev_cq, &ev_ctx)) {
				fprintf(stderr, "Fail to get cq_event\n");
				return false;
			}

            if (ev_cq != cq) {
                fprintf(stderr, "CQ event for unknown CQ %p\n", ev_cq);
				return false;
            }

            ibv_ack_cq_events(cq, 1);

            if (ibv_req_notify_cq(cq, 0)) {
                fprintf(stderr, "Cannot request CQ notification\n");
                return false;
            }
        }

        // Empty the completion queue
        while (true) {
            ne = ibv_poll_cq(cq, 1, &wc);
            if (ne < 0) {
                fprintf(stderr, "Fail to poll CQ (%d)\n", ne);
			    return false;

            } else if (ne == 0) {
                break;
            }

            if (!parse_recv_wc(&wc)) {
                fprintf(stderr, "Fail to get the completion event\n");
                return false;
            }

            unsigned int qp = wc.wr_id;
            connections[qp].complete_reqs++;

            if (connections[qp].complete_reqs == iters) {
                num_complete_qps++;
                if (gettimeofday(&(connections[qp].end_tv), NULL)) {
                    fprintf(stderr, "Cannot get current time\n");
		            return false;
                }
            } else if (connections[qp].post_reqs < iters) {
                if (post_recv(&connections[qp], 1) != 1) {
                    fprintf(stderr, "Could not post recv on QP %u\n", qp);
                    return false;
                }
                connections[qp].post_reqs++;
            }
        }
    }

    return true;
}

/*
 * Send a ready notification to the peer
 * @param sockfd socket file descriptor of the peer
 * @return true on success and false on failure
 */
bool send_ready(int sockfd)
{
    char buf[] = READY_MSG;
    size_t buf_size = sizeof(buf);
    return write_exact(sockfd, buf, buf_size) == buf_size;
}

/*
 * Wait for a ready notification from the peer
 * @param sockfd socket file descriptor of the peer
 * @return true on success and false on failure
 */
bool wait_ready(int sockfd)
{
    char buf[sizeof(READY_MSG)] = {0};
    size_t buf_size = sizeof(buf);
    return read_exact(sockfd, buf, buf_size) == buf_size && strcmp(buf, READY_MSG) == 0;
}

/*
 * Send a completion notification to the peer
 * @param sockfd socket file descriptor of the peer
 * @return true on success and false on failure
 */
bool send_completion(int sockfd)
{
    char buf[] = COMPLETE_MSG;
    size_t buf_size = sizeof(buf);
    return write_exact(sockfd, buf, buf_size) == buf_size;
}

/*
 * Wait for a completion notification from the peer
 * @param sockfd socket file descriptor of the peer
 * @return true on success and false on failure
 */
bool wait_completion(int sockfd)
{
    char buf[sizeof(COMPLETE_MSG)] = {0};
    size_t buf_size = sizeof(COMPLETE_MSG);
    return read_exact(sockfd, buf, buf_size) == buf_size && strcmp(buf, COMPLETE_MSG) == 0;
}

/*
 * Extract DSCP array from the string. Set *size to the number of DSCP values extracted.
 * DSCP values are between 0 and 63. Examples: "1-2,5-7" -> [1,2,5,6,7]
 *
 * @param str string to parse. Format: <d1>[-d2][,d3[-d4],...] where d1, d2, etc are DSCP values.
 * @param size pointer to the number of DSCP values extracted
 * @return pointer to the DSCP array on success and NULL on failure
 */
uint8_t* get_dscp_list(char *str, size_t *size)
{
    struct range *ranges = NULL;
    uint8_t *dscp_list = NULL;
    size_t num_ranges = 1;
    size_t num_dscps = 0;
    char *tmp = str;
    char delim_char = ',';
    char delim[2] = ",";
    char range_delim_char = '-';

    *size = 0;

    while (1) {
        char c = *tmp;

        if (c == '\0') {
            break;

        } else if (c == delim_char) {
            num_ranges++;

        } else if ((c < '0' || c > '9') && c != range_delim_char) {
            fprintf(stderr, "Unexpected char %c\n", c);
            goto err;
        }

        tmp++;
    }

    ranges = (struct range*)malloc(num_ranges * sizeof(struct range));
    if (!ranges) {
        fprintf(stderr, "Fail to allocate %lu ranges\n", num_ranges);
        goto err;
    }

    size_t id = 0;
    char *token = strtok(str, delim);

    while (token) {
        if (!str2range(token, &ranges[id])) {
            fprintf(stderr, "Fail to convert %s to a range\n", token);
            goto err;

        } else if (ranges[id].start < MIN_DSCP ||
                   ranges[id].start > MAX_DSCP ||
                   ranges[id].end < MIN_DSCP ||
                   ranges[id].end > MAX_DSCP ||
                   ranges[id].start > ranges[id].end) {
            fprintf(stderr, "Both start and end should be in [%d, %d]\n", MIN_DSCP, MAX_DSCP);
            fprintf(stderr, "And start should be no larger than end\n");
            goto err;

        } else {
            token = strtok(NULL, delim);
            id++;
        }
    }

    if (id != num_ranges) {
        fprintf(stderr, "Fail to get %lu DSCP ranges (actually %lu)\n", num_ranges, id);
        goto err;
    }

    num_dscps = 0;
    for (size_t i = 0; i < num_ranges; i++) {
        num_dscps += (ranges[i].end - ranges[i].start + 1);
    }

    dscp_list = (uint8_t*)malloc(num_dscps * sizeof(uint8_t));
    if (!dscp_list) {
        fprintf(stderr, "Fail to allocate %lu DSCP values\n", num_dscps);
        goto err;
    }

    id = 0;
    for (size_t i = 0; i < num_ranges; i++) {
        unsigned long start = ranges[i].start;
        unsigned long end = ranges[i].end;

        for (unsigned long j = start; j <= end; j++) {
            dscp_list[id++] = j;
        }
    }

    *size = num_dscps;
    free(ranges);
    return dscp_list;

err:
    free(ranges);
    free(dscp_list);
    return NULL;
}

/*
 * Extract range from the string and store the range in *r.
 * Examples: "1-2" -> {.start=1, .end=2}, "1" -> {.start=1, .end=1}
 *
 * @param str string to parse. Format: <d1>[-d2] where d1 and d2 are numbers.
 * @param r pointer to the range struct
 * @return true on success and false on failure
 */
bool str2range(char *str, struct range *r)
{
    char *tmp = str;
    char delim = '-';
    size_t delim_cnt = 0;

    while (1) {
        char c = *tmp;

        if (c == '\0') {
            break;

        } else if (c == delim) {
            delim_cnt++;

        } else if (c < '0' || c > '9') {
            fprintf(stderr, "Unexpected char %c\n", c);
            return false;
        }

        tmp++;
    }

    if (delim_cnt > 1) {
        fprintf(stderr, "There are %lu \'%c\' in %s\n", delim_cnt, delim, str);
        fprintf(stderr, "Range formats: a or a-b (a and b are unsigned integers)\n");
        return false;

    } else if (delim_cnt == 0) {
        unsigned long number = strtoul(str, NULL, 10);
        r->start = number;
        r->end = number;
        return true;

    } else if (sscanf(str, "%lu-%lu", &(r->start), &(r->end)) != 2) {
        fprintf(stderr, "Cannot parse %s\n", str);
        return false;

    } else {
        return true;
    }
}
