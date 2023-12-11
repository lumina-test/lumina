#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#if __TARGET_TOFINO__ == 1
typedef bit<3> mirror_type_t;
#else
typedef bit<4> mirror_type_t;
#endif

#include "includes/headers.p4"

typedef bit<8>  pkt_type_t;
const pkt_type_t PKT_TYPE_NORMAL    = 1;
const pkt_type_t PKT_TYPE_MIRROR_IG = 2;
const mirror_type_t MIRROR_TYPE_I2E = 1;
const bit<8> NUM_MIRROR_HOSTS       = 2;

const ether_type_t ETHERTYPE_VLAN  = 16w0x8100;
const ether_type_t ETHERTYPE_IPV4  = 16w0x0800;
const ether_type_t ETHERTYPE_ARP   = 16w0x0806;
const bit<8>  IP_PROTOCOLS_TCP     = 6;
const bit<8>  IP_PROTOCOLS_UDP     = 17;
const bit<16> UDP_DST_PORT_ROCE    = 4791;
const bit<16> ARP_HW_TYPE_ETHERNET = 0x0001;
const bit<16> ARP_PROTOCOL_IPV4    = 0x0800;

const bit<8> EVENT_TYPE_DROP = 1;
const bit<8> EVENT_TYPE_ECN  = 2;
const bit<8> EVENT_TYPE_BIT_ERROR = 3;

struct pair {
    bit<32> first;
    bit<32> second;
}

header bridged_metadata_h {
    pkt_type_t pkt_type;
}

header ig_mirror_h {
    pkt_type_t  pkt_type;
    bit<8>  event_type;
    bit<48>  global_timestamp;
    bit<48>  switch_seqnum;
}

struct metadata_t {
    MirrorId_t ig_mir_ses;
    bit<8>  event_type;
    pkt_type_t pkt_type;
    bit<16>  iteration;
    bit<8>   mirror_index;
    bit<8>   is_first_pkt_in_msg;
    bit<48>  global_timestamp;
    bit<48>  switch_seqnum;
};

struct headers_t {
    ig_mirror_h ig_mirror_md;
    bridged_metadata_h bridged_md;
    ethernet_h ethernet;
    vlan_h vlan;
    arp_h arp;
    ipv4_h ipv4;
    udp_h udp;
    roce_h roce;
}

// ---------------------------------
// Tofino Parser
// ---------------------------------
parser TofinoIngressParser(packet_in pkt,
                           out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        // * Parse ingress intrinsic metadata
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // * Parse resubmitted packet here.
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

// ---------------------------------
// Ingress parser
// ---------------------------------
parser SwitchIngressParser(packet_in pkt,
                           out headers_t hdr,
                           out metadata_t ig_md,
                           out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_VLAN: parse_vlan;
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition select(hdr.vlan.vlan_eth_type) {
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition select (hdr.arp.hw_type, hdr.arp.proto_type) {
            (ARP_HW_TYPE_ETHERNET, ARP_PROTOCOL_IPV4) : accept;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            UDP_DST_PORT_ROCE: parse_roce;
            default: accept;
        }
    }

    state parse_roce {
        pkt.extract(hdr.roce);
        transition accept;
    }
}

// -------------------------------------
// Ingress Deparser
// -------------------------------------
control SwitchIngressDeparser(packet_out pkt,
                              inout headers_t hdr,
                              in metadata_t ig_md,
                              in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Checksum() ipv4_checksum;
    Mirror() mirror;
    apply {
        // * I2E mirror
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_I2E) {
            mirror.emit<ig_mirror_h>(ig_md.ig_mir_ses, {ig_md.pkt_type, ig_md.event_type, ig_md.global_timestamp, ig_md.switch_seqnum});
        }
        pkt.emit(hdr);
    }
}

// -------------------------------------
// Ingress
// -------------------------------------
control SwitchIngress(inout headers_t hdr,
                      inout metadata_t ig_md,
                      in ingress_intrinsic_metadata_t ig_intr_md,
                      in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                      inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                      inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    action nop() {}

    // * check if the packet is the first packet in its message
    action check_first_pkt_in_msg(bit<8> is_first_pkt_in_msg) {
        ig_md.is_first_pkt_in_msg = is_first_pkt_in_msg;
    }
    table check_first_pkt_in_msg_table {
        key = {
            hdr.roce.destination_qp: exact;
            ig_intr_md.ingress_port: exact;
            hdr.roce.packet_seqnum: exact;
        }
        actions = {
            check_first_pkt_in_msg;
        }
        default_action=check_first_pkt_in_msg(0);
        size = 4096;
    }

    // * maintain and return the current iteration based on the packet sequence number
    const bit<32> next_roceseq_reg_size = (1<< 10) - 1;
    // * next_roceseq_reg.first: expected next sequence number 
    // * next_roceseq_reg.second: current iter number           
    Register<pair, bit<16>>(next_roceseq_reg_size) next_roceseq_reg;
    RegisterAction<pair, bit<16>, bit<32>>(next_roceseq_reg) update_next_roceseq_reg_action = {
        void apply(inout pair value, out bit<32> ret_value) {
            // * If the packet's seqnum is out-of-order (retransmit), iter ++
            if ((bit<32>)hdr.roce.packet_seqnum != value.first) {
                value.second = value.second + 1;
            }
            value.first = (bit<32>)hdr.roce.packet_seqnum + 1;
            ret_value = value.second;
        }
    };

    RegisterAction<pair, bit<16>, bit<32>>(next_roceseq_reg) reset_next_roceseq_reg_action = {
        void apply(inout pair value, out bit<32> ret_value) {
            // * If the packet's seqnum is out-of-order (retransmit), iter ++
            // * Otherwise, iter = 1 because it's the first pkt of a msg
            if ((bit<32>)hdr.roce.packet_seqnum == value.first) {
                value.second = 1;
            }
            else {
                value.second = value.second + 1;
            }
            value.first = (bit<32>)hdr.roce.packet_seqnum + 1;
            ret_value = value.second;
        }
    };
    action update_next_roceseq(bit<16> index) {
        ig_md.iteration = (bit<16>)update_next_roceseq_reg_action.execute(index);
    }
    action reset_next_roceseq(bit<16> index) {
        ig_md.iteration = (bit<16>)reset_next_roceseq_reg_action.execute(index);
    }
    table update_next_roceseq_table {
        key = {
            hdr.roce.destination_qp: exact;
            ig_intr_md.ingress_port: exact;
            ig_md.is_first_pkt_in_msg: exact;
        }
        actions = {
            update_next_roceseq;
            reset_next_roceseq;
        }
        size = 2048;
    }

    action drop() {
        ig_md.event_type = EVENT_TYPE_DROP;
        ig_dprsr_md.drop_ctl = 0x1;
    }
    action mark_ecn() {
        ig_md.event_type = EVENT_TYPE_ECN;
        hdr.ipv4.ecn_flag = 0b11;
    }
    action bit_error() {
        ig_md.event_type = EVENT_TYPE_BIT_ERROR;
        hdr.ipv4.identification = hdr.ipv4.identification ^ 0xffff;
    }
    table inject_event_table {
        key = {
            hdr.roce.destination_qp: exact;
            ig_intr_md.ingress_port: exact;
            hdr.roce.packet_seqnum:  exact;
            ig_md.iteration: exact;
        }
        actions = {
            drop;
            mark_ecn;
            bit_error;
            nop;
        }
        default_action = nop;
        size = 8192;
    }

    // * Config I2E mirror
    action set_mirror_ig(MirrorId_t ig_mir_ses) {
        ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
        ig_md.ig_mir_ses = ig_mir_ses;
        // * Add pkt_type to the mirror header
        ig_md.pkt_type = PKT_TYPE_MIRROR_IG;
    }
    table set_mirror_ig_table {
        key = {
            ig_md.mirror_index: exact;
        }
        actions = {
            set_mirror_ig;
            nop;
        }
        default_action = nop;
        size = 1024;
    }

    Register<bit<32>, bit<2>>(1) sequence_reg;
    RegisterAction<bit<32>, bit<2>, bit<32>>(sequence_reg) sequence_reg_action = {
        void apply(inout bit<32> value, out bit<32> ret_value) {
            if (value < 0x7fffffff) {
                value = value + 1;
            }
            else {
                value = 1;
            }
            ret_value = value;
        }
    };

    const bit<32> ingress_counter_reg_size = (1 << 10) - 1;
    Register<bit<32>, bit<16>>(ingress_counter_reg_size) ingress_counter_reg;
    RegisterAction<bit<32>, bit<16>, bit<32>>(ingress_counter_reg) ingress_counter_reg_action = {
        void apply(inout bit<32> value, out bit<32> ret_value) {
            if (value < 0x7fffffff) {
                value = value + 1;
            }
            else {
                value = 1;
            }
        }
    };
    action ingress_counter(bit<16> ingress_counter_index) {
        ingress_counter_reg_action.execute(ingress_counter_index);
    }
    table ingress_counter_table {
        key = {
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            ingress_counter;
            nop;
        }
        default_action = nop;
        size = 1024;
    }

    action arp_hit(mac_addr_t resp_mac) {
        ipv4_addr_t req_ip = hdr.arp.sender_ip;
        mac_addr_t req_mac = hdr.arp.sender_mac;
        ipv4_addr_t resp_ip = hdr.arp.target_ip;

        // Swap source and destination IP and MAC
        hdr.ethernet.dst_addr = req_mac;
        hdr.ethernet.src_addr = resp_mac;

        hdr.arp.opcode = 0x0002;
        hdr.arp.sender_mac = resp_mac;
        hdr.arp.sender_ip = resp_ip;
        hdr.arp.target_mac = req_mac;
        hdr.arp.target_ip = req_ip;

        // bounce back the ARP packet
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }
    table arp_table {
        key = {
            hdr.arp.opcode : exact;
            hdr.arp.target_ip : exact;
        }

        actions = {
            arp_hit;
            @defaultonly nop;
        }

        const default_action = nop;
        size = 2048;
    }

    // * Do l2 forwarding, and carry info in the bridged header
    action l2_forward(PortId_t dst_port) {
        ig_tm_md.ucast_egress_port = dst_port;
        hdr.bridged_md.setValid();
        hdr.bridged_md.pkt_type = PKT_TYPE_NORMAL;
    }
    table forward_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            l2_forward;
        }
        size = 1024;
    }
    const bit<32> mirror_index_reg_size = 1;
    Register<bit<8>, bit<8>>(mirror_index_reg_size) mirror_index_reg;
    RegisterAction<bit<8>, bit<8>, bit<8>>(mirror_index_reg) mirror_index_reg_action = {
        void apply(inout bit<8> value, out bit<8> ret_value) {
            if (value >= NUM_MIRROR_HOSTS - 1) {
                value = 0;
            }
            else {
                value = value + 1;
            }
            ret_value = value;
        }
    };
    apply {
        // * If it is a ROCE packet, inject events based on the table entries
        if (hdr.roce.isValid()) {
            // * Check if the packet is the first packet in a message
            check_first_pkt_in_msg_table.apply();

            // * Maintain the iteration number by checking the roce sequence number
            update_next_roceseq_table.apply();

            // * Inject event according to <qpn, psn, iteration>
            inject_event_table.apply();

            // * Do I2E mirror
            //   Mirror the packets to the two mirror servers evenly (round-robin)
            ig_md.mirror_index = mirror_index_reg_action.execute(0);
            
            // * Get the switch sequence number and timestamp 
            //   Will store them into the mirror metadata
            ig_md.switch_seqnum[31:0] = sequence_reg_action.execute(0);
            ig_md.switch_seqnum[47:32] = 16w0;
            ig_md.global_timestamp = ig_prsr_md.global_tstamp;
            set_mirror_ig_table.apply();

            // * Count ROCE packets for each ingress port
            ingress_counter_table.apply();
        }
        
        // * Do l2 forwarding
        if (hdr.arp.isValid()) {
            arp_table.apply();
            ig_tm_md.bypass_egress = 1w1;
        } else {
            forward_table.apply();
        }
    }
}


// ---------------------------------
// Egress parser
// ---------------------------------
parser SwitchEgressParser(packet_in pkt,
                          out headers_t hdr,
                          out metadata_t eg_md,
                          out egress_intrinsic_metadata_t eg_intr_md) {
    TofinoEgressParser() tofino_parser;
    state start {
        // * Parse egress intrinsic metadata
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_metadata;
    }

    state parse_metadata {
        // * Check if the packet is a ingress mirrored packet or a normal packet 
        bridged_metadata_h mirror_md = pkt.lookahead<bridged_metadata_h>();
        transition select(mirror_md.pkt_type) {
            PKT_TYPE_MIRROR_IG: parse_mirror_ig_md;
            PKT_TYPE_NORMAL: parse_bridged_md;
            default: accept;
        }
    }

    state parse_mirror_ig_md {
        // * Extract metadata carried in the mirror header
        pkt.extract(hdr.ig_mirror_md);
        transition parse_ethernet;
    }

    state parse_bridged_md {
        // * Extract bridged header
        bridged_metadata_h eg_bridged_md;
        pkt.extract(eg_bridged_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_VLAN: parse_vlan;
            default: parse_ipv4;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition parse_udp;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            UDP_DST_PORT_ROCE: parse_roce;
            default: accept;
        }
    }

    state parse_roce {
        pkt.extract(hdr.roce);
        transition accept;
    }
}

// ---------------------------------
// Egress parser
// ---------------------------------
control SwitchEgressDeparser(packet_out pkt,
                             inout headers_t hdr,
                             in metadata_t eg_md,
                             in egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md) {
    Checksum() ipv4_checksum;
    Mirror() mirror;
    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn_flag,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        pkt.emit(hdr);
    }
}

// ---------------------------------
// Egress
// ---------------------------------
control SwitchEgress(inout headers_t hdr,
                     inout metadata_t eg_md,
                     in    egress_intrinsic_metadata_t                 eg_intr_md,
                     in    egress_intrinsic_metadata_from_parser_t     eg_intr_md_from_prsr,
                     inout egress_intrinsic_metadata_for_deparser_t    eg_intr_dprsr_md,
                     inout egress_intrinsic_metadata_for_output_port_t eg_intr_oprt_md) {
    action nop() {}
    const bit<32> egress_counter_reg_size = (1 << 10) - 1;
    Register<bit<32>, bit<16>>(egress_counter_reg_size) egress_counter_reg;
    RegisterAction<bit<32>, bit<16>, bit<32>>(egress_counter_reg) egress_counter_reg_action = {
        void apply(inout bit<32> value, out bit<32> ret_value) {
            if (value < 0x7fffffff) {
                value = value + 1;
            }
            else {
                value = 1;
            }
        }
    };
    action egress_counter(bit<16> egress_counter_index) {
        egress_counter_reg_action.execute(egress_counter_index);
    }
    table egress_counter_table {
        key = {
            eg_intr_md.egress_port: exact;
        }
        actions = {
            egress_counter;
            nop;
        }
        default_action = nop;
        size = 1024;
    }

    Random<bit<16>>() random_value;
    // * Retrieve switch seqnum and timestamp from mirror metadata
    // * Tag sequence number and timestamp onto the packets, 
    // *     change the udp dst port, so that it can escape 
    // *     from ROCE filter at the endhost
    // * hdr.ethernet.src_addr = sequence number
    // * hdr.ethernet.dst_addr = timestamp
    action add_timestamp(bit<16> dst_port) {
        // * source MAC for sequence
        hdr.ethernet.src_addr = hdr.ig_mirror_md.switch_seqnum;
        // * destination MAC for timestamp
        hdr.ethernet.dst_addr = hdr.ig_mirror_md.global_timestamp;
        // * destroy ROCE header
        hdr.udp.dst_port = dst_port;
    }
    table add_timestamp_table {
        actions = {
            add_timestamp;
        }
    }

    apply {
        if (hdr.ig_mirror_md.isValid()) {
            // * If it is a I2E mirrored packet, mark drop in some field (ipv4.ttl)
            hdr.ipv4.ttl = (bit<8>) hdr.ig_mirror_md.event_type;
            if (hdr.ig_mirror_md.event_type == EVENT_TYPE_BIT_ERROR) {
                hdr.ipv4.identification = hdr.ipv4.identification ^ 0xffff;
            }
            // * Tag timestamp, seqnumber in MAC address field, change udp_dst_port
            add_timestamp_table.apply();
            // * store the original udp.src_port in udp.checksum
            hdr.udp.checksum = hdr.udp.src_port;
            // * disturb the RSS by changing the udp.src_port
            hdr.udp.src_port = random_value.get();
            hdr.ig_mirror_md.setInvalid();
        }
        // * Count the egress ROCE packet for each port
        if (hdr.roce.isValid())
            egress_counter_table.apply();
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;