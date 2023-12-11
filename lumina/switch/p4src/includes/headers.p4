// -----------------------------
// Headers
// root: ../inject_switch.p4
// -----------------------------

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn_flag;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header vlan_h {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    ether_type_t vlan_eth_type;
}

// Address Resolution Protocol -- RFC 6747
header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    mac_addr_t sender_mac;
    ipv4_addr_t sender_ip;
    mac_addr_t target_mac;
    ipv4_addr_t target_ip;
}

header roce_h {
    bit<8>  opcode;
    bit<1>  solicited_event;
    bit<1>  mig_req;
    bit<2>  pad_count;
    bit<4>  header_version;
    bit<16> partition_key;
    bit<8>  reserved_0;
    bit<24> destination_qp;
    bit<1>  aknowledge_request;
    bit<7>  reserved_1;
    bit<24> packet_seqnum;
}

struct empty_header_t {}

struct empty_metadata_t {}