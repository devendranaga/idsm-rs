// @brief - describes the list of events found by the idsm
// @copyright - Devendra Naga 2024-present all rights reserved
#![allow(dead_code)]
#![allow(non_camel_case_types)]

#[non_exhaustive]
pub struct event_desc;

// defines a list of events found by the firewall
impl event_desc {
    // list of events related to Ethernet
    pub const ETH_SHORT_HDR_LEN         : u32 = 0x1000;
    pub const ETH_SRC_ZERO_MAC          : u32 = 0x1001;
    pub const ETH_SRC_BROADCAST_MAC     : u32 = 0x1002;

    // list of events related to IPv4
    pub const IPV4_SHORT_HDR_LEN        : u32 = 0x2000;
    pub const IPV4_INVAL_VERSION        : u32 = 0x2001;
    pub const IPV4_IHL_INVAL            : u32 = 0x2002;
    pub const IPV4_RESERVED_SET         : u32 = 0x2003;

    // list of events related to TCP
    pub const TCP_SHORT_HDR_LEN         : u32 = 0x3000;
    pub const TCP_SRC_PORT_ZERO         : u32 = 0x3001;
    pub const TCP_DST_PORT_ZERO         : u32 = 0x3002;
    pub const TCP_FLAGS_ALL_ZERO        : u32 = 0x3003;
    pub const TCP_FLAGS_SYN_FIN_SET     : u32 = 0x3004;
    pub const TCP_UNKNOWN_OPT           : u32 = 0x3005;

    // list of events related to VLAN
    pub const VLAN_ID_RESERVED          : u32 = 0x4000;

    // list of events related to ARP
    pub const ARP_INVAL_HWADDR_LEN      : u32 = 0x5000;
    pub const ARP_INVAL_PROTOCOL_LEN    : u32 = 0x5001;
    pub const ARP_OP_INVALID            : u32 = 0x5002;

    pub const IPV6_SHORT_HDR_LEN        : u32 = 0x6000;
    pub const IPV6_INVAL_VERSION        : u32 = 0x6001;
    pub const IPV6_SRC_ADDR_INVALID     : u32 = 0x6002;
    pub const IPV6_DST_ADDR_INVALID     : u32 = 0x6003;

    pub const ICMP6_SHORT_HDR_LEN       : u32 = 0x7000;
    pub const NONE                      : u32 = 0xDEADBEEF;
}
