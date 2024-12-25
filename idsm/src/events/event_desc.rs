#![allow(non_camel_case_types)]

#[non_exhaustive]
pub struct event_desc;

impl event_desc {
    pub const ETH_SHORT_HDR_LEN         : u32 = 0x1000;
    pub const ETH_SRC_ZERO_MAC          : u32 = 0x1001;
    pub const ETH_SRC_BROADCAST_MAC     : u32 = 0x1002;

    pub const IPV4_SHORT_HDR_LEN        : u32 = 0x2000;
    pub const IPV4_INVAL_VERSION        : u32 = 0x2001;
    pub const IPV4_IHL_INVAL            : u32 = 0x2002;

    pub const TCP_SHORT_HDR_LEN         : u32 = 0x3000;
    pub const TCP_SRC_PORT_ZERO         : u32 = 0x3001;
    pub const TCP_DST_PORT_ZERO         : u32 = 0x3002;

    pub const VLAN_ID_RESERVED          : u32 = 0x4000;

    pub const ARP_INVAL_HWADDR_LEN      : u32 = 0x5000;
    pub const ARP_INVAL_PROTOCOL_LEN    : u32 = 0x5001;
    pub const NONE                      : u32 = 0xDEADBEEF;
}
