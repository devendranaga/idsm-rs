#![allow(non_camel_case_types)]

#[non_exhaustive]
pub struct event_desc;

impl event_desc {
    pub const ETH_SHORT_HDR_LEN         : u32 = 0x1000;
    pub const ETH_SRC_ZERO_MAC          : u32 = 0x1001;
    pub const ETH_SRC_BROADCAST_MAC     : u32 = 0x1002;

    pub const IPV4_SHORT_HDR_LEN        : u32 = 0x2000;

    pub const TCP_SHORT_HDR_LEN         : u32 = 0x3000;
    pub const NONE                      : u32 = 0xDEADBEEF;
}
