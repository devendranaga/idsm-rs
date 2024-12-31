#![allow(dead_code)]
#![allow(non_camel_case_types)]

#[non_exhaustive]
pub struct ProtocolTypes;

impl ProtocolTypes {
    pub const TCP           : u8 = 6;
    pub const ICMP6         : u8 = 58;
}
