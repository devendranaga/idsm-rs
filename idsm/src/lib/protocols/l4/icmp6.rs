#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::{events::{event_desc::event_desc, event_mgr::event_mgr, event_type::event_type}, lib::protocols::packet::packet::packet};

#[non_exhaustive]
pub struct icmp6_types;

impl icmp6_types {
    pub const DEST_UNREACHABLE : u8 = 1;
    pub const PKT_TOO_BIG : u8 = 2;
    pub const TIME_EXCEEDED : u8 = 3;
    pub const PARAM_PROBLEM : u8 = 4;
    pub const ECHO_REQ : u8 = 128;
    pub const ECHO_REPLY : u8 = 129;
    pub const MCAST_LISTENER_DISC : u8 = 130;
    pub const MCAST_LISTENER_REPORT : u8 = 131;
    pub const MCAST_LISTENER_DONE : u8 = 132;
    pub const ROUTER_SOL : u8 = 133;
    pub const ROUTER_ADV : u8 = 134;
    pub const NEIGHBOR_SOL : u8 = 135;
    pub const NEIGHBOR_ADV : u8 = 136;
    pub const REDIR_MSG : u8 = 137;
    pub const ROUTER_RENUMBERING : u8 = 138;
    pub const ICMP_NODE_INFO_QUERY : u8 = 139;
}

#[non_exhaustive]
pub struct icmp6_dest_unreach_codes;

impl icmp6_dest_unreach_codes {
    pub const NO_ROUTE_TO_DEST : u8 = 0;
    pub const COMM_IS_ADMINISTRATIVELY_PROHIBITED : u8 = 1;
    pub const BEYOND_SCOPE_OF_SRC_ADDR : u8 = 2;
    pub const ADDR_UNREACHABLE : u8 = 3;
    pub const PORT_UNREACHABLE : u8 = 4;
    pub const SRC_ADDR_FAILED_INGRESS_EGRESS_POLICY : u8 = 5;
    pub const REJECT_ROUTE_TO_DESTINATION : u8 = 6;
    pub const ERR_IN_SRC_ROUTING_HDR : u8 = 7;
}

pub struct icmp6_hdr {
    icmp6_type : u8,
    code : u8,
    checksum : u16
}

impl icmp6_hdr {
    pub const ICMP6_MIN_HDR_LEN : u32 = 4;

    #[inline(always)]
    pub fn new() -> icmp6_hdr {
        let icmp6_h = icmp6_hdr {
            icmp6_type : 0,
            code : 0,
            checksum : 0
        };
        icmp6_h
    }

    pub fn deserialize(&mut self, p : &mut packet, evt_mgr : &mut event_mgr, debug : bool) -> i32 {
        if p.remaining_len_in_bounds(icmp6_hdr::ICMP6_MIN_HDR_LEN) {
            evt_mgr.insert_evt_info(
                                    event_type::EVENT_TYPE_DENY,
                                    event_desc::ICMP6_SHORT_HDR_LEN);
            return -1;
        }

        p.deserialize_byte(&mut self.icmp6_type);
        p.deserialize_byte(&mut self.code);
        p.deserialize_2_bytes(&mut self.checksum);

        if debug { self.print(); }
        return 0;
    }

    pub fn print(&self) {
        println!("icmp6_hdr: ");
    }
}
