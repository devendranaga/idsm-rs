#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::{
    events::{
        event_desc::event_desc,
        event_mgr::event_mgr,
        event_type::event_type
    },
    lib::protocols::packet::packet::packet
};

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

#[non_exhaustive]
pub struct icmp6_time_exceeded_codes;

impl icmp6_time_exceeded_codes {
    pub const HOP_LIM_EXCEEDED_IN_TRANSIT : u8 = 0;
    pub const FRAG_REASSEMBLY_TIME_EXCEEDED : u8 = 1;
}

#[non_exhaustive]
pub struct icmp6_parameter_problem;

impl icmp6_parameter_problem {
    pub const ERRONEOUS_HDR_FIELD_ENCOUNTERED : u32 = 0;
    pub const UNRECOG_NH_TYPE : u32 = 1;
    pub const UNRECOG_IPV6_OPT : u32 = 2;
}

pub struct icmp6_dest_unreachable {
    pub unused : u8,
    pub length : u8,
    pub next_hop_mtu : u16
}

impl icmp6_dest_unreachable {
    pub const DEST_UNREACHABLE_LEN : u32 = 4;

    #[inline(always)]
    pub fn new() -> icmp6_dest_unreachable {
        let d = icmp6_dest_unreachable {
            unused : 0,
            length : 0,
            next_hop_mtu : 0
        };
        d
    }

    pub fn deserialize(&mut self, p : &mut packet, evt_mgr : &mut event_mgr, debug : bool) -> i32 {
        if p.remaining_len_in_bounds(icmp6_dest_unreachable::DEST_UNREACHABLE_LEN) == false {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                                    event_desc::ICMP6_SHORT_DEST_UNREACH_HDR_LEN);
            return -1;
        }

        p.deserialize_byte(&mut self.unused);
        p.deserialize_byte(&mut self.length);
        p.deserialize_2_bytes(&mut self.next_hop_mtu);

        if debug { self.print(); }

        return 0;
    }

    pub fn print(&self) {
        log::info!("\t destination_unreachable: ");
        log::info!("\t\t unused: {}", self.unused);
        log::info!("\t\t length: {}", self.length);
        log::info!("\t\t next_hop_mtu: {}", self.next_hop_mtu);
    }
}

pub struct icmp6_hdr {
    icmp6_type          : u8,
    code                : u8,
    checksum            : u16,
    dest_unreach        : icmp6_dest_unreachable
}

impl icmp6_hdr {
    pub const ICMP6_MIN_HDR_LEN : u32 = 4;

    #[inline(always)]
    pub fn new() -> icmp6_hdr {
        let icmp6_h = icmp6_hdr {
            icmp6_type          : 0,
            code                : 0,
            checksum            : 0,
            dest_unreach        : icmp6_dest_unreachable::new()
        };
        icmp6_h
    }

    pub fn deserialize(&mut self, p : &mut packet, evt_mgr : &mut event_mgr, debug : bool) -> i32 {
        let ret : i32;

        if p.remaining_len_in_bounds(icmp6_hdr::ICMP6_MIN_HDR_LEN) {
            evt_mgr.insert_evt_info(
                                    event_type::EVENT_TYPE_DENY,
                                    event_desc::ICMP6_SHORT_HDR_LEN);
            return -1;
        }

        p.deserialize_byte(&mut self.icmp6_type);
        p.deserialize_byte(&mut self.code);
        p.deserialize_2_bytes(&mut self.checksum);

        match self.icmp6_type {
            icmp6_types::DEST_UNREACHABLE => ret = self.dest_unreach.deserialize(p, evt_mgr, debug),
            _ => ret = -1,
        }

        if ret < 0 {
            return ret;
        }

        if debug { self.print(); }

        return 0;
    }

    pub fn print(&self) {
        log::info!("icmp6_hdr: ");
        match self.icmp6_type {
            icmp6_types::DEST_UNREACHABLE => self.dest_unreach.print(),
            _ => (),
        }
    }
}
