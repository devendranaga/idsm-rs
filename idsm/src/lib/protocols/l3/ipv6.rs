// @brief - implements ipv6 serialize and deserialization
// @copyright - 2024-present Devendra Naga All rights reserved
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::{
    events::{
        event_desc::event_desc,
        event_mgr::event_mgr,
        event_type::event_type
    },
    lib::{c_lib::c_memcmp, protocols::packet::packet::packet}
};

// @brief - defines ipv6 header
pub struct ipv6_hdr {
    version             : u8, // 4 bits
    traffic_class       : u8, // 1 byte
    flow_lable          : u32, // 20 bits
    payload_len         : u16, // 2 bytes
    pub next_hdr        : u8, // 1 byte
    hop_limit           : u8, // 1 byte
    src_ip6addr         : [u8; 16], // 16 bytes
    dst_ip6addr         : [u8; 16], // 16 bytes
}

impl ipv6_hdr {
    pub const IPV6_MIN_HDR_LEN : u32 = 40;
    pub const IPV6_VERSION : u32 = 6;

    // @brief - get a cleared ipv6_hdr
    //
    // @return return cleared ipv6_hdr
    #[inline(always)]
    pub fn new() -> ipv6_hdr {
        let ipv6_h = ipv6_hdr {
            version             : 0,
            traffic_class       : 0,
            flow_lable          : 0,
            payload_len         : 0,
            next_hdr            : 0,
            hop_limit           : 0,
            src_ip6addr         : [0; 16],
            dst_ip6addr         : [0; 16]
        };
        ipv6_h
    }

    // @brief - chceck if an ipv6 address is valid
    //
    // @param [in] addr - ipv6 address
    //
    // @return true if valid address false if invalid
    fn is_valid_address(addr : &[u8]) -> bool {
        let z_ip6addr : [u8; 16] = [0; 16];

        if c_memcmp::c_memcmp(addr, &z_ip6addr, 16) {
            return false;
        }

        return true;
    }

    // @brief - deserialize ipv6 packet
    //
    // @param [inout] self - ipv6 header
    // @param [inout] p - packet
    // @param [out] evt_mgr - event mgr
    // @param [in] debug - frame debug
    pub fn deserialize(&mut self, p : &mut packet, evt_mgr : &mut event_mgr, debug : bool) -> i32 {
        // drop if packet is too short
        if !p.remaining_len_in_bounds(ipv6_hdr::IPV6_MIN_HDR_LEN) {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                         event_desc::IPV6_SHORT_HDR_LEN);
            return -1;
        }

        // drop if version is invalid
        self.version = (p.buf[p.off] & 0xF0) >> 4;
        if self.version != ipv6_hdr::IPV6_VERSION as u8 {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                         event_desc::IPV6_INVAL_VERSION);
            return -1;
        }

        self.traffic_class = ((p.buf[p.off] & 0x0F) << 4) | ((p.buf[p.off + 1] & 0xF0) >> 4);
        p.off += 1;

        self.flow_lable = (((p.buf[p.off] & 0x0F) as u32) << 16) as u32 |
                          ((p.buf[p.off + 1] as u32) << 8) as u32 |
                          (p.buf[p.off + 2]) as u32;
        p.off += 3;

        p.deserialize_2_bytes(&mut self.payload_len);
        p.deserialize_byte(&mut self.next_hdr);
        p.deserialize_byte(&mut self.hop_limit);
        p.deserialize_ip6addr(&mut self.src_ip6addr);
        if ipv6_hdr::is_valid_address(&self.src_ip6addr) == false {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                                    event_desc::IPV6_SRC_ADDR_INVALID);
            return -1;
        }

        p.deserialize_ip6addr(&mut self.dst_ip6addr);
        if ipv6_hdr::is_valid_address(&self.dst_ip6addr) == false {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                                    event_desc::IPV6_DST_ADDR_INVALID);
            return -1;
        }

        if debug { self.print(); }

        return 0;
    }

    // @brief - print ipv6 header
    //
    // @param [in] self - ipv6 packet
    pub fn print(&self) {
        println!("ipv6_hdr: ");
        println!("\t version: {}", self.version);
        println!("\t traffic_class: {}", self.traffic_class);
        println!("\t flow_label: {}", self.flow_lable);
        println!("\t payload_len: {}", self.payload_len);
        println!("\t next_hdr: {}", self.next_hdr);
        println!("\t hop_limit: {}", self.hop_limit);
        packet::print_ipv6("src_ip6addr: ", &self.src_ip6addr);
        packet::print_ipv6("dst_ip6addr: ", &self.dst_ip6addr);
    }
}
