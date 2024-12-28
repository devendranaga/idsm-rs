#![allow(non_camel_case_types)]

use crate::{events::{event_desc::event_desc, event_info::event_info, event_type::event_type}, lib::protocols::packet::packet::packet};

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

    pub fn deserialize(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        // drop if packet is too short
        if !p.remaining_len_in_bounds(ipv6_hdr::IPV6_MIN_HDR_LEN) {
            evt_info.set(event_type::EVENT_TYPE_DENY,
                         event_desc::IPV6_SHORT_HDR_LEN);
            return -1;
        }

        // drop if version is invalid
        self.version = (p.buf[p.off] & 0xF0) >> 4;
        if self.version != ipv6_hdr::IPV6_VERSION as u8 {
            evt_info.set(event_type::EVENT_TYPE_DENY,
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
        p.deserialize_ip6addr(&mut self.dst_ip6addr);

        return 0;
    }
}
