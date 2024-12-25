#![allow(non_camel_case_types)]

use crate::{events::{event_desc::event_desc, event_info::event_info, event_type::event_type}, lib::protocols::packet::packet::packet};

pub struct ipv4_hdr {
    version             : u8, // 4 bits
    ihl                 : u8, // 4 bits
    dscp                : u8, // 6 bits
    ecn                 : u8, // 2 bits
    total_len           : u16, // 16 bits
    id                  : u16, // 16 bits
    flags_res           : u8, // 1 bit
    flags_df            : u8, // 1 bit
    flags_mf            : u8, // 1 bit
    frag_off            : u16, // 13 bits
    ttl                 : u8, // 8 bits
    pub protocol        : u8, // 8 bits
    hdr_checksum        : u16, // 16 bits
    src_ipaddr          : u32, // 32 bits
    dst_ipaddr          : u32, // 32 bits
}

impl ipv4_hdr {
    pub const IPV4_MIN_HDR_LEN : u32 = 20;
    pub const IPV4_VERSION : u32 = 4;
    pub const IPV4_IHL_DEFAULT : u32 = 5;

    pub fn new() -> ipv4_hdr {
        let hdr = ipv4_hdr {
            version             : 0,
            ihl                 : 0,
            dscp                : 0,
            ecn                 : 0,
            total_len           : 0,
            id                  : 0,
            flags_res           : 0,
            flags_df            : 0,
            flags_mf            : 0,
            frag_off            : 0,
            ttl                 : 0,
            protocol            : 0,
            hdr_checksum        : 0,
            src_ipaddr          : 0,
            dst_ipaddr          : 0
        };
        hdr
    }

    pub fn deserialize(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        if ((p.pkt_len - p.off) as u32) < ipv4_hdr::IPV4_MIN_HDR_LEN {
            evt_info.set(event_type::EVENT_TYPE_DENY,
                         event_desc::IPV4_SHORT_HDR_LEN);
            return -1;
        }

        self.version = (p.buf[p.off] & 0xF0) >> 4;
        if (self.version as u32) != ipv4_hdr::IPV4_VERSION {
            evt_info.set(event_type::EVENT_TYPE_DENY,
                         event_desc::IPV4_INVAL_VERSION);
            return -1;
        }

        self.ihl = p.buf[p.off] & 0x0F;
        if (self.ihl as u32) != ipv4_hdr::IPV4_IHL_DEFAULT {
            evt_info.set(event_type::EVENT_TYPE_DENY,
                         event_desc::IPV4_IHL_INVAL);
            return -1;
        }

        p.off += 1;

        self.dscp = (p.buf[p.off] & 0xFC) >> 2;
        self.ecn = p.buf[p.off] & 0x03;
        p.off += 1;

        p.deserialize_2_bytes(&mut self.total_len);
        p.deserialize_2_bytes(&mut self.id);

        self.flags_res = !!(p.buf[p.off] & 0x80);
        self.flags_df = !!(p.buf[p.off] & 0x40);
        self.flags_mf = !!(p.buf[p.off] & 0x20);
        self.frag_off = (((p.buf[p.off] & 0x1F) as u32) << 8) as u16 | (p.buf[p.off + 1]) as u16;
        p.off += 2;

        p.deserialize_byte(&mut self.ttl);
        p.deserialize_byte(&mut self.protocol);
        p.deserialize_2_bytes(&mut self.hdr_checksum);
        p.deserialize_4_bytes(&mut self.src_ipaddr);
        p.deserialize_4_bytes(&mut self.dst_ipaddr);

        return 0;
    }

    pub fn print(&self) {
        println!("ipv4_hdr: ");
        println!("\t version: {}", self.version);
        println!("\t ihl: {}", self.ihl);
        println!("\t protocol: {}", self.protocol);
        println!("\t src_ipaddr: {}.{}.{}.{}",
                                (self.src_ipaddr & 0xFF000000) >> 24,
                                (self.src_ipaddr & 0x00FF0000) >> 16,
                                (self.src_ipaddr & 0x0000FF00) >> 8,
                                (self.src_ipaddr & 0x000000FF));
    }
}
