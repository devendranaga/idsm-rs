#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::{events::{event_desc::event_desc, event_type::event_type, event_info::event_info}, lib::protocols::packet::packet::packet};

pub struct arp_hdr {
    hdr_type                : u16,
    protocol_type           : u16,
    hw_addr_len             : u8,
    protocol_len            : u8,
    op                      : u16,
    sender_hw_addr          : [u8; 6],
    sender_proto_addr       : u32,
    target_hw_addr          : [u8; 6],
    target_proto_addr       : u32
}

impl arp_hdr {
    pub const ARP_HDR_LEN : u32 = 28;
    pub const ARP_HW_ADDR_LEN : u32 = 6;
    pub const ARP_PROTOCOL_ADDR_LEN : u32 = 4;

    pub fn new() -> arp_hdr {
        let arp_h = arp_hdr {
            hdr_type            : 0,
            protocol_type       : 0,
            hw_addr_len         : 0,
            protocol_len        : 0,
            op                  : 0,
            sender_hw_addr      : [0; 6],
            sender_proto_addr   : 0,
            target_hw_addr      : [0; 6],
            target_proto_addr   : 0
        };
        arp_h
    }

    pub fn deserialize(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        p.deserialize_2_bytes(&mut self.hdr_type);
        p.deserialize_2_bytes(&mut self.protocol_type);
        p.deserialize_byte(&mut self.hw_addr_len);
        if (self.hw_addr_len as u32) != arp_hdr::ARP_HW_ADDR_LEN {
            evt_info.set(event_type::EVENT_TYPE_DENY,
                         event_desc::ARP_INVAL_HWADDR_LEN);
            return -1;
        }

        p.deserialize_byte(&mut self.protocol_len);
        if (self.protocol_len as u32) != arp_hdr::ARP_PROTOCOL_ADDR_LEN {
            evt_info.set(event_type::EVENT_TYPE_DENY,
                         event_desc::ARP_INVAL_PROTOCOL_LEN);
            return -1;
        }

        p.deserialize_2_bytes(&mut self.op);
        p.deserialize_mac(&mut self.sender_hw_addr);
        p.deserialize_4_bytes(&mut self.sender_proto_addr);
        p.deserialize_mac(&mut self.target_hw_addr);
        p.deserialize_4_bytes(&mut self.target_proto_addr);

        return 0;
    }
}