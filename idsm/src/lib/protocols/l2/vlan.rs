#![allow(non_camel_case_types)]

use crate::{events::{event_desc::event_desc, event_info::event_info, event_type::event_type}, lib::protocols::packet::packet::packet};

pub struct vlan_hdr {
    pcp             : u8, // 3 bits
    dei             : u8, // 1 bit
    vid             : u16, // 12 bits
    pub ethertype   : u16 // 16 bits
}

impl vlan_hdr {
    const VLAN_RESERVED : [u16; 2] = [0, 4096];

    pub fn new() -> vlan_hdr {
        let vh = vlan_hdr {
            pcp             : 0,
            dei             : 0,
            vid             : 0,
            ethertype       : 0
        };
        vh
    }

    pub fn deserialize(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        self.pcp = (p.buf[p.off] & 0xE0) >> 5;
        self.dei = !!(p.buf[p.off] & 0x10);
        self.vid = (((p.buf[p.off] as u32) & 0x0F) << 8) as u16 | p.buf[p.off + 1] as u16;
        p.off += 2;

        for vlan_id in vlan_hdr::VLAN_RESERVED {
            if self.vid == vlan_id {
                evt_info.set(event_type::EVENT_TYPE_DENY,
                             event_desc::VLAN_ID_RESERVED);
                return -1;
            }
        }

        p.deserialize_2_bytes(&mut self.ethertype);

        return 0;
    }
}