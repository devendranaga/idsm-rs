// @brief - implements VLAN frame serialization and deserialization.
// @copyright - Devendra Naga 2024-present All rights reserved.
#![allow(non_camel_case_types)]

use crate::{
    events::{
        event_desc::event_desc, event_mgr::event_mgr, event_type::event_type
    },
    lib::protocols::packet::packet::packet
};

// @brief - implements VLAN header struct.
pub struct vlan_hdr {
    pcp             : u8, // 3 bits
    dei             : u8, // 1 bit
    vid             : u16, // 12 bits
    pub ethertype   : u16 // 16 bits
}

impl vlan_hdr {
    const VLAN_RESERVED : [u16; 2] = [0, 4096];

    // @brief - zero initialize the VLAN header.
    //
    // @return zero initialized VLAN header.
    pub fn new() -> vlan_hdr {
        let vh = vlan_hdr {
            pcp             : 0,
            dei             : 0,
            vid             : 0,
            ethertype       : 0
        };
        vh
    }

    // @brief - deserialize VLAN frame.
    //
    // @param [inout] self - vlan header
    // @param [inout] p - packet
    // @param [inout] evt_info - event ino
    //
    // @return 0 on success -1 on failure.
    pub fn deserialize(&mut self, p : &mut packet, evt_mgr : &mut event_mgr) -> i32 {
        self.pcp = (p.buf[p.off] & 0xE0) >> 5;
        self.dei = !!(p.buf[p.off] & 0x10);
        self.vid = (((p.buf[p.off] as u32) & 0x0F) << 8) as u16 | p.buf[p.off + 1] as u16;
        p.off += 2;

        for vlan_id in vlan_hdr::VLAN_RESERVED {
            if self.vid == vlan_id {
                evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                             event_desc::VLAN_ID_RESERVED);
                return -1;
            }
        }

        p.deserialize_2_bytes(&mut self.ethertype);

        return 0;
    }

    pub fn serialize(&mut self, p : &mut packet) -> i32 {
        return 0;
    }
}