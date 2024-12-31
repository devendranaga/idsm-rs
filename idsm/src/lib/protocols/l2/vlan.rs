// @brief - implements VLAN frame serialization and deserialization.
// @copyright - Devendra Naga 2024-present All rights reserved.
#![allow(dead_code)]
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
    #[inline(always)]
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
    pub fn deserialize(&mut self, p : &mut packet, evt_mgr : &mut event_mgr, debug : bool) -> i32 {
        self.pcp        = (p.buf[p.off] & 0xE0) >> 5;
        self.dei        = !!(p.buf[p.off] & 0x10);
        self.vid        = (((p.buf[p.off] as u32) & 0x0F) << 8) as u16 | p.buf[p.off + 1] as u16;
        p.off           += 2;

        for vlan_id in vlan_hdr::VLAN_RESERVED {
            if self.vid == vlan_id {
                evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                             event_desc::VLAN_ID_RESERVED);
                return -1;
            }
        }

        p.deserialize_2_bytes(&mut self.ethertype);

        if debug { self.print(); }

        return 0;
    }

    // @brief - serialize VLAN frame.
    //
    // @param [in] self - vlan header
    // @param [out] p - packet
    //
    // @return 0 on success -1 on failure.
    pub fn serialize(&mut self, p : &mut packet) -> i32 {
        p.buf[p.off]        = (self.pcp << 5) as u8;
        p.buf[p.off]        |= (self.dei << 4) as u8;
        p.buf[p.off]        |= (((self.vid & 0x0F00) >> 8) << 4) as u8;
        p.buf[p.off + 1]    = (self.vid & 0x00FF) as u8;
        p.off               += 2;

        p.buf[p.off]        = ((self.ethertype & 0xFF00) >> 8) as u8;
        p.buf[p.off + 1]    = ((self.ethertype & 0x00FF)) as u8;
        p.off               += 2;

        return 0;
    }

    // @brief - print VLAN frame.
    //
    // @param [in] self - vlan header
    pub fn print(&self) {
        println!("vlan_hdr: ");
        println!("\t pcp: {}", self.pcp);
        println!("\t dei: {}", self.dei);
        println!("\t vid: {}", self.vid);
        println!("\t ethertype: {:02X}", self.ethertype);
    }
}
