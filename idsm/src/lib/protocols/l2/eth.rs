#![allow(non_camel_case_types)]

use crate::{events::{event_desc::event_desc, event_mgr::event_mgr, event_type::event_type}, lib::protocols::packet::packet};

pub struct eth_hdr {
    pub dst_mac : [u8; 6],
    pub src_mac : [u8; 6],
    pub ethertype : u16
}

impl eth_hdr {
    pub const ETH_HDR_LEN : u32 = 14;

    pub fn new() -> eth_hdr {
        let eh = eth_hdr {
            dst_mac : [0; 6],
            src_mac : [0; 6],
            ethertype : 0
        };
        eh
    }

    pub fn deserialize(&mut self, p : &mut packet::packet, evt_mgr : &mut event_mgr, debug : bool) -> i32 {
        if (p.pkt_len as u32) < eth_hdr::ETH_HDR_LEN {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                                    event_desc::ETH_SHORT_HDR_LEN);
            return -1;
        }

        p.deserialize_mac(&mut self.dst_mac);
        p.deserialize_mac(&mut self.src_mac);
        p.deserialize_2_bytes(&mut self.ethertype);

        if debug { self.print(); }
        return 0;
    }

    pub fn print(&self) {
        println!("eth_hdr:");
        println!("\t dst_mac: {:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
                                self.dst_mac[0], self.dst_mac[1], self.dst_mac[2],
                                self.dst_mac[3], self.dst_mac[4], self.dst_mac[5]);
        println!("\t src_mac: {:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
                                self.src_mac[0], self.src_mac[1], self.src_mac[2],
                                self.src_mac[3], self.src_mac[4], self.src_mac[5]);
        println!("\t ethertype: {:04X?}", self.ethertype);
    }
}