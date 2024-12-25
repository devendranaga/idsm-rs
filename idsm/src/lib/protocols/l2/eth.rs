#![allow(non_camel_case_types)]

use crate::lib::protocols::packet::packet;

pub struct eth_hdr {
    pub dst_mac : [u8; 6],
    pub src_mac : [u8; 6],
    pub ethertype : u16
}

impl eth_hdr {
    pub fn new() -> eth_hdr {
        let eh = eth_hdr {
            dst_mac : [0; 6],
            src_mac : [0; 6],
            ethertype : 0
        };
        eh
    }

    pub fn deserialize(&mut self, p : &mut packet::packet) {
        p.deserialize_mac(&mut self.dst_mac);
        p.deserialize_mac(&mut self.src_mac);
        p.deserialize_2_bytes(&mut self.ethertype);
    }

    pub fn print(&self) {
        println!("dst_mac: {:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
                                self.dst_mac[0], self.dst_mac[1], self.dst_mac[2],
                                self.dst_mac[3], self.dst_mac[4], self.dst_mac[5]);
        println!("src_mac: {:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}",
                                self.src_mac[0], self.src_mac[1], self.src_mac[2],
                                self.src_mac[3], self.src_mac[4], self.src_mac[5]);
        println!("ethertype: {:04X?}", self.ethertype);
    }
}