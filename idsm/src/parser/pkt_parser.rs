#![allow(non_camel_case_types)]

use crate::lib::protocols::{l2::eth, packet::packet::packet};

pub struct pkt_parser {
    eh : eth::eth_hdr,
}

impl pkt_parser {
    pub fn new() -> pkt_parser {
        let parser = pkt_parser {
            eh : eth::eth_hdr::new()
        };
        parser
    }

    pub fn parse(&mut self, p : &mut packet) {
        self.eh.deserialize(p);
        self.eh.print();
    }
}