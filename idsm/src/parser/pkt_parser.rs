#![allow(non_camel_case_types)]

use crate::{events::event_info::event_info, lib::protocols::{l2::{eth, ethertypes::Ethertypes}, l3::ipv4, l4::tcp, packet::packet::packet}};

pub struct pkt_parser {
    eh : eth::eth_hdr,
    ipv4_h : ipv4::ipv4_hdr,
    tcp_h : tcp::tcp_hdr,
}

impl pkt_parser {
    pub fn new() -> pkt_parser {
        let parser = pkt_parser {
            eh : eth::eth_hdr::new(),
            ipv4_h : ipv4::ipv4_hdr::new(),
            tcp_h : tcp::tcp_hdr::new()
        };
        parser
    }

    pub fn parse(&mut self, p : &mut packet) -> i32 {
        let mut evt_info : event_info = event_info::new();
        let mut ret : i32;

        ret = self.eh.deserialize(p, &mut evt_info);
        if ret < 0 {
            return -1;
        }

        if self.eh.ethertype == Ethertypes::IPV4 {
            ret = self.ipv4_h.deserialize(p, &mut evt_info);
            //self.ipv4_h.print();
            if ret < 0 {
                return -1;
            }

            if self.ipv4_h.protocol == 6 {
                self.tcp_h.deserialize(p, &mut evt_info);
                self.tcp_h.print();
            }
        }

        return ret;
    }
}
