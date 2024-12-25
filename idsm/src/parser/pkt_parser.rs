#![allow(non_camel_case_types)]

use crate::{
    events::event_info::event_info,
    lib::protocols::{
        l2::{
            arp, eth, ethertypes::Ethertypes
        },
        l3::{
            ipv4,
            protocol_types::ProtocolTypes
        },
        l4::tcp,
        packet::packet::packet
    }
};

pub struct pkt_parser {
    eh          : eth::eth_hdr,
    ah          : arp::arp_hdr,
    ipv4_h      : ipv4::ipv4_hdr,
    tcp_h       : tcp::tcp_hdr,
    has_ipv4_h  : bool,
    has_tcp_h   : bool,
}

impl pkt_parser {
    pub fn new() -> pkt_parser {
        let parser = pkt_parser {
            eh          : eth::eth_hdr::new(),
            ah          : arp::arp_hdr::new(),
            ipv4_h      : ipv4::ipv4_hdr::new(),
            tcp_h       : tcp::tcp_hdr::new(),
            has_ipv4_h  : false,
            has_tcp_h   : false
        };
        parser
    }

    fn parse_tcp(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32 = -1;

        ret = self.tcp_h.deserialize(p, evt_info);
        if ret < 0 {
            return -1;
        }

        self.has_tcp_h = true;

        return ret;
    }

    fn parse_ipv4(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32 = -1;

        if self.eh.ethertype == Ethertypes::IPV4 {
            ret = self.ipv4_h.deserialize(p, evt_info);
            if ret < 0 {
                return -1;
            }

            self.has_ipv4_h = true;

            match self.ipv4_h.protocol {
                ProtocolTypes::TCP => ret = self.parse_tcp(p, evt_info),
                _ => ret = -1,
            }
        }

        return ret;
    }

    fn parse_l2(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32 = -1;
        let mut ethertype : u16;

        ret = self.eh.deserialize(p, evt_info);
        if ret < 0 {
            return -1;
        }

        ethertype = self.eh.ethertype;

        match ethertype {
            Ethertypes::ARP => ret = self.ah.deserialize(p, evt_info),
            _ => ret = -1,
        }

        return ret;
    }

    pub fn parse(&mut self, p : &mut packet) -> i32 {
        let mut evt_info : event_info = event_info::new();
        let mut ret : i32;

        ret = self.parse_l2(p, &mut evt_info);
        if ret < 0 {
            return -1;
        }

        match self.eh.ethertype {
            Ethertypes::IPV4 => ret = self.parse_ipv4(p, &mut evt_info),
            _ => ret = -1,
        }

        return ret;
    }
}
