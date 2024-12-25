#![allow(non_camel_case_types)]

use crate::{
    events::event_info::event_info,
    lib::protocols::{
        l2::{
            arp, eth, ethertypes::Ethertypes, vlan
        },
        l3::{
            ipv4, ipv6, protocol_types::ProtocolTypes
        },
        l4::tcp,
        packet::packet::packet
    }
};

pub struct pkt_parser {
    eh          : eth::eth_hdr,
    ah          : arp::arp_hdr,
    vh          : vlan::vlan_hdr,
    ipv4_h      : ipv4::ipv4_hdr,
    ipv6_h      : ipv6::ipv6_hdr,
    tcp_h       : tcp::tcp_hdr,
    has_vlan_h  : bool,
    has_ipv4_h  : bool,
    has_ipv6_h  : bool,
    has_tcp_h   : bool,
    ethertype   : u16,
}

impl pkt_parser {
    pub fn new() -> pkt_parser {
        let parser = pkt_parser {
            eh          : eth::eth_hdr::new(),
            ah          : arp::arp_hdr::new(),
            vh          : vlan::vlan_hdr::new(),
            ipv4_h      : ipv4::ipv4_hdr::new(),
            ipv6_h      : ipv6::ipv6_hdr::new(),
            tcp_h       : tcp::tcp_hdr::new(),
            has_vlan_h  : false,
            has_ipv4_h  : false,
            has_ipv6_h  : false,
            has_tcp_h   : false,
            ethertype   : 0
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

    fn match_l4(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32 = -1;

        match self.ipv4_h.protocol {
            ProtocolTypes::TCP => ret = self.parse_tcp(p, evt_info),
            _ => ret = -1,
        }

        return ret;
    }

    fn parse_ipv4(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32 = -1;

        ret = self.ipv4_h.deserialize(p, evt_info);
        if ret < 0 {
            return -1;
        }

        self.has_ipv4_h = true;

        ret = self.match_l4(p, evt_info);

        return ret;
    }

    fn parse_ipv6(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32 = -1;

        ret = self.ipv6_h.deserialize(p, evt_info);
        if ret < 0 {
            return -1;
        }

        self.has_ipv6_h = true;

        ret = self.match_l4(p, evt_info);

        return ret;
    }

    fn parse_vlan(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32 = -1;

        ret = self.vh.deserialize(p, evt_info);
        if ret < 0 {
            return -1;
        }

        self.has_vlan_h = true;
        self.ethertype = self.vh.ethertype;

        return ret;
    }

    fn parse_l2(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32 = -1;

        ret = self.eh.deserialize(p, evt_info);
        if ret < 0 {
            return -1;
        }

        match self.eh.ethertype {
            Ethertypes::ARP             => ret = self.ah.deserialize(p, evt_info),
            Ethertypes::IEEE_8021Q      => ret = self.parse_vlan(p, evt_info),
            _                           => ret = -1,
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

        let ethertype = self.ethertype;

        if Ethertypes::has_l3(ethertype) {
            match ethertype {
                Ethertypes::IPV4 => ret = self.parse_ipv4(p, &mut evt_info),
                Ethertypes::IPV6 => ret = self.parse_ipv6(p, &mut evt_info),
                _ => ret = -1,
            }
        }

        return ret;
    }
}
