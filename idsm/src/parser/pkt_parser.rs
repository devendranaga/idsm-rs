// @brief - parses the packet
// @copyright - Devendra Naga 2024-present All rights reserved
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

// @brief - defines a group of protocol headers and some
//          information about a single packet that entered
//          on the interface.
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
    // @brief - zero initialize the packet parser
    //
    // @return returns zero initialized packet parser structure
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

    // @brief - parse TCP frame
    //
    // @param [in] self - pkt_parser
    // @param [in] p - packet
    // @param [in] evt_info - event info
    //
    // @return 0 on success -1 on failure
    fn parse_tcp(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32;

        ret = self.tcp_h.deserialize(p, evt_info);
        if ret < 0 {
            return -1;
        }

        self.has_tcp_h = true;

        return ret;
    }

    // @brief - match an L4 frame
    //
    // @param [in] self - pkt_parser
    // @param [in] p - packet
    // @param [in] evt_info - event info
    // @param [in] protocol - Layer 4 protocol
    //
    // @return 0 on success -1 on failure
    fn match_l4(&mut self, p : &mut packet, evt_info : &mut event_info, protocol : u8) -> i32 {
        let mut ret : i32 = -1;

        match protocol {
            ProtocolTypes::TCP => ret = self.parse_tcp(p, evt_info),
            _ => ret = -1,
        }

        return ret;
    }

    // @brief - parse an IPv4 packet
    //
    // @param [in] self - pkt_parser
    // @param [in] p - packet
    // @param [in] evt_info - event info
    //
    // @return 0 on success -1 on failure
    fn parse_ipv4(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32;

        ret = self.ipv4_h.deserialize(p, evt_info);
        if ret < 0 {
            return -1;
        }

        self.has_ipv4_h = true;

        ret = self.match_l4(p, evt_info, self.ipv4_h.protocol);

        return ret;
    }

    // @brief - parse an IPv6 packet
    //
    // @param [in] self - pkt_parser
    // @param [in] p - packet
    // @param [in] evt_info - event info
    //
    // @return 0 on success -1 on failure
    fn parse_ipv6(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32;

        ret = self.ipv6_h.deserialize(p, evt_info);
        if ret < 0 {
            return -1;
        }

        self.has_ipv6_h = true;

        ret = self.match_l4(p, evt_info, self.ipv6_h.next_hdr);

        return ret;
    }

    // @brief - parse a VLAN packet
    //
    // @param [in] self - pkt_parser
    // @param [in] p - packet
    // @param [in] evt_info - event info
    //
    // @return 0 on success -1 on failure
    fn parse_vlan(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let ret : i32;

        ret = self.vh.deserialize(p, evt_info);
        if ret < 0 {
            return -1;
        }

        self.has_vlan_h = true;
        self.ethertype = self.vh.ethertype;

        return ret;
    }

    // @brief - parse a Layer 2 frame
    //
    // @param [in] self - pkt_parser
    // @param [in] p - packet
    // @param [in] evt_info - event info
    //
    // @return 0 on success -1 on failure
    fn parse_l2(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32;

        ret = self.eh.deserialize(p, evt_info);
        if ret < 0 {
            return -1;
        }
        self.ethertype = self.eh.ethertype;

        match self.eh.ethertype {
            Ethertypes::ARP             => ret = self.ah.deserialize(p, evt_info),
            Ethertypes::IEEE_8021Q      => ret = self.parse_vlan(p, evt_info),
            _                           => ret = -1,
        }

        if Ethertypes::has_l3(self.eh.ethertype) {
            ret = 0;
        }

        return ret;
    }

    // @brief - parse an incoming frame
    //
    // @param [in] self - pkt_parser
    // @param [in] p - packet
    //
    // @return 0 on success -1 on failure
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
