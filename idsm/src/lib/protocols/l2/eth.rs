// @brief - implements Ethernet serialize deserialize.
// @copyright - 2024-present Devendra Naga All rights reserved.
#![allow(non_camel_case_types)]

use crate::{events::{event_desc::event_desc, event_mgr::event_mgr, event_type::event_type}, lib::{c_lib, protocols::packet::packet}};

use self::c_lib::memcmp::c_memcmp;

// @brief - defines Ethernet header
pub struct eth_hdr {
    pub dst_mac : [u8; 6],
    pub src_mac : [u8; 6],
    pub ethertype : u16
}

impl eth_hdr {
    pub const ETH_HDR_LEN : u32 = 14;

    // @brier - zero initialize Ethernet header
    //
    // @return zero initialized Ethernet header
    pub fn new() -> eth_hdr {
        let eh = eth_hdr {
            dst_mac : [0; 6],
            src_mac : [0; 6],
            ethertype : 0
        };
        eh
    }

    // @brief - deserialize Ethernet header
    //
    // @param [in] self - ethernet header
    // @param [in] p - packet
    // @param [in] evt_mgt - event manager
    // @param [in] debug - debug
    //
    // @return 0 on success -1 on failure
    pub fn deserialize(&mut self, p : &mut packet::packet, evt_mgr : &mut event_mgr, debug : bool) -> i32 {
        let z_mac : [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let b_mac : [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

        // short ethernet frame length
        if (p.pkt_len as u32) < eth_hdr::ETH_HDR_LEN {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                                    event_desc::ETH_SHORT_HDR_LEN);
            return -1;
        }

        p.deserialize_mac(&mut self.dst_mac);
        p.deserialize_mac(&mut self.src_mac);
        p.deserialize_2_bytes(&mut self.ethertype);

        // zero source mac.. raise event
        if c_memcmp(&self.src_mac, &z_mac, 6) == false {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                                    event_desc::ETH_SRC_ZERO_MAC);
            return -1;
        }

        // broadcast source mac.. raise event
        if c_memcmp(&self.src_mac, &b_mac, 6) == false {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                                    event_desc::ETH_SRC_BROADCAST_MAC);
            return -1;
        }

        if debug { self.print(); }
        return 0;
    }

    // @brief - serialize ethernet header
    //
    // @param [in] self - ethernet header
    // @param [in] p - packet
    pub fn serialize(&mut self, p : &mut packet::packet) {
        p.serialize_mac(&mut self.dst_mac);
        p.serialize_mac(&mut self.src_mac);
        p.serialize_2_bytes(&mut self.ethertype);
    }

    // @brief - print ethernet header
    //
    // @param [in] self - ethernet header
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