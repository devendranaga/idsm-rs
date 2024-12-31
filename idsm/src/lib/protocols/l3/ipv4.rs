// @brief - implements ipv4 serialize and deserialization
// @copyright - 2024-present Devendra Naga All rights reserved
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::{
    events::{
        event_desc::event_desc,
        event_mgr::event_mgr,
        event_type::event_type
    },
    lib::protocols::packet::packet::packet
};

// @brief - implements ipv4 header
pub struct ipv4_hdr {
    version             : u8, // 4 bits
    ihl                 : u8, // 4 bits
    dscp                : u8, // 6 bits
    ecn                 : u8, // 2 bits
    total_len           : u16, // 16 bits
    id                  : u16, // 16 bits
    flags_res           : u8, // 1 bit
    flags_df            : u8, // 1 bit
    flags_mf            : u8, // 1 bit
    frag_off            : u16, // 13 bits
    ttl                 : u8, // 8 bits
    pub protocol        : u8, // 8 bits
    hdr_checksum        : u16, // 16 bits
    src_ipaddr          : u32, // 32 bits
    dst_ipaddr          : u32, // 32 bits
}

impl ipv4_hdr {
    pub const IPV4_MIN_HDR_LEN          : u32 = 20;
    pub const IPV4_VERSION              : u32 = 4;
    pub const IPV4_IHL_DEFAULT          : u32 = 5;

    // @brief - return an instance of ipv4_hdr
    //
    // @return return an instance of ipv4_hdr
    #[inline(always)]
    pub fn new() -> ipv4_hdr {
        let hdr = ipv4_hdr {
            version             : 0,
            ihl                 : 0,
            dscp                : 0,
            ecn                 : 0,
            total_len           : 0,
            id                  : 0,
            flags_res           : 0,
            flags_df            : 0,
            flags_mf            : 0,
            frag_off            : 0,
            ttl                 : 0,
            protocol            : 0,
            hdr_checksum        : 0,
            src_ipaddr          : 0,
            dst_ipaddr          : 0
        };
        hdr
    }

    // @brief - deserialize ipv4 header
    //
    // @param [inout] self - ipv4 header
    // @param [inout] p - packet
    // @param [inout] evt_mgr - event manager
    // @param [in] debug - debug
    //
    // @return 0 on success -1 on failure.
    pub fn deserialize(&mut self, p : &mut packet, evt_mgr : &mut event_mgr, debug : bool) -> i32 {
        if ((p.pkt_len - p.off) as u32) < ipv4_hdr::IPV4_MIN_HDR_LEN {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                         event_desc::IPV4_SHORT_HDR_LEN);
            return -1;
        }

        self.version = (p.buf[p.off] & 0xF0) >> 4;
        if (self.version as u32) != ipv4_hdr::IPV4_VERSION {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                         event_desc::IPV4_INVAL_VERSION);
            return -1;
        }

        self.ihl = p.buf[p.off] & 0x0F;
        if (self.ihl as u32) != ipv4_hdr::IPV4_IHL_DEFAULT {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                         event_desc::IPV4_IHL_INVAL);
            return -1;
        }

        p.off += 1;

        self.dscp = (p.buf[p.off] & 0xFC) >> 2;
        self.ecn = p.buf[p.off] & 0x03;
        p.off += 1;

        p.deserialize_2_bytes(&mut self.total_len);
        p.deserialize_2_bytes(&mut self.id);

        self.flags_res = if (p.buf[p.off] & 0x80) == 0x80 { 1 } else { 0 };
        if self.flags_res != 0 {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                                    event_desc::IPV4_RESERVED_SET);
            return -1;
        }

        self.flags_df = if (p.buf[p.off] & 0x40) == 0x40 { 1 } else { 0 };
        self.flags_mf = if (p.buf[p.off] & 0x20) == 0x20 { 1 } else { 0 };
        self.frag_off = (((p.buf[p.off] & 0x1F) as u32) << 8) as u16 | (p.buf[p.off + 1]) as u16;
        p.off += 2;

        p.deserialize_byte(&mut self.ttl);
        p.deserialize_byte(&mut self.protocol);
        p.deserialize_2_bytes(&mut self.hdr_checksum);
        p.deserialize_4_bytes(&mut self.src_ipaddr);
        p.deserialize_4_bytes(&mut self.dst_ipaddr);

        if debug { self.print(); }

        return 0;
    }

    // @brief - print ipv4 header
    //
    // @param [in] self - ipv4 header
    pub fn print(&self) {
        log::info!("ipv4_hdr: ");
        log::info!("\t version: {}", self.version);
        log::info!("\t ihl: {}", self.ihl);
        log::info!("\t dscp: {}", self.dscp);
        log::info!("\t ech: {}", self.ecn);
        log::info!("\t total_len: {}", self.total_len);
        log::info!("\t id: 0x{:02X}", self.id);
        log::info!("\t flags: ");
        log::info!("\t\t reserved: {}", self.flags_res);
        log::info!("\t\t df: {}", self.flags_df);
        log::info!("\t\t mf: {}", self.flags_mf);
        log::info!("\t ttl: {}", self.ttl);
        log::info!("\t protocol: {}", self.protocol);
        log::info!("\t hdr_checksum: 0x{:02X}", self.hdr_checksum);
        packet::print_ipv4("src_ipaddr", self.src_ipaddr);
        packet::print_ipv4("dst_ipaddr", self.dst_ipaddr);
    }
}
