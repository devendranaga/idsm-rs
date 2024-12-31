// @brief - implements TCP serialize and deserializer
// @copyright - 2024-present Devendra Naga All rights reserved
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::{
    events::{
        event_desc::event_desc, event_mgr::event_mgr, event_type::event_type
    },
    lib::protocols::packet::packet::packet
};

// @brief - defines TCP flags
pub struct tcp_flags {
    pub res             : u8, // 3 bits
    pub accurate_ecn    : u8, // 1 bit
    pub cwr             : u8, // 1 bit
    pub ece             : u8, // 1 bit
    pub urg             : u8, // 1 bit
    pub ack             : u8, // 1 bit
    pub psh             : u8, // 1 bit
    pub rst             : u8, // 1 bit
    pub syn             : u8, // 1 bit
    pub fin             : u8  // 1 bit
}

impl tcp_flags {
    // @brief - get a cleared TCP flags structure
    //
    // @return returns cleared TCP flags structure
    #[inline(always)]
    pub fn new() -> tcp_flags {
        let flags = tcp_flags {
            res             : 0,
            accurate_ecn    : 0,
            cwr             : 0,
            ece             : 0,
            urg             : 0,
            ack             : 0,
            psh             : 0,
            rst             : 0,
            syn             : 0,
            fin             : 0
        };
        flags
    }

    // @brief - deserialize TCP flags
    //
    // @param [inout] self - TCP flags
    // @param [inout] p - packet
    // @param [out] evt_mgr - event mgr
    //
    // @return 0 on success -1 on failure
    pub fn deserialize(&mut self, p : &mut packet, evt_mgr : &mut event_mgr) -> i32 {
        self.res = p.buf[p.off] & 0x0E;
        self.accurate_ecn = if (p.buf[p.off] & 0x01) == 0x01 { 1 } else { 0 };
        p.off += 1;

        self.cwr = if (p.buf[p.off] & 0x80) == 0x80 { 1 } else { 0 };
        self.ece = if (p.buf[p.off] & 0x40) == 0x40 { 1 } else { 0 };
        self.urg = if (p.buf[p.off] & 0x20) == 0x20 { 1 } else { 0 };
        self.ack = if (p.buf[p.off] & 0x10) == 0x10 { 1 } else { 0 };
        self.psh = if (p.buf[p.off] & 0x08) == 0x08 { 1 } else { 0 };
        self.rst = if (p.buf[p.off] & 0x04) == 0x04 { 1 } else { 0 };
        self.syn = if (p.buf[p.off] & 0x02) == 0x02 { 1 } else { 0 };
        self.fin = if (p.buf[p.off] & 0x01) == 0x01 { 1 } else { 0 };
        p.off += 1;

        // raise event if all flags are set
        if (self.res == 1) &&
           (self.accurate_ecn == 1) &&
           (self.cwr == 1) &&
           (self.ece == 1) &&
           (self.urg == 1) &&
           (self.ack == 1) &&
           (self.psh == 1) &&
           (self.rst == 1) &&
           (self.syn == 1) &&
           (self.fin == 1) {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                                    event_desc::TCP_FLAGS_ALL_SET);
            return -1;
        }

        // raise event if no flags are set
        if (self.res == 0) &&
           (self.accurate_ecn == 0) &&
           (self.cwr == 0) &&
           (self.ece == 0) &&
           (self.urg == 0) &&
           (self.ack == 0) &&
           (self.psh == 0) &&
           (self.rst == 0) &&
           (self.syn == 0) &&
           (self.fin == 0) {
            evt_mgr.insert_evt_info(
                                    event_type::EVENT_TYPE_DENY,
                                    event_desc::TCP_FLAGS_ALL_ZERO);
            return -1;
        }

        // raise event if both syn and fin are set
        if (self.syn != 0) && (self.fin != 0) {
            evt_mgr.insert_evt_info(
                                    event_type::EVENT_TYPE_DENY,
                                    event_desc::TCP_FLAGS_SYN_FIN_SET);
            return -1;
        }

        return 0;
    }

    // @brief - print TCP flags
    //
    // @param [in] self - TCP flags
    pub fn print(&self) {
        log::info!("\t flags: ");
        log::info!("\t\t res: {}", self.res);
        log::info!("\t\t accurate_ecn: {}", self.accurate_ecn);
        log::info!("\t\t cwr: {}", self.cwr);
        log::info!("\t\t ece: {}", self.ece);
        log::info!("\t\t urg: {}", self.urg);
        log::info!("\t\t ack: {}", self.ack);
        log::info!("\t\t psh: {}", self.psh);
        log::info!("\t\t rst: {}", self.rst);
        log::info!("\t\t syn: {}", self.syn);
        log::info!("\t\t fin: {}", self.fin);
    }
}

// @brief - TCP option timestamp structure
pub struct tcp_opt_timestamp {
    len                 : u8, // 1 byte
    ts_val              : u32, // 4 bytes
    ts_echo_reply       : u32 // 4 bytes
}

impl tcp_opt_timestamp {
    pub const TCP_TIMESTAMP_OPT_LEN : u8 = 10;

    // @brief - get a cleared TCP timestamp opt structure
    //
    // @return returns cleared TCP timestamp opt structure
    #[inline(always)]
    pub fn new() -> tcp_opt_timestamp {
        let opt_timestamp = tcp_opt_timestamp {
            len                 : 0,
            ts_val              : 0,
            ts_echo_reply       : 0
        };
        opt_timestamp
    }

    // @brief - deserialize TCP timestamp
    //
    // @param [out] self - this struct
    // @param [inout] p - packet
    // @param [out] evt_mgr - event mgr
    pub fn deserialize(&mut self, p : &mut packet, evt_mgr : &mut event_mgr) -> i32  {
        p.deserialize_byte(&mut self.len);
        if self.len != tcp_opt_timestamp::TCP_TIMESTAMP_OPT_LEN {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                                    event_desc::TCP_TIMESTAMP_OPT_LEN_INVAL);
            return -1;
        }
        p.deserialize_4_bytes(&mut self.ts_val);
        p.deserialize_4_bytes(&mut self.ts_echo_reply);

        return 0;
    }

    // @brief - print TCP timestamp
    //
    // @param [in] self - TCP timestamp
    pub fn print(&self) {
        log::info!("\t\t opt_timestamp: ");
        log::info!("\t\t\t len: {}", self.len);
        log::info!("\t\t\t ts_val: {}", self.ts_val);
        log::info!("\t\t\t ts_echo_reply: {}", self.ts_echo_reply);
    }
}

// @brief - defines TCP options
pub struct tcp_opt {
    pub available_options   : u32,
    pub opt_timestamp       : tcp_opt_timestamp
}

impl tcp_opt {
    pub const OPT_NO_OP     : u8 = 1;
    pub const OPT_TIMESTAMP : u8 = 8;

    // @brief - clears TCP options
    //
    // @return returns cleared TCP options
    #[inline(always)]
    pub fn new() -> tcp_opt {
        let opts = tcp_opt {
            available_options : 0,
            opt_timestamp : tcp_opt_timestamp::new()
        };
        opts
    }

    // @brief - deserialize TCP options
    //
    // @param [out] self - this struct
    // @param [inout] p - packet
    // @param [out] evt_mgr - event mgr
    pub fn deserialize(&mut self, p : &mut packet, evt_mgr : &mut event_mgr) -> i32 {
        let mut ret : i32 = 0;
        let mut opt : u8;

        /* skip if no options present. */
        while p.off < p.pkt_len {
            opt = p.buf[p.off];

            if opt == tcp_opt::OPT_NO_OP {
                p.off += 1;
                self.available_options |= tcp_opt::OPT_NO_OP as u32;
            } else if opt == tcp_opt::OPT_TIMESTAMP {
                ret = self.opt_timestamp.deserialize(p, evt_mgr);
                if ret != 0 {
                    return -1;
                }
                self.available_options |= tcp_opt::OPT_TIMESTAMP as u32;
            } else {
                // unknown option
                evt_mgr.insert_evt_info(
                                        event_type::EVENT_TYPE_DENY,
                                        event_desc::TCP_UNKNOWN_OPT);
                ret = -1;
                break;
            }
        }

        return ret;
    }

    // @brief - print TCP options
    //
    // @param [in] self - this struct
    pub fn print(&self) {
        if (self.available_options & tcp_opt::OPT_TIMESTAMP as u32) == 0 {
            self.opt_timestamp.print();
        }
    }
}

// @brief - defines TCP header
pub struct tcp_hdr {
    src_port            : u16, // 16 bits
    dst_port            : u16, // 16 bits
    seq_no              : u32, // 32 bits
    ack_no              : u32, // 32 bits
    hdr_len             : u8, // 4 bits
    flags               : tcp_flags,
    window              : u16,
    hdr_checksum        : u16,
    urg_ptr             : u16,
    options             : tcp_opt
}

impl tcp_hdr {
    pub const TCP_MIN_HDR_LEN : u32 = 20;

    // @brier - zero initialize TCP header
    //
    // @return returns zero initialized TCP header
    #[inline(always)]
    pub fn new() -> tcp_hdr {
        let tcp_h = tcp_hdr {
            src_port            : 0,
            dst_port            : 0,
            seq_no              : 0,
            ack_no              : 0,
            hdr_len             : 0,
            flags               : tcp_flags::new(),
            window              : 0,
            hdr_checksum        : 0,
            urg_ptr             : 0,
            options             : tcp_opt::new()
        };
        tcp_h
    }

    // @brief - deserialize TCP header
    //
    // @param [inout] self - this struct
    // @param [inout] p - packet
    // @param [out] evt_mgr - event mgr
    // @param [in] debug - debug frame
    //
    // @return 0 on success -1 on failure
    pub fn deserialize(&mut self, p : &mut packet, evt_mgr : &mut event_mgr, debug : bool) -> i32 {
        // check if the packet within the TCP header length
        if ((p.pkt_len - p.off) as u32) < tcp_hdr::TCP_MIN_HDR_LEN {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                         event_desc::TCP_SHORT_HDR_LEN);
            return -1;
        }

        p.deserialize_2_bytes(&mut self.src_port);
        if self.src_port == 0 {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                         event_desc::TCP_SRC_PORT_ZERO);
            return -1;
        }

        p.deserialize_2_bytes(&mut self.dst_port);
        if self.dst_port == 0 {
            evt_mgr.insert_evt_info(event_type::EVENT_TYPE_DENY,
                         event_desc::TCP_DST_PORT_ZERO);
            return -1;
        }

        p.deserialize_4_bytes(&mut self.seq_no);
        p.deserialize_4_bytes(&mut self.ack_no);

        self.hdr_len = (p.buf[p.off] & 0xF0) >> 4;

        let mut ret = self.flags.deserialize(p, evt_mgr);
        if ret < 0 {
            return -1;
        }

        p.deserialize_2_bytes(&mut self.window);
        p.deserialize_2_bytes(&mut self.hdr_checksum);
        p.deserialize_2_bytes(&mut self.urg_ptr);

        ret = self.options.deserialize(p, evt_mgr);
        if ret < 0 {
            return -1;
        }

        if debug { self.print(); }

        return 0;
    }

    // @brief - print TCP header
    //
    // @param [in] self - this structure
    pub fn print(&self) {
        log::info!("tcp_hdr: ");
        log::info!("\t src_port : {}", self.src_port);
        log::info!("\t dst_port : {}", self.dst_port);
        log::info!("\t seq_no : {}", self.seq_no);
        log::info!("\t ack_no : {}", self.ack_no);
        log::info!("\t hdr_len : {}", self.hdr_len);
        self.flags.print();

        log::info!("\t window : {}", self.window);
        log::info!("\t hdr_checksum : 0x{:02X}", self.hdr_checksum);
        log::info!("\t urg_ptr: {}", self.urg_ptr);
        self.options.print();
    }
}
