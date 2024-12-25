#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::{events::{event_desc::event_desc, event_info::event_info, event_type::event_type}, lib::protocols::packet::packet::packet};

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

    pub fn deserialize(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        self.res = p.buf[p.off] & 0x0E;
        self.accurate_ecn = !!(p.buf[p.off] & 0x01);
        p.off += 1;

        self.cwr = !!(p.buf[p.off] & 0x80);
        self.ece = !!(p.buf[p.off] & 0x40);
        self.urg = !!(p.buf[p.off] & 0x20);
        self.ack = !!(p.buf[p.off] & 0x10);
        self.psh = !!(p.buf[p.off] & 0x08);
        self.rst = !!(p.buf[p.off] & 0x04);
        self.syn = !!(p.buf[p.off] & 0x02);
        self.fin = !!(p.buf[p.off] & 0x01);
        p.off += 1;

        return 0;
    }

    pub fn print(&self) {
        println!("\t flags: ");
        println!("\t\t res: {}", self.res);
        println!("\t\t accurate_ecn: {}", self.accurate_ecn);
        println!("\t\t cwr: {}", self.cwr);
        println!("\t\t ece: {}", self.ece);
        println!("\t\t urg: {}", self.urg);
        println!("\t\t ack: {}", self.ack);
        println!("\t\t psh: {}", self.psh);
        println!("\t\t rst: {}", self.rst);
        println!("\t\t syn: {}", self.syn);
        println!("\t\t fin: {}", self.fin);
    }
}

pub struct tcp_opt_timestamp {
    len                 : u8, // 1 byte
    ts_val              : u32, // 4 bytes
    ts_echo_reply       : u32 // 4 bytes
}

impl tcp_opt_timestamp {
    pub fn new() -> tcp_opt_timestamp {
        let opt_timestamp = tcp_opt_timestamp {
            len                 : 0,
            ts_val              : 0,
            ts_echo_reply       : 0
        };
        opt_timestamp
    }

    pub fn deserialize(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32  {
        p.deserialize_byte(&mut self.len);
        p.deserialize_4_bytes(&mut self.ts_val);
        p.deserialize_4_bytes(&mut self.ts_echo_reply);

        return 0;
    }

    pub fn print(&self) {
        println!("\t\t opt_timestamp: ");
        println!("\t\t\t len: {}", self.len);
        println!("\t\t\t ts_val: {}", self.ts_val);
        println!("\t\t\t ts_echo_reply: {}", self.ts_echo_reply);
    }
}

pub struct tcp_opt {
    pub available_options   : u32,
    pub opt_timestamp       : tcp_opt_timestamp
}

impl tcp_opt {
    pub const OPT_NO_OP     : u8 = 1;
    pub const OPT_TIMESTAMP : u8 = 8;

    pub fn new() -> tcp_opt {
        let opts = tcp_opt {
            available_options : 0,
            opt_timestamp : tcp_opt_timestamp::new()
        };
        opts
    }

    pub fn deserialize(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        let mut ret : i32 = -1;
        let mut opt : u8;

        while p.off < p.pkt_len {
            opt = p.buf[p.off];

            if opt == tcp_opt::OPT_NO_OP {
                p.off += 1;
                self.available_options |= tcp_opt::OPT_NO_OP as u32;
            } else if opt == tcp_opt::OPT_TIMESTAMP {
                ret = self.opt_timestamp.deserialize(p, evt_info);
                if ret != 0 {
                    return -1;
                }
                self.available_options |= tcp_opt::OPT_TIMESTAMP as u32;
            } else {
                ret = -1;
                break;
            }
        }

        return ret;
    }

    pub fn print(&self) {
        if (self.available_options & tcp_opt::OPT_TIMESTAMP as u32) == 0 {
            self.opt_timestamp.print();
        }
    }
}

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

    pub fn deserialize(&mut self, p : &mut packet, evt_info : &mut event_info) -> i32 {
        if ((p.pkt_len - p.off) as u32) < tcp_hdr::TCP_MIN_HDR_LEN {
            evt_info.set(event_type::EVENT_TYPE_DENY,
                         event_desc::TCP_SHORT_HDR_LEN);
            return -1;
        }

        p.deserialize_2_bytes(&mut self.src_port);
        if self.src_port == 0 {
            evt_info.set(event_type::EVENT_TYPE_DENY,
                         event_desc::TCP_SRC_PORT_ZERO);
            return -1;
        }

        p.deserialize_2_bytes(&mut self.dst_port);
        if self.dst_port == 0 {
            evt_info.set(event_type::EVENT_TYPE_DENY,
                         event_desc::TCP_DST_PORT_ZERO);
            return -1;
        }

        p.deserialize_4_bytes(&mut self.seq_no);
        p.deserialize_4_bytes(&mut self.ack_no);

        self.hdr_len = (p.buf[p.off] & 0xF0) >> 4;

        self.flags.deserialize(p, evt_info);

        p.deserialize_2_bytes(&mut self.window);
        p.deserialize_2_bytes(&mut self.hdr_checksum);
        p.deserialize_2_bytes(&mut self.urg_ptr);

        self.options.deserialize(p, evt_info);

        return 0;
    }

    pub fn print(&self) {
        println!("tcp_hdr: ");
        println!("\t src_port : {}", self.src_port);
        println!("\t dst_port : {}", self.dst_port);
        println!("\t seq_no : {}", self.seq_no);
        println!("\t ack_no : {}", self.ack_no);
        println!("\t hdr_len : {}", self.hdr_len);
        self.flags.print();

        println!("\t window : {}", self.window);
        println!("\t hdr_checksum : {}", self.hdr_checksum);
        println!("\t urg_ptr: {}", self.urg_ptr);
        self.options.print();
    }
}
