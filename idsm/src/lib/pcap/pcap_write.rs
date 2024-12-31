#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::lib::{fileio::fileio, time_linux::timestamp};

struct pcap_header {
    magic_number            : u32,
    version_major           : u16,
    version_minor           : u16,
    thiszone                : i32,
    sigfigs                 : u32,
    snaplen                 : u32,
    network                 : u32
}

fn serialize_4_bytes(val32 : u32, buf : &mut [u8], off : &mut usize) {
    buf[*off]           = ((val32 & 0xFF000000) >> 24) as u8;
    buf[*off + 1]       = ((val32 & 0x00FF0000) >> 16) as u8;
    buf[*off + 2]       = ((val32 & 0x0000FF00) >> 8) as u8;
    buf[*off + 3]       = ((val32 & 0x000000FF)) as u8;

    *off                += 4;
}

fn serialize_2_bytes(val16 : u16, buf : &mut [u8], off : &mut usize) {
    buf[*off]           = ((val16 & 0xFF00) >> 8) as u8;
    buf[*off + 1]       = ((val16 & 0x00FF)) as u8;

    *off                += 2;
}

impl pcap_header {
    pub fn new() -> pcap_header {
        let pcap_hdr = pcap_header {
            magic_number            : 0xA1B2C3D4,
            version_major           : 2,
            version_minor           : 4,
            thiszone                : 0,
            sigfigs                 : 0,
            snaplen                 : 65535,
            network                 : 1
        };
        pcap_hdr
    }

    pub fn serialize(&mut self, buf : &mut [u8], off : &mut usize) {
        serialize_4_bytes(self.magic_number, buf, off);
        serialize_2_bytes(self.version_major, buf, off);
        serialize_2_bytes(self.version_minor, buf, off);
        serialize_4_bytes(self.thiszone as u32, buf, off);
        serialize_4_bytes(self.sigfigs, buf, off);
        serialize_4_bytes(self.snaplen, buf, off);
        serialize_4_bytes(self.network, buf, off);
    }
}

struct pcap_record {
    ts_sec          : u32,
    ts_usec         : u32,
    incl_len        : u32,
    orig_len        : u32
}

impl pcap_record {
    pub fn new() -> pcap_record {
        let pcap_rec = pcap_record {
            ts_sec          : 0,
            ts_usec         : 0,
            incl_len        : 0,
            orig_len        : 0
        };
        pcap_rec
    }

    pub fn serialize(&mut self, buf : &mut [u8], off : &mut usize) {
        serialize_4_bytes(self.ts_sec, buf, off);
        serialize_4_bytes(self.ts_usec, buf, off);
        serialize_4_bytes(self.incl_len, buf, off);
        serialize_4_bytes(self.orig_len, buf, off);
    }
}

pub struct pcap_writer {
    io : fileio::fileio
}

impl pcap_writer {
    pub fn new() -> pcap_writer {
        let pcap = pcap_writer {
            io : fileio::fileio::new()
        };
        pcap
    }

    pub fn create(&mut self, filename : &String) -> i32 {
        let mut pcap_hdr : pcap_header = pcap_header::new();
        let mut buf : [u8; 24] = [0; 24];
        let mut off = 0;
        let ret : i32;

        ret = self.io.new_file(filename);
        if ret < 0 {
            return -1;
        }

        pcap_hdr.serialize(&mut buf, &mut off);
        let wr_len = self.io.write(&buf, off);
        if wr_len > 0 {
            return 0;
        }
        return -1;
    }

    pub fn write(&mut self, buf : &[u8], buf_len : u32) -> i32 {
        let mut pcap_rec : pcap_record = pcap_record::new();
        let mut pcap_rec_buf : [u8; 16] = [0; 16];
        let mut off = 0;
        let ret : i32;
        let mut t : timestamp::timestamp = timestamp::timestamp::new();

        if buf_len > 2048 {
            return -1;
        }

        ret = timestamp::get_wallclock(&mut t);
        if ret < 0 {
            return -1;
        }

        pcap_rec.ts_sec = t.sec;
        pcap_rec.ts_usec = t.usec;
        pcap_rec.incl_len = buf_len;
        pcap_rec.orig_len = buf_len;

        pcap_rec.serialize(&mut pcap_rec_buf, &mut off);
        self.io.write(&pcap_rec_buf, 16);
        self.io.write(buf, buf_len as usize);

        return 0;
    }
}
