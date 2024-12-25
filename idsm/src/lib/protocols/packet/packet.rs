#![allow(dead_code)]
#![allow(non_camel_case_types)]

pub struct packet {
    pub buf : [u8; 2048],
    buf_len : usize,
    pub pkt_len : usize,
    pub off : usize
}

impl packet {
    pub fn new() -> packet {
        let p = packet {
            buf : [0; 2048],
            buf_len : 2048,
            pkt_len : 0,
            off : 0
        };
        p
    }
    pub fn buf_len(&self) -> usize {
        return self.buf_len;
    }

    fn packet_buf_panic(&mut self) {
        panic!("too short buffer length: offset: {}, buffer_len: {}",
                                    self.off, self.buf_len);
    }

    pub fn deserialize_ip6addr(&mut self, ip6addr : &mut [u8; 16]) {
        let res : i32 = self.buf_len as i32 - (self.off + 16) as i32;
        if res < 0 {
            self.packet_buf_panic();
        }
        for i in 0..16 {
            ip6addr[i] = self.buf[self.off + i];
        }
        self.off += 16;
    }

    pub fn deserialize_mac(&mut self, mac : &mut [u8; 6]) {
        let res : i32 = self.buf_len as i32 - (self.off + 6) as i32;
        if res < 0 {
            self.packet_buf_panic();
        }
        for i in 0..6 {
            mac[i] = self.buf[self.off + i];
        }
        self.off += 6;
    }

    pub fn deserialize_byte(&mut self, val8 : &mut u8) {
        let res : i32 = self.buf_len as i32 - (self.off + 1) as i32;
        if res < 0 {
            self.packet_buf_panic();
        }
        *val8 = self.buf[self.off];
        self.off += 1;
    }

    pub fn deserialize_2_bytes(&mut self, val16 : &mut u16) {
        let res : i32 = self.buf_len as i32 - (self.off + 2) as i32;
        if res < 0 {
            self.packet_buf_panic();
        }
        *val16 = ((self.buf[self.off] as u32) << 8) as u16 | (self.buf[self.off + 1]) as u16;
        self.off += 2;
    }

    pub fn deserialize_4_bytes(&mut self, val32 : &mut u32) {
        let res : i32 = self.buf_len as i32 - (self.off + 4) as i32;
        if res < 0 {
            self.packet_buf_panic();
        }
        *val32 = ((self.buf[self.off] as u32) << 24) |
                 ((self.buf[self.off + 1] as u32) << 16) |
                 ((self.buf[self.off + 2] as u32) << 8) |
                 (self.buf[self.off + 3] as u32);
        self.off += 4;
    }
}
