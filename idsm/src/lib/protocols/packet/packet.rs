#![allow(dead_code)]
#![allow(non_camel_case_types)]

pub struct packet {
    pub buf             : [u8; 2048],
    buf_len             : usize,
    pub pkt_len         : usize,
    pub off             : usize
}

impl packet {
    #[inline(always)]
    pub fn new() -> packet {
        let p = packet {
            buf             : [0; 2048],
            buf_len         : 2048,
            pkt_len         : 0,
            off             : 0
        };
        p
    }

    // @brief - check if remaining length from the offset is in bounds
    //          within the header length of the packet.
    // @param [in] self - packet.
    // @param [in] hdr_len - header length.
    // @return true if within bounds false if not within bounds.
    pub fn remaining_len_in_bounds(&self, hdr_len : u32) -> bool {
        return (self.pkt_len as u32 - self.off as u32) >= hdr_len;
    }

    pub fn buf_len(&self) -> usize { return self.buf_len; }

    fn packet_buf_panic(&mut self) {
        panic!("too short buffer length: offset: {}, buffer_len: {}",
                                    self.off, self.buf_len);
    }

    pub fn serialize_ip6addr(&mut self, ip6addr : &mut [u8; 16]) {
        for i in 0..16 {
            self.buf[self.off + i] = ip6addr[i];
        }

        self.off += 16;
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

    pub fn serialize_mac(&mut self, mac : &mut [u8; 6]) {
        for i in 0..6 {
            self.buf[self.off + i] = mac[i];
        }

        self.off += 6;
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

    pub fn serialize_byte(&mut self, val8 : &mut u8) {
        self.buf[self.off] = *val8;

        self.off += 1;
    }

    pub fn deserialize_byte(&mut self, val8 : &mut u8) {
        let res : i32 = self.buf_len as i32 - (self.off + 1) as i32;
        if res < 0 {
            self.packet_buf_panic();
        }
        *val8 = self.buf[self.off];

        self.off += 1;
    }

    pub fn serialize_2_bytes(&mut self, val16: &mut u16) {
        self.buf[self.off] = ((*val16 & 0xFF00) >> 8) as u8;
        self.buf[self.off + 1] = ((*val16 & 0x00FF)) as u8;

        self.off += 2;
    }

    pub fn deserialize_2_bytes(&mut self, val16 : &mut u16) {
        let res : i32 = self.buf_len as i32 - (self.off + 2) as i32;
        if res < 0 {
            self.packet_buf_panic();
        }
        *val16 = ((self.buf[self.off] as u32) << 8) as u16 | (self.buf[self.off + 1]) as u16;

        self.off += 2;
    }

    pub fn serialize_4_bytes(&mut self, val32 : &mut u32) {
        self.buf[self.off] = ((*val32 & 0xFF000000) >> 24) as u8;
        self.buf[self.off + 1] = ((*val32 & 0x00FF0000) >> 16) as u8;
        self.buf[self.off + 2] = ((*val32 & 0x0000FF00) >> 8) as u8;
        self.buf[self.off + 3] = ((*val32 & 0x000000FF)) as u8;

        self.off += 4;
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

    pub fn hexdump(&mut self) {
        log::info!("packet: len {}", self.pkt_len);
        for i in 0..self.pkt_len {
            if i != 0 {
                if i % 8 == 0 {
                    print!("    ");
                }
                if i % 16 == 0 {
                    log::info!("");
                }
            }
            print!("{:02X} ", self.buf[i]);
        }
        log::info!("");
    }

    pub fn print_ipv4(name : &str, addr : u32) {
        log::info!("{}: {}.{}.{}.{}",
                name,
                (addr & 0xFF000000) >> 24,
                (addr & 0x00FF0000) >> 16,
                (addr & 0x0000FF00) >> 8,
                (addr & 0x000000FF));
    }

    pub fn print_macaddr(name : &str, mac_addr : &[u8]) {
        log::info!("{}: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                name,
                mac_addr[0], mac_addr[1],
                mac_addr[2], mac_addr[3],
                mac_addr[4], mac_addr[5]);
    }

    pub fn print_ipv6(name : &str, addr : &[u8]) {
        log::info!("{}: {:02X}{:02X}:{:02X}{:02X}:\
                      {:02X}{:02X}:{:02X}{:02X}:\
                      {:02X}{:02X}:{:02X}{:02X}:\
                      {:02X}{:02X}:{:02X}{:02X}",
                      name,
                      addr[0], addr[1], addr[2], addr[3],
                      addr[4], addr[5], addr[6], addr[7],
                      addr[8], addr[9], addr[10], addr[11],
                      addr[12], addr[13], addr[14], addr[15]);
    }
}
