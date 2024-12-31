#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::mem::MaybeUninit;

extern "C" {
    pub fn inet_aton(cp: *const libc::c_char, inp: *mut libc::in_addr) -> libc::c_int;
    pub fn inet_addr(cp: *const libc::c_char) -> libc::in_addr_t;
    pub fn inet_ntoa(inp: libc::in_addr) -> *mut libc::c_char;
}

pub struct udp_client {
    pub fd : i32
}

impl udp_client {
    pub fn new() -> udp_client {
        let client = udp_client {
            fd : -1
        };
        client
    }

    pub fn create(&mut self) -> i32 {
        unsafe {
            self.fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if self.fd < 0 {
                return -1;
            }
        }

        return 0;
    }

    pub fn sendto(&mut self, msg : &[u8], msg_len : usize, dest : &String, dest_port : u32) -> isize {
        unsafe {
            let ret : isize;
            let res : i32;
            let mut addr : libc::sockaddr_in = MaybeUninit::zeroed().assume_init();

            addr.sin_family = libc::AF_INET as u16;
            addr.sin_port = dest_port as u16;
            res = inet_aton(dest.as_ptr() as *const libc::c_char, &mut addr.sin_addr);
            if res < 0 {
                return -1;
            }

            ret = libc::sendto(self.fd,
                               msg as *const [u8] as *const libc::c_void,
                               msg_len,
                               0,
                               &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                               std::mem::size_of_val(&addr) as u32);
            return ret;
        }
    }
}
