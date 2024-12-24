#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_camel_case_types)]

use std::mem::MaybeUninit;

use crate::lib::c_lib::c_strcpy;

fn net_socket_create(family : i32, sock_type : i32, protocol : i32) -> i32 {
    unsafe {
        return libc::socket(family, sock_type, protocol);
    }
}

fn net_socket_close(sock : i32) {
    unsafe {
        libc::close(sock);
    }
}

pub struct net_ioctl_intf {
}

impl net_ioctl_intf {
    pub fn get_mac_addr(ifname : &String, mac : &mut [u8; 6]) -> i32 {
        let ret;
        let sock = net_socket_create(libc::AF_INET, libc::SOCK_DGRAM, 0);

        unsafe {
            let mut req : libc::ifreq = MaybeUninit::zeroed().assume_init();

            c_strcpy::c_strcpy(&mut req.ifr_name, ifname.as_str());
            ret = libc::ioctl(sock, libc::SIOCGIFHWADDR, &req);
            if ret < 0 {
                net_socket_close(sock);
                return -1;
            }

            for i in 0..6 {
                mac[i] = req.ifr_ifru.ifru_hwaddr.sa_data[i] as u8;
            }
        }

        return ret;
    }
}

