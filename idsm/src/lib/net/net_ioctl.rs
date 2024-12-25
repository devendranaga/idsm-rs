#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_camel_case_types)]

use std::mem::MaybeUninit;

use crate::lib::c_lib::c_strcpy;
use crate::lib::net::net_socket;

pub struct net_ioctl_intf {
}

impl net_ioctl_intf {
    pub fn get_mac_addr(ifname : &String, mac : &mut [u8; 6]) -> i32 {
        let ret;
        let sock = net_socket::net_socket_create(libc::AF_INET, libc::SOCK_DGRAM, 0);

        unsafe {
            let mut req : libc::ifreq = MaybeUninit::zeroed().assume_init();

            c_strcpy::c_strcpy(&mut req.ifr_name, ifname.as_str());
            ret = libc::ioctl(sock, libc::SIOCGIFHWADDR, &req);
            if ret < 0 {
                net_socket::net_socket_close(sock);
                return -1;
            }

            for i in 0..6 {
                mac[i] = req.ifr_ifru.ifru_hwaddr.sa_data[i] as u8;
            }
        }

        net_socket::net_socket_close(sock);
        return ret;
    }

    pub fn get_ifindex(sock : i32, ifname : &String) -> i32 {
        let mut ret : i32;

        unsafe {
            let mut req : libc::ifreq = MaybeUninit::zeroed().assume_init();

            c_strcpy::c_strcpy(&mut req.ifr_name, ifname.as_str());
            ret = libc::ioctl(sock, libc::SIOCGIFINDEX, &req);
            if ret < 0 {
                net_socket::net_socket_close(sock);
                return -1;
            }

            ret = req.ifr_ifru.ifru_ifindex;
        }

        return ret;
    }

    pub fn get_ifindex_nosock(ifname : &String) -> i32 {
        let mut ret : i32;
        let sock : i32 = net_socket::net_socket_create(libc::AF_INET, libc::SOCK_DGRAM, 0);

        unsafe {
            let mut req : libc::ifreq = MaybeUninit::zeroed().assume_init();

            c_strcpy::c_strcpy(&mut req.ifr_name, ifname.as_str());
            ret = libc::ioctl(sock, libc::SIOCGIFINDEX, &req);
            if ret < 0 {
                net_socket::net_socket_close(sock);
                return -1;
            }

            ret = req.ifr_ifru.ifru_ifindex;
        }

        return ret;
    }

    pub fn set_promisc(sock : i32, ifname : &String) -> i32 {
        let mut ret : i32;

        unsafe {
            let mut req : libc::ifreq =  MaybeUninit::zeroed().assume_init();

            c_strcpy::c_strcpy(&mut req.ifr_name, ifname.as_str());
            ret = libc::ioctl(sock, libc::SIOCGIFFLAGS, &req);
            if ret < 0 {
                return -1;
            }

            req.ifr_ifru.ifru_flags |= libc::IFF_PROMISC as i16;
            ret = libc::ioctl(sock, libc::SIOCSIFFLAGS, &req);
            if ret < 0 {
                return -1;
            }
        }

        return ret;
    }
}

