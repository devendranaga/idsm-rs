#![allow(dead_code)]

use std::mem::MaybeUninit;

use crate::lib::c_lib::c_strcpy;

pub fn net_socket_create(family : i32, sock_type : i32, protocol : i32) -> i32 {
    unsafe {
        return libc::socket(family, sock_type, protocol);
    }
}

pub fn net_socket_close(sock : i32) {
    unsafe {
        libc::close(sock);
    }
}

pub fn net_socket_bind_to_device(sock : i32, ifname : &String) -> i32 {
    let mut ret;

    unsafe {
        let mut req : libc::ifreq = MaybeUninit::zeroed().assume_init();

        c_strcpy::c_strcpy(&mut req.ifr_name, ifname.as_str());
        ret = libc::ioctl(sock, libc::SIOCGIFINDEX, &req);
        if ret == 0 {
            ret = libc::setsockopt(sock,
                                   libc::SOL_SOCKET,
                                   libc::SO_BINDTODEVICE,
                                   &req as *const libc::ifreq as *const libc::c_void,
                                   4);
        }
    }

    return ret;
}

pub fn net_socket_bind_lladdr(sock : i32, ifindex : i32, protocol : i32, family : i32) -> i32 {
    let ret : i32;

    unsafe {
        let mut lladdr : libc::sockaddr_ll = MaybeUninit::zeroed().assume_init();

        lladdr.sll_ifindex = ifindex;
        lladdr.sll_protocol = protocol.to_be() as u16;
        lladdr.sll_family = family as u16;

        ret = libc::bind(sock,
                         &lladdr as *const libc::sockaddr_ll as *const libc::sockaddr,
                         std::mem::size_of_val(&lladdr) as u32);
    }

    return ret;
}
