#![allow(dead_code)]

use std::mem::MaybeUninit;

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

pub fn net_socket_bind_to_device(sock : i32) -> i32{
    let ret;
    let bind_to_device : u32 = 0;

    unsafe {
        ret = libc::setsockopt(sock,
                               libc::SOL_SOCKET,
                               libc::SO_BINDTODEVICE,
                               &bind_to_device as *const u32 as *const libc::c_void,
                               4);
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
