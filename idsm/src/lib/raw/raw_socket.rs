#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(unused_variables)]

use crate::lib::net::{net_ioctl, net_socket};

pub struct raw_socket {
    fd : i32,
    ifname : String,
    ifindex : i32,
}

impl raw_socket {

    pub fn create(ifname : &String) -> i32 {
        let mut ret;
        let mut r = raw_socket {
            fd : -1,
            ifname : String::from(ifname),
            ifindex : -1
        };

        r.fd = net_socket::net_socket_create(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL.to_be());
        if r.fd < 0 {
            return -1;
        }

        ret = net_ioctl::net_ioctl_intf::set_promisc(ifname);
        if ret < 0 {
            return -1;
        }

        r.ifindex = net_ioctl::net_ioctl_intf::get_ifindex(ifname);
        if ret < 0 {
            return -1;
        }

        ret = net_socket::net_socket_bind_to_device(r.fd, ifname);
        if ret < 0 {
            return -1;
        }

        ret = net_socket::net_socket_bind_lladdr(r.fd, r.ifindex, libc::ETH_P_ALL, libc::AF_PACKET);

        return ret;
    }
}
