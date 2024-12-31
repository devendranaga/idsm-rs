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

    pub fn new() -> raw_socket {
        let r = raw_socket {
            fd : -1,
            ifname : "".to_string(),
            ifindex : -1
        };

        return r;
    }

    pub fn get(&mut self) -> i32 { return self.fd; }

    pub fn create(r : &mut raw_socket, ifname : &String) -> i32 {
        let mut ret;

        // create raw socket
        r.fd = net_socket::net_socket_create(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_ALL as u16).to_be() as i32);
        if r.fd < 0 {
            return -1;
        }

        // set promiscous mode
        ret = net_ioctl::net_ioctl_intf::set_promisc(r.fd, ifname);
        if ret < 0 {
            return -1;
        }

        r.ifindex = net_ioctl::net_ioctl_intf::get_ifindex(r.fd, ifname);
        if ret < 0 {
            return -1;
        }

        ret = net_socket::net_socket_bind_to_device(r.fd, ifname);
        if ret < 0 {
            return -1;
        }

        ret = net_socket::net_socket_bind_lladdr(r.fd, r.ifindex, (libc::ETH_P_ALL as u16).to_be() as i32, libc::AF_PACKET);

        return ret;
    }

    pub fn read(r : &mut raw_socket, rx_buf : &mut [u8], rx_len : usize) -> i32 {
        let ret : isize;

        unsafe {
            ret = libc::recv(r.fd, rx_buf.as_ptr() as *mut u8 as *mut libc::c_void, rx_len, 0);
        }
        return ret as i32;
    }
}
