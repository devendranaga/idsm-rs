#![allow(dead_code)]
#![allow(unused_variables)]

mod lib;

use crate::lib::net::net_ioctl;

fn test_macaddr()
{
    let mut mac : [u8; 6] = Default::default();
    let ifname = "wlp4s0".to_string();

    net_ioctl::net_ioctl_intf::get_mac_addr(&ifname, &mut mac);
    println!("mac: {:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

fn test_raw_sock()
{
    let ifname = "wlp4s0".to_string();
    let mut ret;
    let mut raw_sock = lib::raw::raw_socket::raw_socket::new();

    ret = lib::raw::raw_socket::raw_socket::create(&mut raw_sock, &ifname);
    println!("raw sock create {}", ret);
    if ret == 0 {
        loop {
            let mut rx_buf : [u8; 2048] = [0; 2048];
            let rx_len = rx_buf.len();

            ret = lib::raw::raw_socket::raw_socket::read(&mut raw_sock, &mut rx_buf, rx_len);
            //println!("read {} bytes", ret);
        }
    }
}

fn main() {
    println!("Hello, world!");

    test_raw_sock();
}
