#![allow(dead_code)]
#![allow(unused_variables)]

mod lib;
mod parser;
mod events;

use lib::protocols::packet::packet::packet;
use parser::pkt_parser;

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
    if ret == 0 {
        loop {
            let mut p : packet = packet::new();
            let rx_len = p.buf_len();

            ret = lib::raw::raw_socket::raw_socket::read(&mut raw_sock, &mut p.buf, rx_len);
            if ret > 0 {
                p.pkt_len = ret as usize;
                let mut parser : pkt_parser::pkt_parser = pkt_parser::pkt_parser::new();

                parser.parse(&mut p);
            }
        }
    }
}

fn main() {
    println!("Hello, world!");

    test_raw_sock();
}
