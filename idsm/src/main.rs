mod lib;

use crate::lib::net::net_ioctl;

fn test_macaddr()
{
    let mut mac : [u8; 6] = Default::default();
    let ifname = "wlp4s0".to_string();

    net_ioctl::net_ioctl_intf::get_mac_addr(&ifname, &mut mac);
    println!("mac: {:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}:{:02X?}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

fn test_ifindex()
{
    let ifname = "wlp4s0".to_string();
    let ifindex;

    ifindex = net_ioctl::net_ioctl_intf::get_ifindex(&ifname);
    println!("ifindex : {}", ifindex);
}

fn test_set_promisc()
{
    let ifname = "wlp4s0".to_string();
    let ret;

    ret = net_ioctl::net_ioctl_intf::set_promisc(&ifname);
    println!("set {}", ret);
}

fn main() {
    println!("Hello, world!");

    test_macaddr();
    test_ifindex();
    test_set_promisc();
}
