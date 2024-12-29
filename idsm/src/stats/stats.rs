#![allow(non_camel_case_types)]

pub struct idsm_stats {
    pub n_rx : u64,
    pub n_eth_rx : u64,
    pub n_vlan_rx : u64,
    pub n_arp_rx : u64,
    pub n_ipv4_rx : u64,
    pub n_ipv6_rx : u64,
    pub n_tcp_rx : u64,
}

impl idsm_stats {
    pub fn new() -> idsm_stats {
        let stats = idsm_stats {
            n_rx : 0,
            n_eth_rx : 0,
            n_vlan_rx : 0,
            n_arp_rx : 0,
            n_ipv4_rx : 0,
            n_ipv6_rx : 0,
            n_tcp_rx : 0
        };
        stats
    }
}
