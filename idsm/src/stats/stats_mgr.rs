#![allow(non_camel_case_types)]

use super::stats;

pub struct idsm_stats_mgr {
    stats : stats::idsm_stats
}

impl idsm_stats_mgr {
    pub fn new() -> idsm_stats_mgr {
        let stats_mgr = idsm_stats_mgr {
            stats : stats::idsm_stats::new()
        };
        stats_mgr
    }

    pub fn get(&mut self) -> &stats::idsm_stats { return &self.stats; }

    pub fn inc_rx(&mut self) { self.stats.n_rx += 1; }
    pub fn inc_eth_rx(&mut self) { self.stats.n_eth_rx += 1; }
    pub fn inc_arp_rx(&mut self) { self.stats.n_arp_rx += 1; }
    pub fn inc_vlan_rx(&mut self) { self.stats.n_vlan_rx += 1; }
    pub fn inc_ipv4_rx(&mut self) { self.stats.n_ipv4_rx += 1; }
    pub fn inc_ipv6_rx(&mut self) { self.stats.n_ipv6_rx += 1; }
    pub fn inc_tcp_rx(&mut self) { self.stats.n_tcp_rx += 1; }
}
