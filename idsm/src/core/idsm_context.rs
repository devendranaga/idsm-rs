// @brief - initialize idsm context
// @copyright - Devendra Naga 2024-present All rights reserved
#![allow(non_camel_case_types)]

use crate::core::debug::{is_debug_level_config_data, is_debug_level_protocol};
use crate::events::event_mgr;
use crate::lib::pcap::{self};
use crate::lib::protocols::packet::packet::packet;
use crate::lib::select_linux::select::select_time_val;
use crate::lib::time_linux::gmtime::gmtime_filename;
use crate::parser::pkt_parser;
use crate::{config, lib};
use crate::stats::stats_mgr;

use super::cmd_args::idsm_cmd_args;

// @brief - defines idsm context
pub struct idsm_context {
    cmd_args                : idsm_cmd_args,
    config_data             : config::config_parser::idsm_config,
    evt_mgr                 : event_mgr::event_mgr,
    stats_mgr               : stats_mgr::idsm_stats_mgr,
    pcap_write              : pcap::pcap_write::pcap_writer
}

impl idsm_context {
    // @brief - zero initialize idsm context
    // @return idsm context
    pub fn new() -> idsm_context {
        let context = idsm_context {
            cmd_args                : idsm_cmd_args::new(),
            config_data             : config::config_parser::idsm_config::new(),
            evt_mgr                 : event_mgr::event_mgr::new(),
            stats_mgr               : stats_mgr::idsm_stats_mgr::new(),
            pcap_write              : pcap::pcap_write::pcap_writer::new(),
        };
        context
    }

    fn init_pcap_writing(&mut self) -> i32 {
        let mut pcap_filename = String::new();
        let mut ret = -1;

        // create pcap file if enabled
        if self.config_data.pcap_config.enable {
            let file_prefix = ".pcap".to_string();

            ret = gmtime_filename(&self.config_data.pcap_config.file_prefix,
                                &file_prefix, &mut pcap_filename);
            if ret < 0 {
                println!("cannot create a filename with current time");
                return -1;
            }

            ret = self.pcap_write.create(&pcap_filename);
            if ret < 0 {
                println!("idsm: failed to create pcap file");
                return -1;
            }
        }

        return ret;
    }

    // @brief - initialize the idsm context
    // @param [in] self - idsm context
    pub fn init(&mut self) -> i32 {
        let mut ret : i32;

        // parse command line arguments
        ret = self.cmd_args.parse();
        if ret < 0 {
            println!("idsm: failed to parse command line args");
            return -1;
        }

        let config_dbg = is_debug_level_config_data(self.cmd_args.debug);
        // parse config file
        ret = self.config_data.parse(&self.cmd_args.config_file, config_dbg);
        if ret < 0 {
            println!("idsm: failed to parse config data");
            return -1;
        }

        ret = self.init_pcap_writing();
        if ret < 0 {
            println!("idsm: cannot create pcap context");
            return -1;
        }

        println!("idsm: init ok");

        return 0;
    }

    // @brief - process raw socket receive
    //
    // @param [inout] self - this struct
    // @param [in] raw_sock - raw socket
    //
    // @return 0 on success -1 on failure
    fn process_raw_sock_recv(&mut self, raw_sock : &mut lib::raw::raw_socket::raw_socket) -> i32 {
        use crate::lib;

        let mut ret : i32;
        let mut p : packet = packet::new();
        let rx_len = p.buf_len();
        let debug_protocols = is_debug_level_protocol(self.cmd_args.debug);

        // read from the raw socket
        ret = lib::raw::raw_socket::raw_socket::read(raw_sock, &mut p.buf, rx_len);
        if ret < 0 {
            return -1;
        }

        p.pkt_len = ret as usize;
        // allocate a new parser context
        let mut parser : pkt_parser::pkt_parser = pkt_parser::pkt_parser::new();

        // update stats for rx
        self.stats_mgr.inc_rx();

        // parse the incoming frame, store events if necessary
        ret = parser.parse(&mut p, &mut self.evt_mgr, &mut self.stats_mgr, debug_protocols);
        if ret < 0 {
            return -1;
        }

        if self.config_data.pcap_config.enable {
            self.pcap_write.write(&p.buf, p.pkt_len as u32);
        }

        return 0;
    }

    fn process_evt_upload(&mut self) {
    }

    // @brief - start firewall
    // @param [in] self - idsm context
    //
    // @details - start a firewall context for the interface
    //
    //            only one instance is supported, no multi threading yet (i do not how to in rust)
    //            1. creates raw socket
    //            2. create a timer that periodically pushes firewall events that are collected
    //            3. registers to the select
    //              3.1. receive raw socket data -> parse it -> filter it -> consume it
    //              3.2. periodically forward events
    pub fn start_firewall(&mut self) {
        use crate::lib;

        let ret;
        let mut raw_sock = lib::raw::raw_socket::raw_socket::new();
        let mut select_loop = lib::select_linux::select::select_linux::new();
        let evt_intvl_sec = self.config_data.evt_config.udp_config.interval_sec;

        // create raw socket
        ret = lib::raw::raw_socket::raw_socket::create(&mut raw_sock, &self.config_data.ifname);
        if ret != 0 {
            println!("idsm: cannot create raw socket!");
            return;
        }

        // add raw socket to the monitoring fds
        select_loop.add_fd(raw_sock.get());

        let mut evt_timeval = select_time_val::new();
        evt_timeval.id = 1;
        evt_timeval.sec = evt_intvl_sec;
        evt_timeval.nsec = 0;

        // add timer to the monitoring
        select_loop.add_timer(&mut evt_timeval);

        loop {
            let select_res = select_loop.select();
            if select_res.res == 0 {
                if select_res.fd == raw_sock.get() {
                    _ = self.process_raw_sock_recv(&mut raw_sock);
                }
                if select_res.id == evt_timeval.id {
                    self.process_evt_upload();
                }
            }
        }
    }    
}
