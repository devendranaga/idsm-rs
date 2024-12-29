// @brief - initialize idsm context
// @copyright - Devendra Naga 2024-present All rights reserved
#![allow(non_camel_case_types)]

use crate::core::debug::is_debug_level_protocol;
use crate::events::event_mgr;
use crate::lib::pcap::{self};
use crate::lib::protocols::packet::packet::packet;
use crate::lib::time_linux::gmtime::gmtime_filename;
use crate::parser::pkt_parser;
use crate::config;

use super::cmd_args::idsm_cmd_args;

// @brief - defines idsm context
pub struct idsm_context {
    cmd_args                : idsm_cmd_args,
    config_data             : config::config_parser::idsm_config,
    evt_mgr                 : event_mgr::event_mgr,
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
            pcap_write              : pcap::pcap_write::pcap_writer::new(),
        };
        context
    }

    fn init_pcap_context(&mut self) -> i32 {
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

        // parse config file
        ret = self.config_data.parse(&self.cmd_args.config_file);
        if ret < 0 {
            println!("idsm: failed to parse config data");
            return -1;
        }

        ret = self.init_pcap_context();
        if ret < 0 {
            println!("idsm: cannot create pcap context");
            return -1;
        }

        println!("idsm: init ok");

        return 0;
    }

    // @brief - start firewall
    // @param [in] self - idsm context
    pub fn start_firewall(&mut self) {
        use crate::lib;

        let mut ret;
        let mut raw_sock = lib::raw::raw_socket::raw_socket::new();

        // create raw socket
        ret = lib::raw::raw_socket::raw_socket::create(&mut raw_sock, &self.config_data.ifname);
        if ret != 0 {
            println!("idsm: cannot create raw socket!");
            return;
        }

        loop {
            let mut p : packet = packet::new();
            let rx_len = p.buf_len();
            let debug_protocols = is_debug_level_protocol(self.cmd_args.debug);
    
            // read from the raw socket
            ret = lib::raw::raw_socket::raw_socket::read(&mut raw_sock, &mut p.buf, rx_len);
            if ret > 0 {
                p.pkt_len = ret as usize;
                let mut parser : pkt_parser::pkt_parser = pkt_parser::pkt_parser::new();
    
                //p.hexdump();
                parser.parse(&mut p, &mut self.evt_mgr, debug_protocols);
                self.pcap_write.write(&p.buf, p.pkt_len as u32);
            }
        }
    }    
}
