#![allow(non_camel_case_types)]

use crate::lib::protocols::packet::packet::packet;
use crate::parser::pkt_parser;
use crate::config;

pub struct idsm_context {
    config_data : config::config_parser::idsm_config
}

impl idsm_context {
    pub fn new() -> idsm_context {
        let context = idsm_context {
            config_data : config::config_parser::idsm_config::new()
        };
        context
    }

    pub fn init(&mut self) -> i32 {
        let config_file = "./config/firewall_config.json".to_string();
        let mut ret : i32 = 0;

        ret = self.config_data.parse(&config_file);
        if ret < 0 {
            return -1;
        }

        return 0;
    }

    pub fn start_firewall(&mut self) {
        use crate::lib;

        let mut ret;
        let mut raw_sock = lib::raw::raw_socket::raw_socket::new();
    
        ret = lib::raw::raw_socket::raw_socket::create(&mut raw_sock, &self.config_data.ifname);
        if ret != 0 {
            println!("cannot create raw socket!");
            return;
        }
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
