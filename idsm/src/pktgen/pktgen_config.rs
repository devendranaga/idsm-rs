#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::lib::protocols::l2::eth;
use std::fs;

pub struct pktgen_eth_config {
    pub repeat : bool,
    pub repeat_intvl_us : u32,
    pub eth_hdr : eth::eth_hdr,    
}

impl pktgen_eth_config {
    pub fn new() -> pktgen_eth_config {
        let eth_config = pktgen_eth_config {
            repeat : false,
            repeat_intvl_us : 1,
            eth_hdr : eth::eth_hdr::new()
        };
        eth_config
    }

    pub fn parse(&mut self, config_data : &serde_json::Value) -> i32 {
        let eth_obj = config_data.get("eth").unwrap();

        if eth_obj.is_object() {
            self.repeat = eth_obj.get("repeat").unwrap().as_bool().unwrap();
            self.repeat_intvl_us = eth_obj.get("replay_intvl_us").unwrap().to_string().parse().unwrap();
        }
        return 0;
    }
}

pub struct pktgen_config {
    pub eth_config : pktgen_eth_config
}

impl pktgen_config {
    pub fn new() ->pktgen_config {
        let config = pktgen_config {
            eth_config : pktgen_eth_config::new()
        };
        config
    }

    pub fn parse(&mut self, config_file : &String) -> i32 {
        let file = fs::File::open(config_file)
                                            .expect("file should be read-only");
        let json : serde_json::Value = serde_json::from_reader(file)
                                            .expect("file must be a valid json");
        self.eth_config.parse(&json);

        return 0;
    }
}
