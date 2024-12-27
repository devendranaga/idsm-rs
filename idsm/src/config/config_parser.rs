#![allow(non_camel_case_types)]

use std::fs;

pub struct idsm_pcap_config {
    pub enable : bool,
    pub file_prefix : String
}

impl idsm_pcap_config {
    pub fn new() -> idsm_pcap_config {
        let pcap_config = idsm_pcap_config {
            enable : false,
            file_prefix : "".to_string()
        };
        pcap_config
    }

    pub fn parse(&mut self, config_data : &serde_json::Value) -> i32 {
        let pcap_obj = config_data.get("pcap").unwrap();

        if pcap_obj.is_object() {
            self.enable = pcap_obj.get("enable").unwrap().as_bool().unwrap();
            self.file_prefix = pcap_obj.get("file_prefix").unwrap().as_str().unwrap().to_string();
            println!("{} {}", self.enable, self.file_prefix);
        }
        return 0;
    }
}

pub struct idsm_config {
    pub ifname : String,
    pub pcap_config : idsm_pcap_config
}

impl idsm_config {
    pub fn new() -> idsm_config {
        let config = idsm_config {
            ifname : "".to_string(),
            pcap_config : idsm_pcap_config::new()
        };
        config
    }

    pub fn parse(&mut self, config_file : &String) -> i32 {
        let file = fs::File::open(config_file)
                                            .expect("file should be read-only");
        let json : serde_json::Value = serde_json::from_reader(file)
                                            .expect("file must be a valid json");
        let ifname = json.get("ifname")
                                            .expect("ifname must contain a valid string").as_str().unwrap();
        self.ifname = ifname.to_string();
        self.pcap_config.parse(&json);

        return 0;
    }
}