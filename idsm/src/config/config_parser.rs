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
        } else {
            return -1;
        }

        return 0;
    }

    pub fn print(&self) {
        println!("pcap_config: ");
        println!("\t enable: {}", self.enable);
        println!("\t file_prefix: {}", self.file_prefix);
    }
}

pub struct idsm_event_transport_udp {
    pub ipaddr : String,
    pub port : u16,
    pub interval_sec : u32
}

impl idsm_event_transport_udp {
    pub fn new() -> idsm_event_transport_udp {
        let udp_config = idsm_event_transport_udp {
            ipaddr : "".to_string(),
            port : 0,
            interval_sec : 0
        };
        udp_config
    }

    pub fn parse(&mut self, config_data :  &serde_json::Value) -> i32 {
        let udp_obj = config_data.get("udp").unwrap();

        if udp_obj.is_object() {
            self.ipaddr = udp_obj.get("ipaddr").unwrap().as_str().unwrap().to_string();
            self.port = (udp_obj.get("port").unwrap().as_u64().unwrap()) as u16;
            self.interval_sec = (udp_obj.get("interval_sec").unwrap().as_u64().unwrap()) as u32;
        } else {
            return -1;
        }

        return 0;
    }

    pub fn print(&self) {
        println!("udp_config: ");
        println!("\t ipaddr: {}", self.ipaddr);
        println!("\t port: {}", self.port);
        println!("\t interval_sec: {}", self.interval_sec);
    }
}

#[non_exhaustive]
struct idsm_event_transport_type;

impl idsm_event_transport_type {
    pub const UDP : u32 = 1;
}

pub struct idsm_events_config {
    pub enable : bool,
    pub evt_transport_type : u32,
    pub udp_config : idsm_event_transport_udp
}

impl idsm_events_config {
    pub fn new() -> idsm_events_config {
        let evt_config = idsm_events_config {
            enable : false,
            evt_transport_type : idsm_event_transport_type::UDP,
            udp_config : idsm_event_transport_udp::new()
        };
        evt_config
    }

    pub fn parse(&mut self, config_data : &serde_json::Value) -> i32 {
        let evt_obj = config_data.get("events").unwrap();

        if evt_obj.is_object() {
            self.enable = evt_obj.get("enable").unwrap().as_bool().unwrap();
            let evt_transport_type_str = evt_obj.get("transport").unwrap().as_str().unwrap().to_string();

            if evt_transport_type_str == "udp" {
                self.evt_transport_type = idsm_event_transport_type::UDP;
            }

            self.udp_config.parse(&evt_obj);
        } else {
            return -1;
        }

        return 0;
    }

    pub fn print(&self) {
        println!("event_config: ");
        println!("\t enable: {}", self.enable);
        println!("\t evt_transport_type: {}", self.evt_transport_type);
        self.udp_config.print();
    }
}

pub struct idsm_config {
    pub ifname : String,
    pub pcap_config : idsm_pcap_config,
    pub evt_config : idsm_events_config
}

impl idsm_config {
    pub fn new() -> idsm_config {
        let config = idsm_config {
            ifname : "".to_string(),
            pcap_config : idsm_pcap_config::new(),
            evt_config : idsm_events_config::new()
        };
        config
    }

    pub fn parse(&mut self, config_file : &String, debug : bool) -> i32 {
        let file = fs::File::open(config_file)
                                            .expect("file should be read-only");
        let json : serde_json::Value = serde_json::from_reader(file)
                                            .expect("file must be a valid json");
        let ifname = json.get("ifname")
                                            .expect("ifname must contain a valid string").as_str().unwrap();
        self.ifname = ifname.to_string();
        let mut ret = self.pcap_config.parse(&json);
        if ret < 0 {
            return -1;
        }

        ret = self.evt_config.parse(&json);
        if ret < 0 {
            return -1;
        }

        if debug { self.print(); }

        return 0;
    }

    pub fn print(&self) {
        println!("idsm config data: ");
        println!("ifname: {}", self.ifname);
        self.pcap_config.print();
        self.evt_config.print();
    }
}
