#![allow(non_camel_case_types)]

use std::fs;

pub struct idsm_config {
    pub ifname : String
}

impl idsm_config {
    pub fn new() -> idsm_config {
        let config = idsm_config {
            ifname : "".to_string()
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

        return 0;
    }
}