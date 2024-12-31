#![allow(dead_code)]
#![allow(non_camel_case_types)]

use super::event_info::event_info;

pub struct event_mgr {
    evt_list : Vec<event_info>
}

impl event_mgr {
    pub fn new() -> event_mgr {
        let evt_mgr = event_mgr {
            evt_list : Vec::new()
        };
        evt_mgr
    }

    pub fn insert_evt_info(&mut self,
                           event_type : u32,
                           event_desc : u32) {
        let mut evt_info : event_info = event_info::new();

        evt_info.set(event_type, event_desc);
        self.evt_list.push(evt_info);
    }
}
