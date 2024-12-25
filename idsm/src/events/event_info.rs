#![allow(non_camel_case_types)]

pub struct event_info {
    pub event_type : u32,
    pub event_desc : u32
}

impl event_info {
    pub fn new() -> event_info {
        let evt_info = event_info {
            event_type : 0,
            event_desc : 0
        };
        evt_info
    }

    pub fn set(&mut self, event_type : u32, event_desc : u32) {
        self.event_type = event_type;
        self.event_desc = event_desc;
    }
}
