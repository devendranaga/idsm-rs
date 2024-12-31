// @brief - implements event info description
// @copyright - Devendra Naga 2024-present All rights reserved.
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use crate::lib::time_linux::{self, timestamp::get_wallclock};

use self::time_linux::timestamp::timestamp;

// @brief - describes event info
pub struct event_info {
    pub event_type : u32,
    pub event_desc : u32,
    pub detection_ts : timestamp
}

impl event_info {
    // @brief - returns an initialized event_info
    pub fn new() -> event_info {
        let evt_info = event_info {
            event_type : 0,
            event_desc : 0,
            detection_ts : timestamp::new()
        };
        evt_info
    }

    // @brief - set events
    pub fn set(&mut self, event_type : u32, event_desc : u32) {
        self.event_type = event_type;
        self.event_desc = event_desc;
        // write detection time as now
        get_wallclock(&mut self.detection_ts);
    }
}
