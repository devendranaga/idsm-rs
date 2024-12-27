#![allow(non_camel_case_types)]

use std::mem::MaybeUninit;

pub struct timestamp {
    pub sec : u32,
    pub usec : u32
}

impl timestamp {
    pub fn new() -> timestamp {
        let t = timestamp {
            sec : 0,
            usec : 0
        };
        t
    }
}

pub fn get_wallclock(t : &mut timestamp) -> i32 {
    let ret : i32;

    unsafe {
        let mut tp : libc::timespec = MaybeUninit::zeroed().assume_init();
        ret = libc::clock_gettime(libc::CLOCK_REALTIME, &mut tp);
        if ret < 0 {
            return -1;
        }
        t.sec = tp.tv_sec as u32;
        t.usec = (tp.tv_nsec / 1000) as u32;
    }

    return 0;
}
