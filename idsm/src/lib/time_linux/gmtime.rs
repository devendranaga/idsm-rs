#![allow(non_camel_case_types)]

pub struct tm_linux {
    pub year : u32,
    pub mon : u32,
    pub day : u32,
    pub hour : u32,
    pub min : u32,
    pub sec : u32,
}

impl tm_linux {
    pub fn new() -> tm_linux {
        let t: tm_linux = tm_linux {
            year : 0,
            mon : 0,
            day : 0,
            hour : 0,
            min : 0,
            sec : 0
        };
        t
    }
}

pub fn gmtime_linux(t : &mut tm_linux) -> i32 {
    unsafe {
        let now = libc::time(0 as *mut i64);
        let tm = libc::gmtime(&now);
        if tm == std::ptr::null_mut() {
            return -1;
        }

        t.year = ((*tm).tm_year + 1900) as u32;
        t.mon = ((*tm).tm_mon + 1) as u32;
        t.day = (*tm).tm_mday as u32;
        t.hour = (*tm).tm_hour as u32;
        t.min = (*tm).tm_min as u32;
        t.sec = (*tm).tm_sec as u32;
    }
    return 0;
}

pub fn gmtime_filename(file_prefix : &String,
                       file_ext : &String,
                       filename : &mut String) -> i32 {
    let mut t = tm_linux::new();

    gmtime_linux(&mut t);

    filename.push_str(&file_prefix);
    filename.push_str(t.year.to_string().as_str());
    filename.push('_');
    filename.push_str(t.mon.to_string().as_str());
    filename.push('_');
    filename.push_str(t.day.to_string().as_str());
    filename.push('_');
    filename.push_str(t.hour.to_string().as_str());
    filename.push('_');
    filename.push_str(t.min.to_string().as_str());
    filename.push('_');
    filename.push_str(t.sec.to_string().as_str());
    filename.push_str(&file_ext);
    filename.push('\0');

    return 0;
}
