#![allow(dead_code)]
#![allow(non_camel_case_types)]

struct raw_socket {
    fd : i32,
    ifname : String,
}

impl raw_socket {
    pub fn new() -> raw_socket {
        let r = raw_socket {
            fd : -1,
            ifname : "".to_string()
        };
        return r
    }
}
