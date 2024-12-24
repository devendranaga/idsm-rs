#![allow(dead_code)]

pub fn c_strcpy(dst : &mut [i8], src : &str) -> i32 {
    let src_bytes = src.as_bytes();

    for i in 0..src.len() {
        dst[i] = src_bytes[i] as i8;
    }

    return 0;
}
