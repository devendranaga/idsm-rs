#![allow(dead_code)]

pub fn c_strcpy(dst : &mut [i8], src : &str) -> i32 {
    let mut i : usize = 0;
    let src_bytes = src.as_bytes();

    while i < src.len() {
        dst[i] = src_bytes[i] as i8;
        i = i + 1
    }
    dst[i] = '\0' as i8;

    return 0;
}
