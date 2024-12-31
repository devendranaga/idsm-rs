#![allow(non_camel_case_types)]

pub fn c_memcmp(src : &[u8], dst : &[u8], len : usize) -> bool {
    for i in 0..len {
        if src[i] != dst[i] {
            return false;
        }
    }

    return true;
}
