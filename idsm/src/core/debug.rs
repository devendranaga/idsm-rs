#![allow(non_camel_case_types)]

#[non_exhaustive]
struct debug_levels;

impl debug_levels {
    pub const PROTOCOLS : u32 = 1;
    pub const CONFIG_DATA : u32 = 2;
}

pub fn is_debug_level_protocol(debug_level : u32) -> bool {
    return debug_level == debug_levels::PROTOCOLS;
}

pub fn is_debug_level_config_data(debug_level : u32) -> bool {
    return debug_level == debug_levels::CONFIG_DATA;
}
