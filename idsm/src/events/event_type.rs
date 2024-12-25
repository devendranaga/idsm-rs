#![allow(non_camel_case_types)]

#[non_exhaustive]
pub struct event_type;

impl event_type {
    pub const EVENT_TYPE_ALLOW  : u32 = 1;
    pub const EVENT_TYPE_DENY   : u32 = 2;
}
