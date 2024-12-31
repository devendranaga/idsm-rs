#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_camel_case_types)]

mod lib;
mod parser;
mod events;
mod config;
mod core;
mod stats;

fn main() {
    env_logger::init();

    let mut ctx : core::idsm_context::idsm_context = core::idsm_context::idsm_context::new();
    let ret : i32;

    ret = ctx.init();
    if ret < 0 {
        return;
    }

    ctx.start_firewall();
}
