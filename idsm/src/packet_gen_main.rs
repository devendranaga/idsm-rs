#![allow(non_camel_case_types)]

use pktgen::{pktgen_cmdargs, pktgen_config::pktgen_config};

mod lib;
mod events;
mod pktgen;

struct pktgen_context {
    cmd_args : pktgen_cmdargs::pktgen_cmd_args,
    config : pktgen_config
}

impl pktgen_context {
    pub fn new() -> pktgen_context {
        let ctx = pktgen_context {
            cmd_args : pktgen_cmdargs::pktgen_cmd_args::new(),
            config : pktgen_config::new()
        };
        ctx
    }

    pub fn init(&mut self) -> i32 {
        let mut ret : i32;

        ret = self.cmd_args.parse();
        if ret < 0 {
            return -1;
        }

        ret = self.config.parse(&self.cmd_args.config_file);
        if ret < 0 {
            return -1;
        }

        return 0;
    }
}

fn main() {
    let mut ctx = pktgen_context::new();
    let ret : i32;

    ret = ctx.init();
    if ret < 0 {
        return;
    }
}
