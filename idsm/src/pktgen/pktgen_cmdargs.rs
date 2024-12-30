// @brief - parse command line arguments
// @copyright - Devendra Naga 2024-present All rights reserved.
use std::env;

use getopts::Options;

// defines idsm command line arguments
pub struct pktgen_cmd_args {
    // configuration file
    // the -f of command line argument sets this
    pub config_file : String,
    pub debug : u32,
}

impl pktgen_cmd_args {
    // zero initialize the structure
    // returns cmd_args of type idsm_cmd_args
    pub fn new() -> pktgen_cmd_args {
        let cmd_args = pktgen_cmd_args {
            config_file : "".to_string(),
            debug : 0
        };
        cmd_args
    }

    // displays the usage
    // @param [in] self - struct idsm_cmd_args
    // @param [in] progname - program name
    fn usage(&mut self, progname : &String) {
        println!("{} \n\
                 \t -f / --filename <firewall config file>\n \
                 \t -d / --debug <print debug messages during protocol parsing\n \
                 \t -h / -help <show this help>", progname);
    }

    // parse command line arguments
    // @param [in] self - struct idsm_cmd_args
    // @returns 0 on success -1 on failure
    pub fn parse(&mut self) -> i32 {
        let args : Vec <String> = env::args().collect();
        let progname = args[0].clone();
        let mut options = Options::new();

        options.optopt("f", "filename", "config filename", "");
        options.optopt("d", "debug", "debug this binary", "");
        options.optflag("h", "help", "shows the help");

        let matches = match options.parse(&args[1..]) {
            // if ok, return matched argument list in m
            Ok(m) => {m}

            // on error, panic and fail argument parsing
            Err(f) => {panic!("{}", f.to_string())}
        };

        // if -h is set, show usage
        if matches.opt_present("h") {
            self.usage(&progname);
            return -1;
        }

        // if -f is set, copy config filename
        if matches.opt_present("f") {
            self.config_file = matches.opt_str("f").unwrap();
        }
        // if -d is set, copy debug value
        if matches.opt_present("d") {
            let debug_str = matches.opt_str("d").unwrap().to_string();
            self.debug = debug_str.parse().unwrap();
            println!("debug {}", self.debug);
        }

        return 0;
    }
}
