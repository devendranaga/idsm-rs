use std::env;

use getopts::Options;


pub struct idsm_cmd_args {
    pub config_file : String,
}

impl idsm_cmd_args {
    pub fn new() -> idsm_cmd_args {
        let cmd_args = idsm_cmd_args {
            config_file : "".to_string()
        };
        cmd_args
    }

    fn usage(&mut self, progname : &String) {
        println!("{} \n\
                 \t -f / --filename <firewall config file>\n \
                 \t -h / -help <show this help>", progname);
    }

    pub fn parse(&mut self) -> i32 {
        let args : Vec <String> = env::args().collect();
        let progname = args[0].clone();

        let mut options = Options::new();
        options.optopt("f", "filename", "config filename", "");
        options.optflag("h", "help", "shows the help");

        let matches = match options.parse(&args[1..]) {
            Ok(m) => {m}
            Err(f) => { panic!("{}", f.to_string())}
        };

        if matches.opt_present("h") {
            self.usage(&progname);
            return -1;
        }

        self.config_file = matches.opt_str("f").unwrap();

        return 0;
    }
}
