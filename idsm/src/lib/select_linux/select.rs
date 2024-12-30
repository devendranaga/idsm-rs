#![allow(non_camel_case_types)]

use std::mem::MaybeUninit;

use libc::{fd_set, FD_SET};

pub struct select_time_val {
    sec : u32,
    usec : u32
}

impl select_time_val {
    pub fn new() -> select_time_val {
        let s_t_val = select_time_val {
            sec : 0,
            usec : 0
        };
        s_t_val
    }
}

pub struct select_linux {
    timerlist : Vec<select_time_val>,
    fdlist : Vec<i32>,
    allfd : fd_set,
    maxfd : i32
}

impl select_linux {
    pub fn new() -> select_linux {
        unsafe {
            let s = select_linux {
                timerlist : Vec::new(),
                fdlist : Vec::new(),
                allfd : MaybeUninit::zeroed().assume_init(),
                maxfd : -1
            };
            s
        }
    }

    pub fn add_fd(&mut self, fd : i32) {
        self.fdlist.push(fd);
        if fd > self.maxfd {
            self.maxfd = fd;
        }
    }

    pub fn add_timer(&mut self, s_t_val : select_time_val) {
        self.timerlist.push(s_t_val);
    }

    pub fn run(&mut self) {
        let mut ret;

        // set all fds
        for i in &self.fdlist {
            unsafe {
                FD_SET(*i, &mut self.allfd as *mut libc::fd_set);
            }
            if *i > self.maxfd {
                self.maxfd = *i
            }
        }

        unsafe {
            ret = libc::select(self.maxfd + 1,
                               &mut self.allfd as *mut libc::fd_set,
                               std::ptr::null_mut(),
                               std::ptr::null_mut(),
                               std::ptr::null_mut());
        }
    }
}