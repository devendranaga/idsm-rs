#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::mem::MaybeUninit;

use libc::{fd_set, FD_SET};

pub struct select_time_val {
    pub sec             : u32,
    pub nsec            : u32,
    pub id              : u32
}

impl select_time_val {
    pub fn new() -> select_time_val {
        let s_t_val = select_time_val {
            sec             : 0,
            nsec            : 0,
            id              : 0
        };
        s_t_val
    }

    pub fn create(&self) -> i32 {
        unsafe {
            let fd : i32;

            fd = libc::timerfd_create(libc::CLOCK_MONOTONIC, 0);
            if fd < 0 {
                return -1;
            }

            let ts : libc::itimerspec = libc::itimerspec {
                    it_interval : libc::timespec {
                        tv_sec : self.sec as i64,
                        tv_nsec : self.nsec as i64,
                    }, it_value : libc::timespec {
                        tv_sec : self.sec as i64,
                        tv_nsec : self.nsec as i64
                    }
            };

            let ret = libc::timerfd_settime(fd,
                                                 0,
                                                 &ts,
                                                 std::ptr::null_mut());
            if ret < 0 {
                libc::close(fd);
                return -1;
            }
            return fd;
        }
    }
}

pub struct timer_info {
    fd : i32,
    id : u32
}

impl timer_info {
    pub fn new(fd : i32, id : u32) -> timer_info {
        let t = timer_info {
            fd : fd,
            id : id
        };
        t
    }
}

pub struct select_res {
    pub res : i32,
    pub fd : i32,
    pub id : u32,
}

impl select_res {
    pub fn new(res : i32, fd : i32, id : u32) -> select_res {
        let r = select_res {
            res : res,
            fd : fd,
            id : id
        };
        r
    }
}

pub struct select_linux {
    fdlist : Vec<i32>,
    timerfd_list : Vec<timer_info>,
    allfd : fd_set,
    maxfd : i32
}

impl select_linux {
    pub fn new() -> select_linux {
        unsafe {
            let s = select_linux {
                fdlist : Vec::new(),
                timerfd_list : Vec::new(),
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

    pub fn add_timer(&mut self, time_val : &mut select_time_val) {
        let fd = time_val.create();
        if fd > self.maxfd {
            self.maxfd = fd;
        }
        let timerfd_info = timer_info::new(fd, time_val.id);
        self.timerfd_list.push(timerfd_info);
    }

    pub fn select(&mut self) -> select_res {
        let ret;

        unsafe { libc::FD_ZERO(&mut self.allfd); }

        // set all fds
        for i in &self.fdlist {
            unsafe {
                FD_SET(*i, &mut self.allfd as *mut libc::fd_set);
            }
            if *i > self.maxfd {
                self.maxfd = *i
            }
        }

        for i in &self.timerfd_list {
            unsafe {
                FD_SET((*i).fd, &mut self.allfd as *mut libc::fd_set);
            }
            if (*i).fd > self.maxfd {
                self.maxfd = (*i).fd;
            }
        }

        unsafe {
            ret = libc::select(self.maxfd + 1,
                               &mut self.allfd as *mut libc::fd_set,
                               std::ptr::null_mut(),
                               std::ptr::null_mut(),
                               std::ptr::null_mut());
            if ret < 0 {
                return select_res::new(-1, -1, 0);
            }

            for i in &self.fdlist {
                if libc::FD_ISSET(*i, &self.allfd as *const libc::fd_set) {
                    libc::FD_CLR(*i, &mut self.allfd);
                    return select_res::new(0, *i, 0);
                }
            }

            for i in &self.timerfd_list {
                if libc::FD_ISSET((*i).fd, &self.allfd as *const libc::fd_set) {
                    libc::FD_CLR((*i).fd, &mut self.allfd);
                    let mut val : u64 = 0;

                    let res = libc::read((*i).fd, &mut val as *mut libc::c_ulong as *mut libc::c_void, 8);
                    if res < 0 {
                        break;
                    }
                    return select_res::new(0, (*i).fd, (*i).id); 
                }
            }
            return select_res::new(-1, -1, 0);
        }
    }
}