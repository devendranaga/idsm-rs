#![allow(dead_code)]
#![allow(non_camel_case_types)]

use libc;

pub struct fileio {
    fd : i32
}

impl fileio {
    pub fn new() -> fileio {
        let io = fileio {
            fd : -1
        };
        io
    }

    pub fn new_file(&mut self, filename : &String) -> i32 {
        unsafe {
            self.fd = libc::open(filename.as_ptr() as *const i8,
                                 libc::O_CREAT |
                                 libc::O_WRONLY |
                                 libc::O_APPEND,
                                 libc::S_IRWXU);
            if self.fd < 0 {
                return -1;
            }
        }
        return 0;
    }

    pub fn write(&mut self, buf : &[u8], buf_len : usize) -> isize {
        let ret : isize;
        unsafe {
            ret = libc::write(self.fd,
                              buf as *const [u8] as *const libc::c_void,
                              buf_len);
        }
        return ret;
    }

    pub fn close(&mut self) {
        unsafe {
            if self.fd > 0 {
                libc::close(self.fd);
            }
        }
    }
}
