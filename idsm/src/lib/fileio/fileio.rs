// @brief - implements fileio for media writes and reads
// @copyright - 2024-present Devendra Naga All rights reserved
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use libc;

// @brief - defines fileio structure
pub struct fileio {
    fd : i32
}

impl fileio {
    // @brief - get a cleared instance of this struct
    //
    // @return a clean instance of this struct
    #[inline(always)]
    pub fn new() -> fileio {
        let io = fileio {
            fd : -1
        };
        io
    }

    // @brief - create a new file
    //
    // @param [in] self - this structure
    // @param [in] filename - name of the file
    //
    // @return 0 on success -1 on failure
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

    // @brief - write to the opened file
    //
    // @param [in] self - this structure
    // @param [in] buf - buffer to write to the file
    // @param [in] buf_len - length of buffer
    //
    // @return write length on success -1 on failure
    pub fn write(&mut self, buf : &[u8], buf_len : usize) -> isize {
        let ret : isize;
        unsafe {
            ret = libc::write(self.fd,
                              buf as *const [u8] as *const libc::c_void,
                              buf_len);
        }
        return ret;
    }

    // @brief - close a opened file
    //
    // @param [in] self - this structure
    pub fn close(&mut self) {
        unsafe {
            if self.fd > 0 {
                libc::close(self.fd);
            }
        }
    }
}

impl Drop for fileio {
    fn drop(&mut self) {
        unsafe {
            if self.fd > 0 {
                libc::close(self.fd);
            }
        }
    }
}