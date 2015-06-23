// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use libc::{self, c_char, c_int, c_void, size_t, socklen_t};
use std::iter;
use std::mem;
use std::ptr;

pub fn channel() -> Result<(UnixSender, UnixReceiver),c_int> {
    let mut results = [0, 0];
    unsafe {
        if socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, &mut results[0]) >= 0 {
            Ok((UnixSender::from_fd(results[0]), UnixReceiver::from_fd(results[1])))
        } else {
            Err(Error::last_os_error().raw_os_error())
        }
    }
}

pub struct UnixReceiver {
    fd: c_int,
}

impl Drop for UnixReceiver {
    fn drop(&mut self) {
        unsafe {
            assert!(libc::close(self.fd) == 0)
        }
    }
}

impl UnixReceiver {
    pub fn recv(&self) -> Result<(Vec<u8>, Vec<UnixSender>),c_int> {
        unsafe {
            let mut length_data: [usize; 2] = [0, 0];
            let result = libc::recv(self.fd,
                                    &length_data[0] as *mut _ as *mut u8,
                                    mem::size_of::<[usize; 2]>,
                                    MSG_WAITALL);
            if result <= 0 {
                return Err(Error::last_os_error())
            }

            let [data_length, sender_length] = length_data;
            let cmsg_length = mem::size_of::<cmsghdr>() + sender_length * mem::size_of::<c_int>();
            let cmsg_buffer = libc::malloc(cmsg_length);

            let mut data_buffer = iter::repeat(0).take(data_length).collect();
            let mut iovec = iovec {
                iov_base: &mut data_buffer[0],
                iov_len: data_length as size_t,
            };

            let mut msghdr = msghdr {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &mut iovec,
                msg_iovlen: 1,
                msg_control: cmsg as *mut c_void,
                msg_controllen: cmsg_length as size_t,
                msg_flags: 0,
            };

            let result = recvmsg(self.fd, &mut msghdr, 0);
            libc::free(cmsg_buffer);
            if result <= 0 {
                return Err(Error::last_os_error())
            }

            let cmsg_fds = cmsg.offset(1) as *const u8 as *const c_int;
            let senders = (0..cmsg_fds).map(|index| UnixSender::from_fd(*cmsg_fds.offset(index)))
                                       .collect();

            Ok((data_buffer, senders))
        }
    }
}

pub struct UnixSender {
    fd: c_int,
}

impl Drop for UnixSender {
    fn drop(&mut self) {
        unsafe {
            assert!(libc::close(self.fd) == 0)
        }
    }
}

impl Clone for UnixSender {
    fn clone(&self) -> UnixSender {
        unsafe {
            UnixSender {
                fd: libc::dup(self.fd)
            }
        }
    }
}

impl UnixSender {
    fn from_fd(&self, fd: c_int) -> UnixSender {
        UnixSender {
            fd: fd,
        }
    }

    pub fn send(&self, data: &[u8], senders: Vec<UnixSender>) -> Result<(),c_int> {
        unsafe {
            let length_data: [usize; 2] = [data.len(), senders.len()];
            let result = libc::send(self.fd,
                                    &length_data as *mut _ as *mut u8,
                                    mem::size_of::<[usize; 2]>,
                                    0);
            if result <= 0 {
                return Err(Error::last_os_error())
            }

            let cmsg_length = mem::size_of::<cmsghdr>() + senders.len() * mem::size_of::<c_int>();
            let cmsg_buffer = libc::malloc(cmsg_length);
            let cmsg = cmsg_buffer as *mut _ as *mut cmsghdr;
            (*cmsg_buffer).cmsg_len = cmsg_len as size_t;
            (*cmsg_buffer).cmsg_level = libc::SOL_SOCKET;
            (*cmsg_buffer).cmsg_type = SCM_RIGHTS;

            let mut fds = Vec::new();
            for sender in senders.into_iter() {
                fds.push(sender.fd);
                mem::forget(sender);
            }
            ptr::copy_nonoverlapping(fds.as_ptr(),
                                     cmsg.offset(1) as *mut _ as *mut c_int,
                                     fds.len());

            let mut iovec = iovec {
                iov_base: data.as_ptr(),
                iov_len: data.len() as usize,
            };

            let msghdr = msghdr {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &mut iovec,
                msg_iovlen: 1,
                msg_control: cmsg as *mut c_void,
                msg_controllen: cmsg_length as size_t,
                msg_flags: 0,
            };

            let result = sendmsg(self.fd, &msghdr, 0);
            libc::free(cmsg_buf);

            if result > 0 {
                Ok(())
            } else {
                Err(Error::last_os_error())
            }
        }
    }
}

// FFI stuff follows:

extern {
    fn recvmsg(socket: c_int, message: *mut msghdr, flags: c_int) -> ssize_t;
    fn sendmsg(socket: c_int, message: *const msghdr, flags: c_int) -> ssize_t;
    fn socketpair(domain: c_int, socket_type: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
}

#[repr(C)]
struct msghdr {
    msg_name: *mut c_void,
    msg_namelen: socklen_t,
    msg_iov: *mut iovec,
    msg_iovlen: size_t,
    msg_control: *mut c_void,
    msg_controllen: size_t,
    msg_flags: c_int,
}

#[repr(C)]
struct iovec {
    iov_base: *mut c_char,
    iov_len: size_t,
}

#[cfg(target_os="linux")]
#[repr(C)]
struct cmsghdr {
    cmsg_len: size_t,
    cmsg_level: c_int,
    cmsg_type: c_int,
}

