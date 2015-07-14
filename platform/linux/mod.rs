// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use libc::{self, c_char, c_int, c_short, c_uint, c_ushort, c_void, size_t, sockaddr, sockaddr_un, socklen_t};
use libc::{ssize_t};
use std::ffi::{CStr, CString};
use std::io::Error;
use std::iter;
use std::mem;
use std::ptr;

pub fn channel() -> Result<(UnixSender, UnixReceiver),c_int> {
    let mut results = [0, 0];
    unsafe {
        if socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, &mut results[0]) >= 0 {
            Ok((UnixSender::from_fd(results[0]), UnixReceiver::from_fd(results[1])))
        } else {
            Err(Error::last_os_error().raw_os_error().unwrap())
        }
    }
}

#[derive(PartialEq, Debug)]
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
    fn from_fd(fd: c_int) -> UnixReceiver {
        UnixReceiver {
            fd: fd,
        }
    }

    pub fn consume(&self) -> UnixReceiver {
        unsafe {
            UnixReceiver::from_fd(libc::dup(self.fd))
        }
    }

    pub fn recv(&self) -> Result<(Vec<u8>, Vec<UnknownUnixChannel>),c_int> {
        unsafe {
            let mut length_data: [usize; 2] = [0, 0];
            let result = libc::recv(self.fd,
                                    &mut length_data[0] as *mut _ as *mut c_void,
                                    mem::size_of::<[usize; 2]>() as size_t,
                                    MSG_WAITALL);
            if result <= 0 {
                return Err(Error::last_os_error().raw_os_error().unwrap())
            }

            let [data_length, channel_length] = length_data;
            let cmsg_length = mem::size_of::<cmsghdr>() + channel_length * mem::size_of::<c_int>();
            let cmsg_buffer: *mut cmsghdr = libc::malloc(cmsg_length as size_t) as *mut cmsghdr;

            let mut data_buffer: Vec<u8> = iter::repeat(0).take(data_length).collect();
            let mut iovec = iovec {
                iov_base: &mut data_buffer[0] as *mut _ as *mut i8,
                iov_len: data_length as size_t,
            };

            let mut msghdr = msghdr {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &mut iovec,
                msg_iovlen: 1,
                msg_control: cmsg_buffer as *mut c_void,
                msg_controllen: cmsg_length as size_t,
                msg_flags: 0,
            };

            let result = recvmsg(self.fd, &mut msghdr, 0);
            libc::free(cmsg_buffer as *mut c_void);
            if result <= 0 {
                return Err(Error::last_os_error().raw_os_error().unwrap())
            }

            let cmsg_fds = cmsg_buffer.offset(1) as *const u8 as *const c_int;
            let channels = (0..channel_length).map(|index| {
                UnknownUnixChannel::from_fd(*cmsg_fds.offset(index as isize))
            }).collect();

            Ok((data_buffer, channels))
        }
    }
}

#[derive(PartialEq, Debug)]
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
    fn from_fd(fd: c_int) -> UnixSender {
        UnixSender {
            fd: fd,
        }
    }

    pub fn send(&self, data: &[u8], channels: Vec<UnixChannel>) -> Result<(),c_int> {
        unsafe {
            let length_data: [usize; 2] = [data.len(), channels.len()];
            let result = libc::send(self.fd,
                                    &length_data[0] as *const _ as *const c_void,
                                    mem::size_of::<[usize; 2]>() as size_t,
                                    0);
            if result <= 0 {
                return Err(Error::last_os_error().raw_os_error().unwrap())
            }

            let cmsg_length = mem::size_of::<cmsghdr>() + channels.len() * mem::size_of::<c_int>();
            let cmsg_buffer = libc::malloc(cmsg_length as size_t) as *mut cmsghdr;
            (*cmsg_buffer).cmsg_len = cmsg_length as size_t;
            (*cmsg_buffer).cmsg_level = libc::SOL_SOCKET;
            (*cmsg_buffer).cmsg_type = SCM_RIGHTS;

            let mut fds = Vec::new();
            for channel in channels.into_iter() {
                fds.push(channel.fd());
                mem::forget(channel);
            }
            ptr::copy_nonoverlapping(fds.as_ptr(),
                                     cmsg_buffer.offset(1) as *mut _ as *mut c_int,
                                     fds.len());

            let mut iovec = iovec {
                iov_base: data.as_ptr() as *const i8 as *mut i8,
                iov_len: data.len() as size_t,
            };

            let msghdr = msghdr {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &mut iovec,
                msg_iovlen: 1,
                msg_control: cmsg_buffer as *mut c_void,
                msg_controllen: cmsg_length as size_t,
                msg_flags: 0,
            };

            let result = sendmsg(self.fd, &msghdr, 0);
            libc::free(cmsg_buffer as *mut c_void);

            if result > 0 {
                Ok(())
            } else {
                Err(Error::last_os_error().raw_os_error().unwrap())
            }
        }
    }

    pub fn connect(name: String) -> Result<UnixSender,c_int> {
        let name = CString::new(name).unwrap();
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            let mut sockaddr = sockaddr_un {
                sun_family: libc::AF_UNIX as u16,
                sun_path: [ 0; 108 ],
            };
            libc::strncpy(sockaddr.sun_path.as_mut_ptr(),
                          name.as_ptr(),
                          sockaddr.sun_path.len() as size_t);

            let len = mem::size_of::<c_short>() + (libc::strlen(sockaddr.sun_path.as_ptr()) as usize);
            if libc::connect(fd, &sockaddr as *const _ as *const sockaddr, len as c_uint) < 0 {
                return Err(Error::last_os_error().raw_os_error().unwrap())
            }

            Ok(UnixSender {
                fd: fd,
            })
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum UnixChannel {
    Sender(UnixSender),
    Receiver(UnixReceiver),
}

impl UnixChannel {
    fn fd(&self) -> c_int {
        match *self {
            UnixChannel::Sender(ref sender) => sender.fd,
            UnixChannel::Receiver(ref receiver) => receiver.fd,
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct UnknownUnixChannel {
    fd: c_int,
}

impl Drop for UnknownUnixChannel {
    fn drop(&mut self) {
        unsafe {
            debug_assert!(libc::close(self.fd) == 0)
        }
    }
}

impl UnknownUnixChannel {
    fn from_fd(fd: c_int) -> UnknownUnixChannel {
        UnknownUnixChannel {
            fd: fd,
        }
    }

    pub fn to_sender(&mut self) -> UnixSender {
        unsafe {
            UnixSender::from_fd(libc::dup(self.fd))
        }
    }

    pub fn to_receiver(&mut self) -> UnixReceiver {
        unsafe {
            UnixReceiver::from_fd(libc::dup(self.fd))
        }
    }
}

pub struct UnixOneShotServer {
    fd: c_int,
}

impl Drop for UnixOneShotServer {
    fn drop(&mut self) {
        unsafe {
            assert!(libc::close(self.fd) == 0)
        }
    }
}

impl UnixOneShotServer {
    pub fn new() -> Result<(UnixOneShotServer, String),c_int> {
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            let mut path: Vec<u8>;
            loop {
                let path_string = CString::new(b"/tmp/rust-ipc-socket.XXXXXX" as &[u8]).unwrap();
                path = path_string.as_bytes().iter().cloned().collect();
                if mktemp(path.as_mut_ptr() as *mut c_char) == ptr::null_mut() {
                    return Err(Error::last_os_error().raw_os_error().unwrap())
                }

                let mut sockaddr = sockaddr_un {
                    sun_family: libc::AF_UNIX as c_ushort,
                    sun_path: [ 0; 108 ],
                };
                libc::strncpy(sockaddr.sun_path.as_mut_ptr(),
                              path.as_ptr() as *const c_char,
                              sockaddr.sun_path.len() as size_t);

                let len = mem::size_of::<c_short>() + (libc::strlen(sockaddr.sun_path.as_ptr()) as usize);
                if libc::bind(fd, &sockaddr as *const _ as *const sockaddr, len as c_uint) == 0 {
                    break
                }

                let errno = Error::last_os_error().raw_os_error().unwrap();
                if errno != libc::EINVAL {
                    return Err(errno)
                }
            }

            if libc::listen(fd, 10) != 0 {
                return Err(Error::last_os_error().raw_os_error().unwrap())
            }

            Ok((UnixOneShotServer {
                fd: fd,
            }, String::from_utf8(CStr::from_ptr(path.as_ptr() as *const c_char).to_bytes().to_owned()).unwrap()))
        }
    }

    pub fn accept(self) -> Result<(UnixReceiver, Vec<u8>, Vec<UnknownUnixChannel>),c_int> {
        unsafe {
            let mut sockaddr = mem::uninitialized();
            let mut sockaddr_len = mem::uninitialized();
            let client_fd = libc::accept(self.fd, &mut sockaddr, &mut sockaddr_len);
            if client_fd < 0 {
                return Err(Error::last_os_error().raw_os_error().unwrap())
            }

            let receiver = UnixReceiver {
                fd: client_fd,
            };
            let (data, channels) = try!(receiver.recv());
            Ok((receiver, data, channels))
        }
    }
}

// FFI stuff follows:

const MSG_WAITALL: c_int = 0x100;
const SCM_RIGHTS: c_int = 0x01;

extern {
    fn mktemp(template: *mut c_char) -> *mut c_char;
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

#[repr(C)]
struct cmsghdr {
    cmsg_len: size_t,
    cmsg_level: c_int,
    cmsg_type: c_int,
}

