// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use libc::{self, c_char, c_int, c_short, c_uint, c_ulong, c_ushort, c_void, size_t, sockaddr};
use libc::{sockaddr_un, socklen_t, ssize_t};
use std::cmp;
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Error, Write};
use std::mem;
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::sync::atomic::{ATOMIC_USIZE_INIT, AtomicUsize, Ordering};

const DEV_NULL_RDEV: libc::dev_t = 0x0103;
const MAX_FDS_IN_CMSG: u32 = 64;

static LAST_FRAGMENT_ID: AtomicUsize = ATOMIC_USIZE_INIT;

lazy_static! {
    static ref DEV_NULL: c_int = open_dev_null();
}

pub fn channel() -> Result<(UnixSender, UnixReceiver),UnixError> {
    let mut results = [0, 0];
    unsafe {
        if socketpair(libc::AF_UNIX, SOCK_SEQPACKET, 0, &mut results[0]) >= 0 {
            Ok((UnixSender::from_fd(results[0]), UnixReceiver::from_fd(results[1])))
        } else {
            Err(UnixError::last())
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
            //assert!(libc::close(self.fd) == 0)
            libc::close(self.fd);
        }
    }
}

impl UnixReceiver {
    fn from_fd(fd: c_int) -> UnixReceiver {
        UnixReceiver {
            fd: fd,
        }
    }

    pub fn consume_fd(&self) -> c_int {
        unsafe {
            libc::dup(self.fd)
        }
    }

    pub fn consume(&self) -> UnixReceiver {
        UnixReceiver::from_fd(self.consume_fd())
    }

    pub fn recv(&self) -> Result<(Vec<u8>, Vec<OpaqueUnixChannel>),UnixError> {
        recv(self.fd)
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

    pub fn send(&self, data: &[u8], channels: Vec<UnixChannel>) -> Result<(),UnixError> {
        let mut data_buffer = vec![0; data.len() + mem::size_of::<u32>() * 2];
        {
            let mut data_buffer = &mut data_buffer[..];
            data_buffer.write_u32::<LittleEndian>(0u32).unwrap();
            data_buffer.write_u32::<LittleEndian>(0u32).unwrap();
            data_buffer.write(data).unwrap();
        }

        unsafe {
            let cmsg_length = channels.len() * mem::size_of::<c_int>();
            let cmsg_buffer = libc::malloc(CMSG_SPACE(cmsg_length as size_t)) as *mut cmsghdr;
            (*cmsg_buffer).cmsg_len = CMSG_LEN(cmsg_length as size_t);
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
            let mut cmsg_padding_ptr =
                (cmsg_buffer.offset(1) as *mut _ as *mut c_int).offset(fds.len() as isize);
            let cmsg_end =
                (cmsg_buffer as *mut _ as *mut u8).offset(CMSG_SPACE(cmsg_length as size_t) as
                                                          isize);
            while (cmsg_padding_ptr as *mut u8) < cmsg_end {
                *cmsg_padding_ptr = *DEV_NULL;
                cmsg_padding_ptr = cmsg_padding_ptr.offset(1);
            }

            let mut iovec = iovec {
                iov_base: data_buffer.as_ptr() as *const c_char as *mut c_char,
                iov_len: data_buffer.len() as size_t,
            };

            let msghdr = msghdr {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &mut iovec,
                msg_iovlen: 1,
                msg_control: cmsg_buffer as *mut c_void,
                msg_controllen: CMSG_SPACE(cmsg_length as size_t),
                msg_flags: 0,
            };

            let result = sendmsg(self.fd, &msghdr, 0);

            if result > 0 {
                libc::free(cmsg_buffer as *mut c_void);
                return Ok(())
            } else {
                let error = UnixError::last();
                if error.0 != libc::EMSGSIZE {
                    libc::free(cmsg_buffer as *mut c_void);
                    return Err(error)
                }
            }

            // The packet is too big. Fragmentation time! First, determine our maximum sending size.
            let mut maximum_send_size: usize = 0;
            let mut maximum_send_size_len = mem::size_of::<usize>() as socklen_t;
            if getsockopt(self.fd,
                          libc::SOL_SOCKET,
                          libc::SO_SNDBUF,
                          &mut maximum_send_size as *mut usize as *mut c_void,
                          &mut maximum_send_size_len as *mut socklen_t) < 0 {
                return Err(UnixError::last())
            }
            let bytes_per_fragment = maximum_send_size - (mem::size_of::<usize>() +
                CMSG_SPACE(cmsg_length as size_t) as usize + 256);

            // Split up the packet into fragments.
            let mut byte_position = 0;
            let mut this_fragment_id = 0;
            while byte_position < data.len() {
                let end_byte_position = cmp::min(data.len(), byte_position + bytes_per_fragment);
                let next_fragment_id = if end_byte_position == data.len() {
                    0
                } else {
                    (LAST_FRAGMENT_ID.fetch_add(1, Ordering::SeqCst) + 1) as u32
                };

                {
                    let mut data_buffer = &mut data_buffer[..];
                    data_buffer.write_u32::<LittleEndian>(this_fragment_id).unwrap();
                    data_buffer.write_u32::<LittleEndian>(next_fragment_id).unwrap();
                    data_buffer.write(&data[byte_position..end_byte_position]).unwrap();
                }

                let bytes_to_send = end_byte_position - byte_position + mem::size_of::<u32>() * 2;
                let result = if byte_position == 0 {
                    // First one. This fragment includes the file descriptors.

                    // Better reset this in case `data_buffer` moved around -- iterator
                    // invalidation!
                    iovec.iov_base = data_buffer.as_ptr() as *const c_char as *mut c_char;
                    iovec.iov_len = bytes_to_send as size_t;

                    sendmsg(self.fd, &msghdr, 0)
                } else {
                    // Trailing fragment.
                    libc::send(self.fd,
                               data_buffer.as_ptr() as *const c_void,
                               bytes_to_send as size_t,
                               0)
                };

                if result <= 0 {
                    return Err(UnixError::last())
                }

                byte_position += bytes_per_fragment;
                this_fragment_id = next_fragment_id;
            }

            libc::free(cmsg_buffer as *mut c_void);
            Ok(())
        }
    }

    pub fn connect(name: String) -> Result<UnixSender,UnixError> {
        let name = CString::new(name).unwrap();
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, SOCK_SEQPACKET, 0);
            let mut sockaddr = sockaddr_un {
                sun_family: libc::AF_UNIX as u16,
                sun_path: [ 0; 108 ],
            };
            libc::strncpy(sockaddr.sun_path.as_mut_ptr(),
                          name.as_ptr(),
                          sockaddr.sun_path.len() as size_t);

            let len = mem::size_of::<c_short>() +
                (libc::strlen(sockaddr.sun_path.as_ptr()) as usize);
            if libc::connect(fd, &sockaddr as *const _ as *const sockaddr, len as c_uint) < 0 {
                return Err(UnixError::last())
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

pub struct UnixReceiverSet {
    pollfds: Vec<pollfd>,
}

impl Drop for UnixReceiverSet {
    fn drop(&mut self) {
        unsafe {
            for pollfd in self.pollfds.iter() {
                assert!(libc::close(pollfd.fd) >= 0);
            }
        }
    }
}

impl UnixReceiverSet {
    pub fn new() -> Result<UnixReceiverSet,UnixError> {
        Ok(UnixReceiverSet {
            pollfds: Vec::new(),
        })
    }

    pub fn add(&mut self, receiver: UnixReceiver) -> Result<i64,UnixError> {
        let fd = receiver.consume_fd();
        self.pollfds.push(pollfd {
            fd: fd,
            events: POLLIN,
            revents: 0,
        });
        Ok(fd as i64)
    }

    pub fn select(&mut self) -> Result<Vec<UnixSelectionResult>,UnixError> {
        let mut selection_results = Vec::new();
        let result = unsafe {
            poll(self.pollfds.as_mut_ptr(), self.pollfds.len() as nfds_t, -1)
        };
        if result <= 0 {
            return Err(UnixError::last())
        }

        let mut hangups = HashSet::new();
        for pollfd in self.pollfds.iter_mut() {
            if (pollfd.revents & POLLIN) != 0 {
                match recv(pollfd.fd) {
                    Ok((data, channels)) => {
                        selection_results.push(UnixSelectionResult::DataReceived(pollfd.fd as i64,
                                                                                 data,
                                                                                 channels));
                    }
                    Err(err) if err.channel_is_closed() => {
                        hangups.insert(pollfd.fd);
                        selection_results.push(UnixSelectionResult::ChannelClosed(
                                    pollfd.fd as i64))
                    }
                    Err(err) => return Err(err),
                }
                pollfd.revents = pollfd.revents & !POLLIN
            }
        }

        if !hangups.is_empty() {
            self.pollfds.retain(|pollfd| !hangups.contains(&pollfd.fd));
        }

        Ok(selection_results)
    }
}

pub enum UnixSelectionResult {
    DataReceived(i64, Vec<u8>, Vec<OpaqueUnixChannel>),
    ChannelClosed(i64),
}

impl UnixSelectionResult {
    pub fn unwrap(self) -> (i64, Vec<u8>, Vec<OpaqueUnixChannel>) {
        match self {
            UnixSelectionResult::DataReceived(id, data, channels) => (id, data, channels),
            UnixSelectionResult::ChannelClosed(id) => {
                panic!("UnixSelectionResult::unwrap(): receiver ID {} was closed!", id)
            }
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct OpaqueUnixChannel {
    fd: c_int,
}

impl Drop for OpaqueUnixChannel {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd); 
        }
    }
}

impl OpaqueUnixChannel {
    fn from_fd(fd: c_int) -> OpaqueUnixChannel {
        OpaqueUnixChannel {
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
    pub fn new() -> Result<(UnixOneShotServer, String),UnixError> {
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, SOCK_SEQPACKET, 0);
            let mut path: Vec<u8>;
            loop {
                let path_string = CString::new(b"/tmp/rust-ipc-socket.XXXXXX" as &[u8]).unwrap();
                path = path_string.as_bytes().iter().cloned().collect();
                if mktemp(path.as_mut_ptr() as *mut c_char) == ptr::null_mut() {
                    return Err(UnixError::last())
                }

                let mut sockaddr = sockaddr_un {
                    sun_family: libc::AF_UNIX as c_ushort,
                    sun_path: [ 0; 108 ],
                };
                libc::strncpy(sockaddr.sun_path.as_mut_ptr(),
                              path.as_ptr() as *const c_char,
                              sockaddr.sun_path.len() as size_t);

                let len = mem::size_of::<c_short>() + (libc::strlen(sockaddr.sun_path.as_ptr()) as
                                                       usize);
                if libc::bind(fd, &sockaddr as *const _ as *const sockaddr, len as c_uint) == 0 {
                    break
                }

                let errno = UnixError::last();
                if errno.0 != libc::EINVAL {
                    return Err(errno)
                }
            }

            if libc::listen(fd, 10) != 0 {
                return Err(UnixError::last())
            }

            Ok((UnixOneShotServer {
                fd: fd,
            }, String::from_utf8(CStr::from_ptr(path.as_ptr() as
                                                *const c_char).to_bytes().to_owned()).unwrap()))
        }
    }

    pub fn accept(self) -> Result<(UnixReceiver, Vec<u8>, Vec<OpaqueUnixChannel>),UnixError> {
        unsafe {
            let mut sockaddr = mem::uninitialized();
            let mut sockaddr_len = mem::uninitialized();
            let client_fd = libc::accept(self.fd, &mut sockaddr, &mut sockaddr_len);
            if client_fd < 0 {
                return Err(UnixError::last())
            }

            let receiver = UnixReceiver {
                fd: client_fd,
            };
            let (data, channels) = try!(receiver.recv());
            Ok((receiver, data, channels))
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct UnixError(c_int);

impl UnixError {
    fn last() -> UnixError {
        UnixError(Error::last_os_error().raw_os_error().unwrap())
    }

    #[allow(dead_code)]
    pub fn channel_is_closed(&self) -> bool {
        self.0 == libc::ECONNRESET
    }
}

fn recv(fd: c_int) -> Result<(Vec<u8>, Vec<OpaqueUnixChannel>),UnixError> {
    unsafe {
        let mut maximum_recv_size: usize = 0;
        let mut maximum_recv_size_len = mem::size_of::<usize>() as socklen_t;
        if getsockopt(fd,
                      libc::SOL_SOCKET,
                      libc::SO_RCVBUF,
                      &mut maximum_recv_size as *mut usize as *mut c_void,
                      &mut maximum_recv_size_len as *mut socklen_t) < 0 {
            return Err(UnixError::last())
        }

        let mut cmsg = UnixCmsg::new(maximum_recv_size);
        let bytes_read = try!(cmsg.recv(fd)) as usize;

        let cmsg_fds = cmsg.cmsg_buffer.offset(1) as *const u8 as *const c_int;
        let cmsg_length = cmsg.msghdr.msg_controllen;
        let channel_length = if cmsg_length == 0 {
            0
        } else {
            ((cmsg.cmsg_len() as usize) - mem::size_of::<cmsghdr>()) / mem::size_of::<c_int>()
        };
        let mut channels = Vec::new();
        for index in 0..channel_length {
            let fd = *cmsg_fds.offset(index as isize);
            if !is_dev_null(fd) {
                channels.push(OpaqueUnixChannel::from_fd(fd))
            }
        }

        // Separate out the fragmentation frame.
        let (fragment_info_buffer, main_data_buffer) = cmsg.data_buffer
                                                           .split_at(mem::size_of::<u32>() * 2);
        let mut main_data_buffer: Vec<u8> =
            main_data_buffer[0..(bytes_read - mem::size_of::<u32>() * 2)].iter()
                                                                         .cloned()
                                                                         .collect();
        let mut next_fragment_id =
            (&fragment_info_buffer[mem::size_of::<u32>()..
                                   (mem::size_of::<u32>() * 2)]).read_u32::<LittleEndian>()
                                                                .unwrap();
        if next_fragment_id == 0 {
            // Fast path: no fragments.
            return Ok((main_data_buffer, channels))
        }

        // Reassemble fragments.
        let mut leftover_fragments = Vec::new();
        while next_fragment_id != 0 {
            let mut cmsg = UnixCmsg::new(maximum_recv_size);
            let bytes_read = try!(cmsg.recv(fd)) as usize;

            let this_fragment_id =
                (&cmsg.data_buffer[0..mem::size_of::<u32>()]).read_u32::<LittleEndian>().unwrap();
            if this_fragment_id != next_fragment_id {
                // Not the fragment we're looking for. Save it and continue.
                leftover_fragments.push(cmsg);
                continue
            }

            // OK, it's the next fragment in the chain. Store its data.
            next_fragment_id =
                (&cmsg.data_buffer[mem::size_of::<u32>()..
                                   (mem::size_of::<u32>() * 2)]).read_u32::<LittleEndian>()
                                                                .unwrap();
            main_data_buffer.extend(
                    cmsg.data_buffer[(mem::size_of::<u32>() * 2)..bytes_read].iter().cloned())
        }

        // Push back any leftovers.
        for mut leftover_fragment in leftover_fragments.into_iter() {
            try!(leftover_fragment.send(fd));
        }

        Ok((main_data_buffer, channels))
    }
}

struct UnixCmsg {
    data_buffer: Vec<u8>,
    cmsg_buffer: *mut cmsghdr,
    #[allow(dead_code)]
    iovec: Box<iovec>,
    msghdr: msghdr,
}

impl Drop for UnixCmsg {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.cmsg_buffer as *mut c_void);
        }
    }
}

impl UnixCmsg {
    unsafe fn new(maximum_recv_size: usize) -> UnixCmsg {
        let cmsg_length = mem::size_of::<cmsghdr>() + (MAX_FDS_IN_CMSG as usize) * mem::size_of::<c_int>();
        assert!(maximum_recv_size > cmsg_length);
        let data_length = maximum_recv_size - cmsg_length;
        let mut data_buffer: Vec<u8> = vec![0; data_length];
        let cmsg_buffer = libc::malloc(cmsg_length as size_t) as *mut cmsghdr;
        let mut iovec = Box::new(iovec {
            iov_base: &mut data_buffer[0] as *mut _ as *mut c_char,
            iov_len: data_length as size_t,
        });
        let iovec_ptr: *mut iovec = &mut *iovec;
        UnixCmsg {
            data_buffer: data_buffer,
            cmsg_buffer: cmsg_buffer,
            iovec: iovec,
            msghdr: msghdr {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: iovec_ptr,
                msg_iovlen: 1,
                msg_control: cmsg_buffer as *mut c_void,
                msg_controllen: cmsg_length as size_t,
                msg_flags: 0,
            },
        }
    }

    unsafe fn recv(&mut self, fd: c_int) -> Result<ssize_t, UnixError> {
        let result = recvmsg(fd, &mut self.msghdr, 0);
        if result > 0 {
            Ok(result)
        } else if result == 0 {
            Err(UnixError(libc::ECONNRESET))
        } else {
            Err(UnixError::last())
        }
    }

    unsafe fn send(&mut self, fd: c_int) -> Result<(), UnixError> {
        let result = sendmsg(fd, &mut self.msghdr, 0);
        if result > 0 {
            Ok(())
        } else {
            Err(UnixError::last())
        }
    }

    unsafe fn cmsg_len(&self) -> size_t {
        (*(self.msghdr.msg_control as *const cmsghdr)).cmsg_len
    }
}

fn open_dev_null() -> c_int {
    let file = File::open("/dev/null").unwrap();
    let fd = file.as_raw_fd();
    mem::forget(file);
    fd
}

fn is_dev_null(fd: c_int) -> bool {
    unsafe {
        let mut st = mem::uninitialized();
        if libc::fstat(fd, &mut st) != 0 {
            return false
        }
        st.st_rdev == DEV_NULL_RDEV
    }
}

// FFI stuff follows:

const POLLIN: c_short = 0x01;
const SCM_RIGHTS: c_int = 0x01;
const SOCK_SEQPACKET: c_int = 0x05;

#[allow(non_camel_case_types)]
type nfds_t = c_ulong;

#[allow(non_snake_case)]
fn CMSG_LEN(length: size_t) -> size_t {
    CMSG_ALIGN((mem::size_of::<cmsghdr>() as size_t) + length)
}

#[allow(non_snake_case)]
fn CMSG_ALIGN(length: size_t) -> size_t {
    (length + (mem::size_of::<size_t>() as size_t) - 1) & ((!(mem::size_of::<size_t>() - 1)) as size_t)
}

#[allow(non_snake_case)]
fn CMSG_SPACE(length: size_t) -> size_t {
    CMSG_ALIGN(length) + CMSG_ALIGN(mem::size_of::<cmsghdr>() as size_t)
}

extern {
    fn getsockopt(sockfd: c_int, level: c_int, optname: c_int, optval: *mut c_void, optlen: *mut socklen_t)
                  -> c_int;
    fn mktemp(template: *mut c_char) -> *mut c_char;
    fn poll(fds: *mut pollfd, nfds: nfds_t, timeout: c_int) -> c_int;
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

#[repr(C)]
struct pollfd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

