// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use bincode::serde::DeserializeError;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use libc::{self, MAP_SHARED, PROT_READ, PROT_WRITE, c_char, c_int, c_short, c_ulong};
use libc::{c_ushort, c_void, mode_t, off_t, size_t, sockaddr, sockaddr_un, socklen_t, ssize_t};
use std::cmp;
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::fmt::{self, Debug, Formatter};
use std::io::{Error, Write};
use std::mem;
use std::ops::Deref;
use std::ptr;
use std::slice;
use std::sync::atomic::{ATOMIC_USIZE_INIT, AtomicUsize, Ordering};
use std::thread;

const MAX_FDS_IN_CMSG: u32 = 64;

// Yes, really!
const MAP_FAILED: *mut u8 = (!0usize) as *mut u8;

// The value Linux returns for SO_SNDBUF
// is not the size we are actually allowed to use...
// Empirically, we have to deduct 32 bytes from that.
const RESERVED_SIZE: usize = 32;

static LAST_FRAGMENT_ID: AtomicUsize = ATOMIC_USIZE_INIT;

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

    fn consume_fd(&self) -> c_int {
        unsafe {
            libc::dup(self.fd)
        }
    }

    pub fn consume(&self) -> UnixReceiver {
        UnixReceiver::from_fd(self.consume_fd())
    }

    pub fn recv(&self)
                -> Result<(Vec<u8>, Vec<OpaqueUnixChannel>, Vec<UnixSharedMemory>),UnixError> {
        recv(self.fd, BlockingMode::Blocking)
    }

    pub fn try_recv(&self)
                    -> Result<(Vec<u8>, Vec<OpaqueUnixChannel>, Vec<UnixSharedMemory>),UnixError> {
        recv(self.fd, BlockingMode::Nonblocking)
    }
}

#[derive(PartialEq, Debug)]
pub struct UnixSender {
    fd: c_int,
}

impl Drop for UnixSender {
    fn drop(&mut self) {
        unsafe {
            let result = libc::close(self.fd);
            assert!(thread::panicking() || result == 0);
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

    /// Maximum size of the kernel buffer used for transfers over this channel.
    ///
    /// Note: This is *not* the actual maximal packet size we are allowed to use...
    /// Some of it is reserved by the kernel for bookkeeping.
    fn get_system_sendbuf_size(&self) -> Result<usize,UnixError> {
        unsafe {
            let mut socket_sendbuf_size: usize = 0;
            let mut socket_sendbuf_size_len = mem::size_of::<usize>() as socklen_t;
            if getsockopt(self.fd,
                          libc::SOL_SOCKET,
                          libc::SO_SNDBUF,
                          &mut socket_sendbuf_size as *mut usize as *mut c_void,
                          &mut socket_sendbuf_size_len as *mut socklen_t) < 0 {
                return Err(UnixError::last())
            }
            Ok(socket_sendbuf_size)
        }
    }

    /// Calculate maximum payload data size per fragment.
    ///
    /// This is the size of the main data chunk only --
    /// it's independent of any auxiliary data (FDs) transferred along with it.
    /// It is the total size of the kernel buffer,
    /// minus the part reserved by the kernel,
    /// and with the size of the fragment header also deducted from it.
    ///
    /// The `sendbuf_size` passed in should usually be the maximum kernel buffer size,
    /// as obtained with `get_system_sendbuf_size()` --
    /// except after getting ENOBUFS, in which case it needs to be reduced.
    fn fragment_size(sendbuf_size: usize) -> usize {
        sendbuf_size - RESERVED_SIZE - mem::size_of::<u32>() * 2
    }

    /// Maximum data size that can be transferred over this channel in a single packet.
    ///
    /// This is the size of the main data chunk only --
    /// it's independent of any auxiliary data (FDs) transferred along with it.
    ///
    /// A send on this channel won't block for transfers up to this size
    /// under normal circumstances.
    /// (It might still block if heavy memory pressure causes ENOBUFS,
    /// forcing us to reduce the packet size.)
    pub fn get_max_fragment_size(&self) -> Result<usize,UnixError> {
        Ok(Self::fragment_size(try!(self.get_system_sendbuf_size())))
    }

    pub fn send(&self,
                data: &[u8],
                channels: Vec<UnixChannel>,
                shared_memory_regions: Vec<UnixSharedMemory>)
                -> Result<(),UnixError> {

        let mut fds = Vec::new();
        for channel in channels.iter() {
            fds.push(channel.fd());
        }
        for shared_memory_region in shared_memory_regions.iter() {
            fds.push(shared_memory_region.fd);
        }

        let mut data_buffer = vec![0; data.len() + mem::size_of::<u32>() * 2];
        {
            let mut data_buffer = &mut data_buffer[..];
            data_buffer.write_u32::<LittleEndian>(0u32).unwrap();
            data_buffer.write_u32::<LittleEndian>(0u32).unwrap();
            data_buffer.write(data).unwrap();
        }

        unsafe {
            unsafe fn construct_header(fds: &[c_int], data_buffer: &[u8]) -> (msghdr, Box<iovec>) {
                let cmsg_length = mem::size_of_val(fds);
                let cmsg_buffer = libc::malloc(CMSG_SPACE(cmsg_length)) as *mut cmsghdr;
                (*cmsg_buffer).cmsg_len = CMSG_LEN(cmsg_length);
                (*cmsg_buffer).cmsg_level = libc::SOL_SOCKET;
                (*cmsg_buffer).cmsg_type = SCM_RIGHTS;

                ptr::copy_nonoverlapping(fds.as_ptr(),
                                         cmsg_buffer.offset(1) as *mut _ as *mut c_int,
                                         fds.len());

                // Put this on the heap so address remains stable across function return.
                let iovec = Box::new(iovec {
                    iov_base: data_buffer.as_ptr() as *const c_char as *mut c_char,
                    iov_len: data_buffer.len(),
                });

                let msghdr = msghdr {
                    msg_name: ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: &*iovec,
                    msg_iovlen: 1,
                    msg_control: cmsg_buffer as *mut c_void,
                    msg_controllen: CMSG_SPACE(cmsg_length),
                    msg_flags: 0,
                };

                // Be sure to always return iovec -- whether the caller uses it or not --
                // to prevent premature deallocation!
                (msghdr, iovec)
            };

            let mut sendbuf_size = try!(self.get_system_sendbuf_size());

            /// Reduce send buffer size after getting ENOBUFS,
            /// i.e. when the kernel failed to allocate a large enough buffer.
            ///
            /// (If the buffer already was significantly smaller
            /// than the memory page size though,
            /// if means something else must have gone wrong;
            /// so there is no point in further downsizing,
            /// and we error out instead.)
            fn downsize(sendbuf_size: &mut usize, sent_size: usize) -> Result<(),()> {
                if sent_size > 2000 {
                    *sendbuf_size /= 2;
                    Ok(())
                } else {
                    Err(())
                }
            }

            let (msghdr, _iovec) = construct_header(&fds[..], &data_buffer[..]);

            let result = sendmsg(self.fd, &msghdr, 0);
            libc::free(msghdr.msg_control);

            if result > 0 {
                return Ok(())
            } else {
                let error = UnixError::last();
                if error.0 == libc::ENOBUFS
                   && downsize(&mut sendbuf_size, data_buffer.len()).is_ok() {
                    // If we get this error,
                    // it means the message was small enough to fit the maximum send size,
                    // but the kernel failed to allocate a buffer large enough
                    // to actually transfer the message --
                    // so we have to proceed with a fragmented send nevertheless.
                } else if error.0 != libc::EMSGSIZE {
                    return Err(error)
                }
            }

            // The packet is too big. Fragmentation time!
            //
            // Create dedicated channel to send all but the first fragment.
            // This way we avoid fragments of different messages interleaving in the receiver.
            //
            // The receiver end of the channel is sent with the first fragment
            // along any other file descriptors that are to be transferred in the message.
            let (dedicated_tx, dedicated_rx) = try!(channel());
            // Extract FD handle without consuming the Receiver, so the FD doesn't get closed.
            fds.push(dedicated_rx.fd);

            // Split up the packet into fragments.
            let mut byte_position = 0;
            let mut this_fragment_id = 0;
            while byte_position < data.len() {
                let bytes_per_fragment = Self::fragment_size(sendbuf_size);

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

                    let (msghdr, _iovec) = construct_header(&fds[..],
                                                            &data_buffer[..bytes_to_send]);

                    let result = sendmsg(self.fd, &msghdr, 0);
                    libc::free(msghdr.msg_control);
                    result
                } else {
                    // Trailing fragment.
                    libc::send(dedicated_tx.fd,
                               data_buffer.as_ptr() as *const c_void,
                               bytes_to_send,
                               0)
                };

                if result <= 0 {
                    let error = UnixError::last();
                    if error.0 == libc::ENOBUFS
                       && downsize(&mut sendbuf_size, bytes_to_send).is_ok() {
                        // If the kernel failed to allocate a buffer large enough for the packet,
                        // retry with a smaller size (if possible).
                        continue
                    } else {
                        return Err(error)
                    }
                }

                byte_position += bytes_per_fragment;
                this_fragment_id = next_fragment_id;
            }

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
                          sockaddr.sun_path.len() - 1);

            let len = mem::size_of::<c_short>() + libc::strlen(sockaddr.sun_path.as_ptr());
            if libc::connect(fd, &sockaddr as *const _ as *const sockaddr, len as socklen_t) < 0 {
                return Err(UnixError::last())
            }

            Ok(UnixSender::from_fd(fd))
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
                let result = libc::close(pollfd.fd);
                assert!(thread::panicking() || result == 0);
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
                match recv(pollfd.fd, BlockingMode::Blocking) {
                    Ok((data, channels, shared_memory_regions)) => {
                        selection_results.push(UnixSelectionResult::DataReceived(
                                pollfd.fd as i64,
                                data,
                                channels,
                                shared_memory_regions));
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
    DataReceived(i64, Vec<u8>, Vec<OpaqueUnixChannel>, Vec<UnixSharedMemory>),
    ChannelClosed(i64),
}

impl UnixSelectionResult {
    pub fn unwrap(self) -> (i64, Vec<u8>, Vec<OpaqueUnixChannel>, Vec<UnixSharedMemory>) {
        match self {
            UnixSelectionResult::DataReceived(id, data, channels, shared_memory_regions) => {
                (id, data, channels, shared_memory_regions)
            }
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
            let result = libc::close(self.fd);
            assert!(thread::panicking() || result == 0);
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
                path = path_string.as_bytes_with_nul().iter().cloned().collect();
                if *mktemp(path.as_mut_ptr() as *mut c_char) == 0 {
                    return Err(UnixError::last())
                }

                let mut sockaddr = sockaddr_un {
                    sun_family: libc::AF_UNIX as c_ushort,
                    sun_path: [ 0; 108 ],
                };
                libc::strncpy(sockaddr.sun_path.as_mut_ptr(),
                              path.as_ptr() as *const c_char,
                              sockaddr.sun_path.len() - 1);

                let len = mem::size_of::<c_short>() + (libc::strlen(sockaddr.sun_path.as_ptr()) as
                                                       usize);
                if libc::bind(fd, &sockaddr as *const _ as *const sockaddr, len as socklen_t) == 0 {
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

    pub fn accept(self) -> Result<(UnixReceiver,
                                   Vec<u8>,
                                   Vec<OpaqueUnixChannel>,
                                   Vec<UnixSharedMemory>),UnixError> {
        unsafe {
            let sockaddr: *mut sockaddr = ptr::null_mut();
            let sockaddr_len: *mut socklen_t = ptr::null_mut();
            let client_fd = libc::accept(self.fd, sockaddr, sockaddr_len);
            if client_fd < 0 {
                return Err(UnixError::last())
            }
            try!(make_socket_lingering(client_fd));

            let receiver = UnixReceiver {
                fd: client_fd,
            };
            let (data, channels, shared_memory_regions) = try!(receiver.recv());
            Ok((receiver, data, channels, shared_memory_regions))
        }
    }
}

// Make sure that the kernel doesn't return errors to readers if there's still data left after we
// close our end.
//
// See, for example, https://github.com/servo/ipc-channel/issues/29
fn make_socket_lingering(sockfd: c_int) -> Result<(),UnixError> {
    let linger = linger {
        l_onoff: 1,
        l_linger: 30,
    };
    let err = unsafe {
        setsockopt(sockfd,
                   SOL_SOCKET,
                   SO_LINGER,
                   &linger as *const linger as *const c_void,
                   mem::size_of::<linger>() as socklen_t)
    };
    if err < 0 {
        return Err(UnixError::last())
    }
    Ok(())
}

pub struct UnixSharedMemory {
    ptr: *mut u8,
    length: usize,
    fd: c_int,
}

unsafe impl Send for UnixSharedMemory {}
unsafe impl Sync for UnixSharedMemory {}

impl Drop for UnixSharedMemory {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                let result = libc::munmap(self.ptr as *mut c_void, self.length);
                assert!(thread::panicking() || result == 0);
            }
            let result = libc::close(self.fd);
            assert!(thread::panicking() || result == 0);
        }
    }
}

impl Clone for UnixSharedMemory {
    fn clone(&self) -> UnixSharedMemory {
        unsafe {
            let new_fd = libc::dup(self.fd);
            let (address, _) = map_file(new_fd, Some(self.length));
            UnixSharedMemory::from_raw_parts(address, self.length, new_fd)
        }
    }
}

impl PartialEq for UnixSharedMemory {
    fn eq(&self, other: &UnixSharedMemory) -> bool {
        **self == **other
    }
}

impl Debug for UnixSharedMemory {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), fmt::Error> {
        (**self).fmt(formatter)
    }
}

impl Deref for UnixSharedMemory {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self.ptr, self.length)
        }
    }
}

impl UnixSharedMemory {
    unsafe fn from_raw_parts(ptr: *mut u8, length: usize, fd: c_int) -> UnixSharedMemory {
        UnixSharedMemory {
            ptr: ptr,
            length: length,
            fd: fd,
        }
    }

    unsafe fn from_fd(fd: c_int) -> UnixSharedMemory {
        let (ptr, length) = map_file(fd, None);
        UnixSharedMemory::from_raw_parts(ptr, length, fd)
    }

    pub fn from_byte(byte: u8, length: usize) -> UnixSharedMemory {
        unsafe {
            let fd = create_memory_backing_store(length);
            let (address, _) = map_file(fd, Some(length));
            for element in slice::from_raw_parts_mut(address, length) {
                *element = byte;
            }
            UnixSharedMemory::from_raw_parts(address, length, fd)
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> UnixSharedMemory {
        unsafe {
            let fd = create_memory_backing_store(bytes.len());
            let (address, _) = map_file(fd, Some(bytes.len()));
            ptr::copy_nonoverlapping(bytes.as_ptr(), address, bytes.len());
            UnixSharedMemory::from_raw_parts(address, bytes.len(), fd)
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

impl From<UnixError> for DeserializeError {
    fn from(unix_error: UnixError) -> DeserializeError {
        DeserializeError::IoError(unix_error.into())
    }
}

impl From<UnixError> for Error {
    fn from(unix_error: UnixError) -> Error {
        Error::from_raw_os_error(unix_error.0)
    }
}

#[derive(Copy, Clone)]
enum BlockingMode {
    Blocking,
    Nonblocking,
}

fn recv(fd: c_int, blocking_mode: BlockingMode)
        -> Result<(Vec<u8>, Vec<OpaqueUnixChannel>, Vec<UnixSharedMemory>),UnixError> {
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
        let bytes_read = try!(cmsg.recv(fd, blocking_mode));

        let cmsg_fds = cmsg.cmsg_buffer.offset(1) as *const u8 as *const c_int;
        let cmsg_length = cmsg.msghdr.msg_controllen;
        let channel_length = if cmsg_length == 0 {
            0
        } else {
            (cmsg.cmsg_len() - mem::size_of::<cmsghdr>()) / mem::size_of::<c_int>()
        };
        let (mut channels, mut shared_memory_regions) = (Vec::new(), Vec::new());
        for index in 0..channel_length {
            let fd = *cmsg_fds.offset(index as isize);
            if is_socket(fd) {
                channels.push(OpaqueUnixChannel::from_fd(fd));
                continue
            }
            shared_memory_regions.push(UnixSharedMemory::from_fd(fd));
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
            return Ok((main_data_buffer, channels, shared_memory_regions))
        }

        // Reassemble fragments.
        //
        // The initial fragment carries the receive end of a dedicated channel
        // through which all the remaining fragments will be coming in.
        let dedicated_rx = channels.pop().unwrap().to_receiver();
        while next_fragment_id != 0 {
            let mut cmsg = UnixCmsg::new(maximum_recv_size - RESERVED_SIZE);
            // Always use blocking mode for followup fragments,
            // to make sure that once we start receiving a multi-fragment message,
            // we don't abort in the middle of it...
            let bytes_read = try!(cmsg.recv(dedicated_rx.fd, BlockingMode::Blocking));

            let this_fragment_id =
                (&cmsg.data_buffer[0..mem::size_of::<u32>()]).read_u32::<LittleEndian>().unwrap();
            assert!(this_fragment_id == next_fragment_id);

            next_fragment_id =
                (&cmsg.data_buffer[mem::size_of::<u32>()..
                                   (mem::size_of::<u32>() * 2)]).read_u32::<LittleEndian>()
                                                                .unwrap();
            main_data_buffer.extend(
                    cmsg.data_buffer[(mem::size_of::<u32>() * 2)..bytes_read].iter().cloned())
        }

        Ok((main_data_buffer, channels, shared_memory_regions))
    }
}

#[cfg(target_os="android")]
const TEMP_FILE_TEMPLATE: &'static str = "/sdcard/servo/ipc-channel-shared-memory.XXXXXX";

#[cfg(not(target_os="android"))]
const TEMP_FILE_TEMPLATE: &'static str = "/tmp/ipc-channel-shared-memory.XXXXXX";

#[cfg(target_os="android")]
fn maybe_unlink(_: *const c_char) -> c_int {
    // Calling `unlink` on a file stored on an sdcard immediately deletes it.
    // FIXME: use a better temporary directory than the sdcard via the Java APIs
    // and threading that value into Servo.
    // https://code.google.com/p/android/issues/detail?id=19017
    0
}

#[cfg(not(target_os="android"))]
unsafe fn maybe_unlink(c: *const c_char) -> c_int {
    libc::unlink(c)
}

unsafe fn create_memory_backing_store(length: usize) -> c_int {
    let string = CString::new(TEMP_FILE_TEMPLATE).unwrap();
    let string_buffer = strdup(string.as_ptr());
    let fd = mkstemp(string_buffer);
    assert!(fd >= 0);
    assert!(maybe_unlink(string_buffer) == 0);
    libc::free(string_buffer as *mut c_void);
    assert!(libc::ftruncate(fd, length as off_t) == 0);
    fd
}

unsafe fn map_file(fd: c_int, length: Option<size_t>) -> (*mut u8, size_t) {
    let length = length.unwrap_or_else(|| {
        let mut st = mem::uninitialized();
        assert!(libc::fstat(fd, &mut st) == 0);
        st.st_size as size_t
    });
    if length == 0 {
        // This will cause `mmap` to fail, so handle it explicitly.
        return (ptr::null_mut(), length)
    }
    let address = libc::mmap(ptr::null_mut(),
                             length,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED,
                             fd,
                             0) as *mut u8;
    assert!(address != ptr::null_mut());
    assert!(address != MAP_FAILED);
    (address, length)
}

struct UnixCmsg {
    data_buffer: Vec<u8>,
    cmsg_buffer: *mut cmsghdr,
    #[allow(dead_code)]
    iovec: Box<iovec>,
    msghdr: msghdr,
}

unsafe impl Send for UnixCmsg {}

impl Drop for UnixCmsg {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.cmsg_buffer as *mut c_void);
        }
    }
}

impl UnixCmsg {
    unsafe fn new(maximum_recv_size: usize) -> UnixCmsg {
        let cmsg_length = mem::size_of::<cmsghdr>() + (MAX_FDS_IN_CMSG as usize) *
            mem::size_of::<c_int>();
        assert!(maximum_recv_size > cmsg_length);
        let mut data_buffer: Vec<u8> = vec![0; maximum_recv_size];
        let cmsg_buffer = libc::malloc(cmsg_length) as *mut cmsghdr;
        let iovec = Box::new(iovec {
            iov_base: &mut data_buffer[0] as *mut _ as *mut c_char,
            iov_len: data_buffer.len(),
        });
        let iovec_ptr: *const iovec = &*iovec;
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
                msg_controllen: cmsg_length,
                msg_flags: 0,
            },
        }
    }

    unsafe fn recv(&mut self, fd: c_int, blocking_mode: BlockingMode)
                   -> Result<usize, UnixError> {
        if let BlockingMode::Nonblocking = blocking_mode {
            if libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) < 0 {
                return Err(UnixError::last())
            }
        }

        let result = recvmsg(fd, &mut self.msghdr, 0);
        let result = if result > 0 {
            Ok(result as usize)
        } else if result == 0 {
            Err(UnixError(libc::ECONNRESET))
        } else {
            Err(UnixError::last())
        };

        if let BlockingMode::Nonblocking = blocking_mode {
            if libc::fcntl(fd, libc::F_SETFL, 0) < 0 {
                return Err(UnixError::last())
            }
        }
        result
    }

    unsafe fn cmsg_len(&self) -> size_t {
        (*(self.msghdr.msg_control as *const cmsghdr)).cmsg_len
    }
}

fn is_socket(fd: c_int) -> bool {
    unsafe {
        let mut st = mem::uninitialized();
        if libc::fstat(fd, &mut st) != 0 {
            return false
        }
        S_ISSOCK(st.st_mode as mode_t)
    }
}

// FFI stuff follows:

const POLLIN: c_short = 0x01;
const SCM_RIGHTS: c_int = 0x01;
const SOCK_SEQPACKET: c_int = 0x05;
const SOL_SOCKET: c_int = 1;
const SO_LINGER: c_int = 13;
const S_IFMT: mode_t = 0o00170000;
const S_IFSOCK: mode_t = 0o0140000;

#[allow(non_camel_case_types)]
type nfds_t = c_ulong;

#[allow(non_snake_case)]
fn CMSG_LEN(length: size_t) -> size_t {
    CMSG_ALIGN(mem::size_of::<cmsghdr>()) + length
}

#[allow(non_snake_case)]
fn CMSG_ALIGN(length: size_t) -> size_t {
    (length + mem::size_of::<size_t>() - 1) & !(mem::size_of::<size_t>() - 1)
}

#[allow(non_snake_case)]
fn CMSG_SPACE(length: size_t) -> size_t {
    CMSG_ALIGN(length) + CMSG_ALIGN(mem::size_of::<cmsghdr>())
}

#[allow(non_snake_case)]
fn S_ISSOCK(mode: mode_t) -> bool {
    (mode & S_IFMT) == S_IFSOCK
}

extern {
    fn getsockopt(sockfd: c_int,
                  level: c_int,
                  optname: c_int,
                  optval: *mut c_void,
                  optlen: *mut socklen_t)
                  -> c_int;
    fn mkstemp(template: *mut c_char) -> c_int;
    fn mktemp(template: *mut c_char) -> *mut c_char;
    fn poll(fds: *mut pollfd, nfds: nfds_t, timeout: c_int) -> c_int;
    fn recvmsg(socket: c_int, message: *mut msghdr, flags: c_int) -> ssize_t;
    fn sendmsg(socket: c_int, message: *const msghdr, flags: c_int) -> ssize_t;
    fn setsockopt(socket: c_int,
                  level: c_int,
                  option_name: c_int,
                  option_value: *const c_void,
                  option_len: socklen_t)
                  -> c_int;
    fn socketpair(domain: c_int, socket_type: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    fn strdup(string: *const c_char) -> *mut c_char;
}

#[repr(C)]
struct msghdr {
    msg_name: *mut c_void,
    msg_namelen: socklen_t,
    msg_iov: *const iovec,
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

#[repr(C)]
struct linger {
    l_onoff: c_int,
    l_linger: c_int,
}

