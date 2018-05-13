// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use bincode;
use fnv::FnvHasher;
use libc::{self, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, SOCK_SEQPACKET, SOL_SOCKET};
use libc::{SO_LINGER, S_IFMT, S_IFSOCK, c_char, c_int, c_void, getsockopt};
use libc::{iovec, mode_t, msghdr, off_t, recvmsg, sendmsg};
use libc::{setsockopt, size_t, sockaddr, sockaddr_un, socketpair, socklen_t, sa_family_t};
use std::cell::Cell;
use std::cmp;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fmt::{self, Debug, Formatter};
use std::hash::BuildHasherDefault;
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, RangeFrom};
use std::ptr;
use std::slice;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::time::UNIX_EPOCH;
use std::thread;
use mio::unix::EventedFd;
use mio::{Poll, Token, Events, Ready, PollOpt};

const MAX_FDS_IN_CMSG: u32 = 64;

const SCM_RIGHTS: c_int = 0x01;

// The value Linux returns for SO_SNDBUF
// is not the size we are actually allowed to use...
// Empirically, we have to deduct 32 bytes from that.
const RESERVED_SIZE: usize = 32;

#[cfg(target_os = "linux")]
type IovLen = usize;
#[cfg(target_os = "linux")]
type MsgControlLen = size_t;

#[cfg(any(target_os = "openbsd", target_os = "freebsd"))]
type IovLen = i32;
#[cfg(any(target_os = "openbsd", target_os = "freebsd"))]
type MsgControlLen = socklen_t;

unsafe fn new_sockaddr_un(path: *const c_char) -> (sockaddr_un, usize) {
    let mut sockaddr: sockaddr_un = mem::zeroed();
    libc::strncpy(sockaddr.sun_path.as_mut_ptr(),
                  path, sockaddr.sun_path.len() - 1);
    sockaddr.sun_family = libc::AF_UNIX as sa_family_t;
    (sockaddr, mem::size_of::<sockaddr_un>())
}

lazy_static! {
    static ref SYSTEM_SENDBUF_SIZE: usize = {
        let (tx, _) = channel().expect("Failed to obtain a socket for checking maximum send size");
        tx.get_system_sendbuf_size().expect("Failed to obtain maximum send size for socket")
    };
}

// The pid of the current process which is used to create unique IDs
lazy_static! {
    static ref PID: c_int = unsafe { libc::getpid() };
}

// A global count used to create unique IDs
static SHM_COUNT: AtomicUsize = ATOMIC_USIZE_INIT;

pub fn channel() -> Result<(OsIpcSender, OsIpcReceiver),UnixError> {
    let mut results = [0, 0];
    unsafe {
        if socketpair(libc::AF_UNIX, SOCK_SEQPACKET, 0, &mut results[0]) >= 0 {
            Ok((OsIpcSender::from_fd(results[0]), OsIpcReceiver::from_fd(results[1])))
        } else {
            Err(UnixError::last())
        }
    }
}

#[derive(Clone, Copy)]
struct PollEntry {
    pub id: u64,
    pub fd: c_int
}

#[derive(PartialEq, Debug)]
pub struct OsIpcReceiver {
    fd: Cell<c_int>,
}

impl Drop for OsIpcReceiver {
    fn drop(&mut self) {
        unsafe {
            if self.fd.get() >= 0 {
                let result = libc::close(self.fd.get());
                assert!(thread::panicking() || result == 0);
            }
        }
    }
}

impl OsIpcReceiver {
    fn from_fd(fd: c_int) -> OsIpcReceiver {
        OsIpcReceiver {
            fd: Cell::new(fd),
        }
    }

    fn consume_fd(&self) -> c_int {
        let fd = self.fd.get();
        self.fd.set(-1);
        fd
    }

    pub fn consume(&self) -> OsIpcReceiver {
        OsIpcReceiver::from_fd(self.consume_fd())
    }

    pub fn recv(&self)
                -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),UnixError> {
        recv(self.fd.get(), BlockingMode::Blocking)
    }

    pub fn try_recv(&self)
                    -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),UnixError> {
        recv(self.fd.get(), BlockingMode::Nonblocking)
    }
}

#[derive(PartialEq, Debug)]
struct SharedFileDescriptor(c_int);

impl Drop for SharedFileDescriptor {
    fn drop(&mut self) {
        unsafe {
            let result = libc::close(self.0);
            assert!(thread::panicking() || result == 0);
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct OsIpcSender {
    fd: Arc<SharedFileDescriptor>,
    // Make sure this is `!Sync`, to match `mpsc::Sender`; and to discourage sharing references.
    //
    // (Rather, senders should just be cloned, as they are shared internally anyway --
    // another layer of sharing only adds unnecessary overhead...)
    nosync_marker: PhantomData<Cell<()>>,
}

impl OsIpcSender {
    fn from_fd(fd: c_int) -> OsIpcSender {
        OsIpcSender {
            fd: Arc::new(SharedFileDescriptor(fd)),
            nosync_marker: PhantomData,
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
            if getsockopt(self.fd.0,
                          libc::SOL_SOCKET,
                          libc::SO_SNDBUF,
                          &mut socket_sendbuf_size as *mut _ as *mut c_void,
                          &mut socket_sendbuf_size_len as *mut socklen_t) < 0 {
                return Err(UnixError::last())
            }
            Ok(socket_sendbuf_size)
        }
    }

    /// Calculate maximum payload data size per fragment.
    ///
    /// It is the total size of the kernel buffer, minus the part reserved by the kernel.
    ///
    /// The `sendbuf_size` passed in should usually be the maximum kernel buffer size,
    /// i.e. the value of *SYSTEM_SENDBUF_SIZE --
    /// except after getting ENOBUFS, in which case it needs to be reduced.
    fn fragment_size(sendbuf_size: usize) -> usize {
        sendbuf_size - RESERVED_SIZE
    }

    /// Calculate maximum payload data size of first fragment.
    ///
    /// This one is smaller than regular fragments, because it carries the message (size) header.
    fn first_fragment_size(sendbuf_size: usize) -> usize {
        (Self::fragment_size(sendbuf_size) - mem::size_of::<usize>())
            & (!8usize + 1) // Ensure optimal alignment.
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
    pub fn get_max_fragment_size() -> usize {
        Self::first_fragment_size(*SYSTEM_SENDBUF_SIZE)
    }

    pub fn send(&self,
                data: &[u8],
                channels: Vec<OsIpcChannel>,
                shared_memory_regions: Vec<OsIpcSharedMemory>)
                -> Result<(),UnixError> {

        let mut fds = Vec::new();
        for channel in channels.iter() {
            fds.push(channel.fd());
        }
        for shared_memory_region in shared_memory_regions.iter() {
            fds.push(shared_memory_region.store.fd());
        }

        // `len` is the total length of the message.
        // Its value will be sent as a message header before the payload data.
        //
        // Not to be confused with the length of the data to send in this packet
        // (i.e. the length of the data buffer passed in),
        // which in a fragmented send will be smaller than the total message length.
        fn send_first_fragment(sender_fd: c_int, fds: &[c_int], data_buffer: &[u8], len: usize)
                               -> Result<(),UnixError> {
            let result = unsafe {
                let cmsg_length = mem::size_of_val(fds);
                let (cmsg_buffer, cmsg_space) = if cmsg_length > 0 {
                    let cmsg_buffer = libc::malloc(CMSG_SPACE(cmsg_length)) as *mut cmsghdr;
                    (*cmsg_buffer).cmsg_len = CMSG_LEN(cmsg_length) as MsgControlLen;
                    (*cmsg_buffer).cmsg_level = libc::SOL_SOCKET;
                    (*cmsg_buffer).cmsg_type = SCM_RIGHTS;

                    ptr::copy_nonoverlapping(fds.as_ptr(),
                                             CMSG_DATA(cmsg_buffer) as *mut c_int,
                                             fds.len());
                    (cmsg_buffer, CMSG_SPACE(cmsg_length))
                } else {
                    (ptr::null_mut(), 0)
                };

                let mut iovec = [
                    // First fragment begins with a header recording the total data length.
                    //
                    // The receiver uses this to determine
                    // whether it already got the entire message,
                    // or needs to receive additional fragments -- and if so, how much.
                    iovec {
                        iov_base: &len as *const _ as *mut c_void,
                        iov_len: mem::size_of_val(&len),
                    },
                    iovec {
                        iov_base: data_buffer.as_ptr() as *mut c_void,
                        iov_len: data_buffer.len(),
                    },
                ];

                let msghdr = msghdr {
                    msg_name: ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: iovec.as_mut_ptr(),
                    msg_iovlen: iovec.len() as IovLen,
                    msg_control: cmsg_buffer as *mut c_void,
                    msg_controllen: cmsg_space as MsgControlLen,
                    msg_flags: 0,
                };

                let result = sendmsg(sender_fd, &msghdr, 0);
                libc::free(cmsg_buffer as *mut c_void);
                result
            };

            if result > 0 {
                Ok(())
            } else {
                Err(UnixError::last())
            }
        };

        fn send_followup_fragment(sender_fd: c_int, data_buffer: &[u8]) -> Result<(),UnixError> {
            let result = unsafe {
                libc::send(sender_fd,
                           data_buffer.as_ptr() as *const c_void,
                           data_buffer.len(),
                           0)
            };

            if result > 0 {
                Ok(())
            } else {
                Err(UnixError::last())
            }
        }

        let mut sendbuf_size = *SYSTEM_SENDBUF_SIZE;

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
                // Make certain we end up with less than what we tried before...
                if !(*sendbuf_size < sent_size) {
                    *sendbuf_size = sent_size / 2;
                }
                Ok(())
            } else {
                Err(())
            }
        }

        // If the message is small enough, try sending it in a single fragment.
        if data.len() <= Self::get_max_fragment_size() {
            match send_first_fragment(self.fd.0, &fds[..], data, data.len()) {
                Ok(_) => return Ok(()),
                Err(error) => {
                    // ENOBUFS means the kernel failed to allocate a buffer large enough
                    // to actually transfer the message,
                    // although the message was small enough to fit the maximum send size --
                    // so we have to proceed with a fragmented send nevertheless,
                    // using a reduced send buffer size.
                    //
                    // Any other errors we might get here are non-recoverable.
                    if !(error.0 == libc::ENOBUFS
                         && downsize(&mut sendbuf_size, data.len()).is_ok()) {
                        return Err(error)
                    }
                },
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
        fds.push(dedicated_rx.fd.get());

        // Split up the packet into fragments.
        let mut byte_position = 0;
        while byte_position < data.len() {
            let end_byte_position;
            let result = if byte_position == 0 {
                // First fragment. No offset; but contains message header (total size).
                // The auxiliary data (FDs) is also sent along with this one.

                // This fragment always uses the full allowable buffer size.
                end_byte_position = Self::first_fragment_size(sendbuf_size);
                send_first_fragment(self.fd.0, &fds[..], &data[..end_byte_position], data.len())
            } else {
                // Followup fragment. No header; but offset by amount of data already sent.

                end_byte_position = cmp::min(byte_position + Self::fragment_size(sendbuf_size),
                                             data.len());
                send_followup_fragment(dedicated_tx.fd.0, &data[byte_position..end_byte_position])
            };

            if let Err(error) = result {
                if error.0 == libc::ENOBUFS
                   && downsize(&mut sendbuf_size, end_byte_position - byte_position).is_ok() {
                    // If the kernel failed to allocate a buffer large enough for the packet,
                    // retry with a smaller size (if possible).
                    continue
                } else {
                    return Err(error)
                }
            }

            byte_position = end_byte_position;
        }

        Ok(())
    }

    pub fn connect(name: String) -> Result<OsIpcSender,UnixError> {
        let name = CString::new(name).unwrap();
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, SOCK_SEQPACKET, 0);
            let (sockaddr, len) = new_sockaddr_un(name.as_ptr());
            if libc::connect(fd, &sockaddr as *const _ as *const sockaddr, len as socklen_t) < 0 {
                return Err(UnixError::last())
            }

            Ok(OsIpcSender::from_fd(fd))
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum OsIpcChannel {
    Sender(OsIpcSender),
    Receiver(OsIpcReceiver),
}

impl OsIpcChannel {
    fn fd(&self) -> c_int {
        match *self {
            OsIpcChannel::Sender(ref sender) => sender.fd.0,
            OsIpcChannel::Receiver(ref receiver) => receiver.fd.get(),
        }
    }
}

pub struct OsIpcReceiverSet {
    incrementor: RangeFrom<u64>,
    poll: Poll,
    pollfds: HashMap<Token, PollEntry, BuildHasherDefault<FnvHasher>>,
    events: Events
}

impl Drop for OsIpcReceiverSet {
    fn drop(&mut self) {
        for &PollEntry { id: _, fd } in self.pollfds.values() {
            let result = unsafe {
                libc::close(fd)
            };
            assert!(thread::panicking() || result == 0);
        }
    }
}

impl OsIpcReceiverSet {
    pub fn new() -> Result<OsIpcReceiverSet,UnixError> {
        let fnv = BuildHasherDefault::<FnvHasher>::default();
        Ok(OsIpcReceiverSet {
            incrementor: 0..,
            poll: try!(Poll::new()),
            pollfds: HashMap::with_hasher(fnv),
            events: Events::with_capacity(10)
        })
    }

    pub fn add(&mut self, receiver: OsIpcReceiver) -> Result<u64,UnixError> {
        let last_index = self.incrementor.next().unwrap();
        let fd = receiver.consume_fd();
        let io = EventedFd(&fd);
        let fd_token = Token(fd as usize);
        let poll_entry = PollEntry {
            id: last_index,
            fd: fd
        };
        try!(self.poll.register(&io,
                                fd_token,
                                Ready::readable(),
                                PollOpt::level()));
        self.pollfds.insert(fd_token, poll_entry);
        Ok(last_index)
    }

    pub fn select(&mut self) -> Result<Vec<OsIpcSelectionResult>,UnixError> {
        let mut selection_results = Vec::new();
        let mut num_events = 0;
        while num_events == 0 {
            match self.poll.poll(&mut self.events, None) {
                Ok(sz) => {
                    num_events = sz;
                },
                Err(ref e) => {
                    if e.kind() != ErrorKind::Interrupted {
                        return Err(UnixError::last());
                    }
                }
            }
        }

        for evt in self.events.iter() {
            let evt_token = evt.token();
            match (evt.readiness().is_readable(), self.pollfds.get(&evt_token)) {
                (true, Some(&poll_entry)) => {
                    match recv(poll_entry.fd, BlockingMode::Blocking) {
                        Ok((data, channels, shared_memory_regions)) => {
                            selection_results.push(OsIpcSelectionResult::DataReceived(
                                    poll_entry.id,
                                    data,
                                    channels,
                                    shared_memory_regions));
                        }
                        Err(err) if err.channel_is_closed() => {
                            self.pollfds.remove(&evt_token).unwrap();
                            self.poll.deregister(&EventedFd(&poll_entry.fd)).unwrap();
                            unsafe {
                                libc::close(poll_entry.fd);
                            }
                            selection_results.push(OsIpcSelectionResult::ChannelClosed(poll_entry.id))
                        }
                        Err(err) => return Err(err),
                    }
                },
                (true, None) => {
                    panic!("Readable event for unknown token: {:?}, readiness: {:?}",
                           evt_token, evt.readiness());
                },
                (false, _) => {
                    panic!("Received an event that was not readable for token: {:?}", evt_token)
                }
            }
        }

        Ok(selection_results)
    }
}

pub enum OsIpcSelectionResult {
    DataReceived(u64, Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),
    ChannelClosed(u64),
}

impl OsIpcSelectionResult {
    pub fn unwrap(self) -> (u64, Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>) {
        match self {
            OsIpcSelectionResult::DataReceived(id, data, channels, shared_memory_regions) => {
                (id, data, channels, shared_memory_regions)
            }
            OsIpcSelectionResult::ChannelClosed(id) => {
                panic!("OsIpcSelectionResult::unwrap(): receiver ID {} was closed!", id)
            }
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct OsOpaqueIpcChannel {
    fd: c_int,
}

impl Drop for OsOpaqueIpcChannel {
    fn drop(&mut self) {
        // Make sure we don't leak!
        //
        // The `OsOpaqueIpcChannel` objects should always be used,
        // i.e. converted with `to_sender()` or `to_receiver()` --
        // so the value should already be unset before the object gets dropped.
        debug_assert!(self.fd == -1);
    }
}

impl OsOpaqueIpcChannel {
    fn from_fd(fd: c_int) -> OsOpaqueIpcChannel {
        OsOpaqueIpcChannel {
            fd: fd,
        }
    }

    pub fn to_sender(&mut self) -> OsIpcSender {
        OsIpcSender::from_fd(mem::replace(&mut self.fd, -1))
    }

    pub fn to_receiver(&mut self) -> OsIpcReceiver {
        OsIpcReceiver::from_fd(mem::replace(&mut self.fd, -1))
    }
}

pub struct OsIpcOneShotServer {
    fd: c_int,
}

impl Drop for OsIpcOneShotServer {
    fn drop(&mut self) {
        unsafe {
            let result = libc::close(self.fd);
            assert!(thread::panicking() || result == 0);
        }
    }
}

impl OsIpcOneShotServer {
    pub fn new() -> Result<(OsIpcOneShotServer, String),UnixError> {
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, SOCK_SEQPACKET, 0);
            let mut path: Vec<u8>;
            loop {
                let path_string = CString::new(&b"/tmp/rust-ipc-socket.XXXXXX"[..]).unwrap();
                path = path_string.as_bytes_with_nul().iter().cloned().collect();
                if *mkstemp(path.as_mut_ptr() as *mut c_char) == 0 {
                    return Err(UnixError::last())
                }

                let (sockaddr, len) = new_sockaddr_un(path.as_ptr() as *const c_char);
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

            Ok((OsIpcOneShotServer {
                fd: fd,
            }, String::from_utf8(CStr::from_ptr(path.as_ptr() as
                                                *const c_char).to_bytes().to_owned()).unwrap()))
        }
    }

    pub fn accept(self) -> Result<(OsIpcReceiver,
                                   Vec<u8>,
                                   Vec<OsOpaqueIpcChannel>,
                                   Vec<OsIpcSharedMemory>),UnixError> {
        unsafe {
            let sockaddr: *mut sockaddr = ptr::null_mut();
            let sockaddr_len: *mut socklen_t = ptr::null_mut();
            let client_fd = libc::accept(self.fd, sockaddr, sockaddr_len);
            if client_fd < 0 {
                return Err(UnixError::last())
            }
            try!(make_socket_lingering(client_fd));

            let receiver = OsIpcReceiver::from_fd(client_fd);
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
                   &linger as *const _ as *const c_void,
                   mem::size_of::<linger>() as socklen_t)
    };
    if err < 0 {
        return Err(UnixError::last())
    }
    Ok(())
}

struct BackingStore {
    fd: c_int
}

impl BackingStore {
    pub fn new(length: usize) -> BackingStore {
        let count = SHM_COUNT.fetch_add(1, Ordering::Relaxed);
        let timestamp = UNIX_EPOCH.elapsed().unwrap();
        let name = CString::new(format!("/ipc-channel-shared-memory.{}.{}.{}.{}",
                                        count, *PID,
                                        timestamp.as_secs(),
                                        timestamp.subsec_nanos())).unwrap();
        let fd = create_shmem(name, length);
        Self::from_fd(fd)
    }

    pub fn from_fd(fd: c_int) -> BackingStore {
        BackingStore {
            fd: fd,
        }
    }

    pub fn fd(&self) -> c_int {
        self.fd
    }

    pub unsafe fn map_file(&self, length: Option<size_t>) -> (*mut u8, size_t) {
        let length = length.unwrap_or_else(|| {
            let mut st = mem::uninitialized();
            assert!(libc::fstat(self.fd, &mut st) == 0);
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
                                 self.fd,
                                 0);
        assert!(address != ptr::null_mut());
        assert!(address != MAP_FAILED);
        (address as *mut u8, length)
    }
}

impl Drop for BackingStore {
    fn drop(&mut self) {
        unsafe {
            let result = libc::close(self.fd);
            assert!(thread::panicking() || result == 0);
        }
    }
}

pub struct OsIpcSharedMemory {
    ptr: *mut u8,
    length: usize,
    store: BackingStore
}

unsafe impl Send for OsIpcSharedMemory {}
unsafe impl Sync for OsIpcSharedMemory {}

impl Drop for OsIpcSharedMemory {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                let result = libc::munmap(self.ptr as *mut c_void, self.length);
                assert!(thread::panicking() || result == 0);
            }
        }
    }
}

impl Clone for OsIpcSharedMemory {
    fn clone(&self) -> OsIpcSharedMemory {
        unsafe {
            let store = BackingStore::from_fd(libc::dup(self.store.fd()));
            let (address, _) = store.map_file(Some(self.length));
            OsIpcSharedMemory::from_raw_parts(address, self.length, store)
        }
    }
}

impl PartialEq for OsIpcSharedMemory {
    fn eq(&self, other: &OsIpcSharedMemory) -> bool {
        **self == **other
    }
}

impl Debug for OsIpcSharedMemory {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), fmt::Error> {
        (**self).fmt(formatter)
    }
}

impl Deref for OsIpcSharedMemory {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self.ptr, self.length)
        }
    }
}

impl OsIpcSharedMemory {
    unsafe fn from_raw_parts(ptr: *mut u8, length: usize,
                             store: BackingStore) -> OsIpcSharedMemory {
        OsIpcSharedMemory {
            ptr: ptr,
            length: length,
            store: store,
        }
    }

    unsafe fn from_fd(fd: c_int) -> OsIpcSharedMemory {
        let store = BackingStore::from_fd(fd);
        let (ptr, length) = store.map_file(None);
        OsIpcSharedMemory::from_raw_parts(ptr, length, store)
    }

    pub fn from_byte(byte: u8, length: usize) -> OsIpcSharedMemory {
        unsafe {
            let store = BackingStore::new(length);
            let (address, _) = store.map_file(Some(length));
            for element in slice::from_raw_parts_mut(address, length) {
                *element = byte;
            }
            OsIpcSharedMemory::from_raw_parts(address, length, store)
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> OsIpcSharedMemory {
        unsafe {
            let store = BackingStore::new(bytes.len());
            let (address, _) = store.map_file(Some(bytes.len()));
            ptr::copy_nonoverlapping(bytes.as_ptr(), address, bytes.len());
            OsIpcSharedMemory::from_raw_parts(address, bytes.len(), store)
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

impl From<UnixError> for bincode::Error {
    fn from(unix_error: UnixError) -> Self {
        Error::from(unix_error).into()
    }
}

impl From<UnixError> for Error {
    fn from(unix_error: UnixError) -> Error {
        Error::from_raw_os_error(unix_error.0)
    }
}

impl From<Error> for UnixError {
    fn from(e: Error) -> UnixError {
        UnixError(e.raw_os_error().unwrap())
    }
}

#[derive(Copy, Clone)]
enum BlockingMode {
    Blocking,
    Nonblocking,
}

fn recv(fd: c_int, blocking_mode: BlockingMode)
        -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),UnixError> {

    let (mut channels, mut shared_memory_regions) = (Vec::new(), Vec::new());

    // First fragments begins with a header recording the total data length.
    //
    // We use this to determine whether we already got the entire message,
    // or need to receive additional fragments -- and if so, how much.
    let mut total_size = 0usize;
    let mut main_data_buffer;
    unsafe {
        // Allocate a buffer without initialising the memory.
        main_data_buffer = Vec::with_capacity(OsIpcSender::get_max_fragment_size());
        main_data_buffer.set_len(OsIpcSender::get_max_fragment_size());

        let mut iovec = [
            iovec {
                iov_base: &mut total_size as *mut _ as *mut c_void,
                iov_len: mem::size_of_val(&total_size),
            },
            iovec {
                iov_base: main_data_buffer.as_mut_ptr() as *mut c_void,
                iov_len: main_data_buffer.len(),
            },
        ];
        let mut cmsg = UnixCmsg::new(&mut iovec);

        let bytes_read = try!(cmsg.recv(fd, blocking_mode));
        main_data_buffer.set_len(bytes_read - mem::size_of_val(&total_size));

        let cmsg_fds = CMSG_DATA(cmsg.cmsg_buffer) as *const c_int;
        let cmsg_length = cmsg.msghdr.msg_controllen;
        let channel_length = if cmsg_length == 0 {
            0
        } else {
            (cmsg.cmsg_len() - CMSG_ALIGN(mem::size_of::<cmsghdr>())) / mem::size_of::<c_int>()
        };
        for index in 0..channel_length {
            let fd = *cmsg_fds.offset(index as isize);
            if is_socket(fd) {
                channels.push(OsOpaqueIpcChannel::from_fd(fd));
                continue
            }
            shared_memory_regions.push(OsIpcSharedMemory::from_fd(fd));
        }
    }

    if total_size == main_data_buffer.len() {
        // Fast path: no fragments.
        return Ok((main_data_buffer, channels, shared_memory_regions))
    }

    // Reassemble fragments.
    //
    // The initial fragment carries the receive end of a dedicated channel
    // through which all the remaining fragments will be coming in.
    let dedicated_rx = channels.pop().unwrap().to_receiver();

    // Extend the buffer to hold the entire message, without initialising the memory.
    let len = main_data_buffer.len();
    main_data_buffer.reserve_exact(total_size - len);

    // Receive followup fragments directly into the main buffer.
    while main_data_buffer.len() < total_size {
        let write_pos = main_data_buffer.len();
        let end_pos = cmp::min(write_pos + OsIpcSender::fragment_size(*SYSTEM_SENDBUF_SIZE),
                               total_size);
        let result = unsafe {
            assert!(end_pos <= main_data_buffer.capacity());
            main_data_buffer.set_len(end_pos);

            // Integer underflow could make the following code unsound...
            assert!(end_pos >= write_pos);

            // Note: we always use blocking mode for followup fragments,
            // to make sure that once we start receiving a multi-fragment message,
            // we don't abort in the middle of it...
            let result = libc::recv(dedicated_rx.fd.get(),
                                    main_data_buffer[write_pos..].as_mut_ptr() as *mut c_void,
                                    end_pos - write_pos,
                                    0);
            main_data_buffer.set_len(write_pos + cmp::max(result, 0) as usize);
            result
        };

        if result == 0 {
            return Err(UnixError(libc::ECONNRESET))
        } else if result < 0 {
            return Err(UnixError::last())
        };
    }

    Ok((main_data_buffer, channels, shared_memory_regions))
}

#[cfg(not(all(target_os="linux", feature="memfd")))]
fn create_shmem(name: CString, length: usize) -> c_int {
    unsafe {
        // NB: the FreeBSD man page for shm_unlink states that it requires
        // write permissions, but testing shows that read-write is required.
        let fd = libc::shm_open(name.as_ptr(),
                                libc::O_CREAT | libc::O_RDWR | libc::O_EXCL,
                                0o600);
        assert!(fd >= 0);
        assert!(libc::shm_unlink(name.as_ptr()) == 0);
        assert!(libc::ftruncate(fd, length as off_t) == 0);
        fd
    }
}

#[cfg(all(feature="memfd", target_os="linux"))]
fn create_shmem(name: CString, length: usize) -> c_int {
    unsafe {
        let fd = memfd_create(name.as_ptr(), 0);
        assert!(fd >= 0);
        assert!(libc::ftruncate(fd, length as off_t) == 0);
        fd
    }
}

struct UnixCmsg {
    cmsg_buffer: *mut cmsghdr,
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
    unsafe fn new(iovec: &mut [iovec]) -> UnixCmsg {
        let cmsg_length = CMSG_SPACE(MAX_FDS_IN_CMSG as usize * mem::size_of::<c_int>());
        let cmsg_buffer = libc::malloc(cmsg_length) as *mut cmsghdr;
        UnixCmsg {
            cmsg_buffer: cmsg_buffer,
            msghdr: msghdr {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: iovec.as_mut_ptr(),
                msg_iovlen: iovec.len() as IovLen,
                msg_control: cmsg_buffer as *mut c_void,
                msg_controllen: cmsg_length as MsgControlLen,
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
        (*(self.msghdr.msg_control as *const cmsghdr)).cmsg_len as size_t
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

#[cfg(all(feature="memfd", target_os="linux"))]
unsafe fn memfd_create(name: *const c_char, flags: usize) -> c_int {
    syscall!(MEMFD_CREATE, name, flags) as c_int
}

#[allow(non_snake_case)]
fn CMSG_LEN(length: size_t) -> size_t {
    CMSG_ALIGN(mem::size_of::<cmsghdr>()) + length
}

#[allow(non_snake_case)]
unsafe fn CMSG_DATA(cmsg: *mut cmsghdr) -> *mut c_void {
    (cmsg as *mut libc::c_uchar).offset(CMSG_ALIGN(
            mem::size_of::<cmsghdr>()) as isize) as *mut c_void
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
    fn mkstemp(template: *mut c_char) -> *mut c_char;
}

#[repr(C)]
struct cmsghdr {
    cmsg_len: MsgControlLen,
    cmsg_level: c_int,
    cmsg_type: c_int,
}

#[repr(C)]
struct linger {
    l_onoff: c_int,
    l_linger: c_int,
}

