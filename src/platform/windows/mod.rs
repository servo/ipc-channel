// Copyright 2016 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use serde;
use bincode;
use kernel32;
use libc::intptr_t;
use std::cell::{Cell, RefCell};
use std::cmp::PartialEq;
use std::default::Default;
use std::env;
use std::ffi::CString;
use std::io::{Error, ErrorKind};
use std::marker::{Send, Sync, PhantomData};
use std::mem;
use std::ops::{Deref, DerefMut};
use std::ptr;
use std::slice;
use uuid::Uuid;
use winapi::{HANDLE, INVALID_HANDLE_VALUE, LPVOID};
use winapi;
use super::incrementor::Incrementor;

lazy_static! {
    static ref CURRENT_PROCESS_ID: winapi::ULONG = unsafe { kernel32::GetCurrentProcessId() };
    static ref CURRENT_PROCESS_HANDLE: intptr_t = unsafe { kernel32::GetCurrentProcess() as intptr_t };

    static ref DEBUG_TRACE_ENABLED: bool = { env::var_os("IPC_CHANNEL_WIN_DEBUG_TRACE").is_some() };
}

/// Debug macro to better track what's going on in case of errors.
macro_rules! win32_trace {
    ($($rest:tt)*) => {
        if cfg!(feature = "win32-trace") {
            if *DEBUG_TRACE_ENABLED { println!($($rest)*); }
        }
    }
}

/// When we create the pipe, how big of a write buffer do we specify?
///
/// This is reserved in the nonpaged pool.  The fragment size is the
/// max we can write to the pipe without fragmentation, and the
/// buffer size is what we tell the pipe it is, so we have room
/// for out of band data etc.
const MAX_FRAGMENT_SIZE: usize = 64 * 1024;

/// Size of the pipe's write buffer, with excess room for the header.
const PIPE_BUFFER_SIZE: usize = MAX_FRAGMENT_SIZE + 4 * 1024;

#[allow(non_snake_case)]
fn GetLastError() -> u32 {
    unsafe {
        kernel32::GetLastError()
    }
}

pub fn channel() -> Result<(OsIpcSender, OsIpcReceiver),WinError> {
    let pipe_id = make_pipe_id();
    let pipe_name = make_pipe_name(&pipe_id);

    let receiver = try!(OsIpcReceiver::new_named(&pipe_name));
    let sender = try!(OsIpcSender::connect_named(&pipe_name));

    Ok((sender, receiver))
}

/// Holds data len and out-of-band data len.
struct MessageHeader(u32, u32);

impl MessageHeader {
    fn size() -> usize {
        mem::size_of::<MessageHeader>()
    }

    fn total_message_bytes_needed(&self) -> usize {
        MessageHeader::size() + self.0 as usize + self.1 as usize
    }
}

struct Message<'data> {
    data_len: usize,
    oob_len: usize,
    bytes: &'data [u8],
}

impl<'data> Message<'data> {
    fn from_bytes(bytes: &'data [u8]) -> Option<Message> {
        if bytes.len() < MessageHeader::size() {
            return None;
        }

        unsafe {
            let ref header = *(bytes.as_ptr() as *const MessageHeader);
            if bytes.len() < header.total_message_bytes_needed() {
                return None;
            }

            Some(Message {
                data_len: header.0 as usize,
                oob_len: header.1 as usize,
                bytes: &bytes[0..header.total_message_bytes_needed()],
            })
        }
    }

    fn data(&self) -> &[u8] {
        &self.bytes[MessageHeader::size()..(MessageHeader::size() + self.data_len)]
    }

    fn oob_bytes(&self) -> &[u8] {
        &self.bytes[(MessageHeader::size() + self.data_len)..]
    }

    fn oob_data(&self) -> Option<OutOfBandMessage> {
        if self.oob_len > 0 {

            let oob = bincode::deserialize::<OutOfBandMessage>(self.oob_bytes())
                .expect("Failed to deserialize OOB data");
            if oob.target_process_id != *CURRENT_PROCESS_ID {
                panic!("Windows IPC channel received handles intended for pid {}, but this is pid {}. \
                       This likely happened because a receiver was transferred while it had outstanding data \
                       that contained a channel or shared memory in its pipe. \
                       This isn't supported in the Windows implementation.",
                       oob.target_process_id, *CURRENT_PROCESS_ID);
            }
            Some(oob)
        } else {
            None
        }
    }

    fn size(&self) -> usize {
        MessageHeader::size() + self.data_len + self.oob_len
    }
}

/// If we have any channel handles or shmem segments, then we'll send an
/// OutOfBandMessage after the data message.
///
/// This includes the receiver's process ID, which the receiver checks to
/// make sure that the message was originally sent to it, and was not sitting
/// in another channel's buffer when that channel got transferred to another
/// process.  On Windows, we duplicate handles on the sender side to a specific
/// reciever.  If the wrong receiver gets it, those handles are not valid.
///
/// TODO(vlad): We could attempt to recover from the above situation by
/// duplicating from the intended target process to ourselves (the receiver).
/// That would only work if the intended process a) still exists; b) can be
/// opened by the receiver with handle dup privileges.  Another approach
/// could be to use a separate dedicated process intended purely for handle
/// passing, though that process would need to be global to any processes
/// amongst which you want to share channels or connect one-shot servers to.
/// There may be a system process that we could use for this purpose, but
/// I haven't found one -- and in the system process case, we'd need to ensure
/// that we don't leak the handles (e.g. dup a handle to the system process,
/// and then everything dies -- we don't want those resources to be leaked).
#[derive(Debug)]
struct OutOfBandMessage {
    target_process_id: u32,
    channel_handles: Vec<intptr_t>,
    shmem_handles: Vec<(intptr_t, u64)>, // handle and size
    big_data_receiver_handle: Option<(intptr_t, u64)>, // handle and size
}

impl OutOfBandMessage {
    fn new(target_id: u32) -> OutOfBandMessage {
        OutOfBandMessage {
            target_process_id: target_id,
            channel_handles: vec![],
            shmem_handles: vec![],
            big_data_receiver_handle: None,
        }
    }

    fn needs_to_be_sent(&self) -> bool {
        !self.channel_handles.is_empty() ||
        !self.shmem_handles.is_empty() ||
        self.big_data_receiver_handle.is_some()
    }
}

impl serde::Serialize for OutOfBandMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer
    {
        ((self.target_process_id,
          &self.channel_handles,
          &self.shmem_handles,
          &self.big_data_receiver_handle)).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for OutOfBandMessage {
    fn deserialize<D>(deserializer: D) -> Result<OutOfBandMessage, D::Error>
        where D: serde::Deserializer<'de>
    {
        let (target_process_id, channel_handles, shmem_handles, big_data_receiver_handle) =
            try!(serde::Deserialize::deserialize(deserializer));
        Ok(OutOfBandMessage {
            target_process_id: target_process_id,
            channel_handles: channel_handles,
            shmem_handles: shmem_handles,
            big_data_receiver_handle: big_data_receiver_handle
        })
    }
}

fn make_pipe_id() -> Uuid {
    Uuid::new_v4()
}

fn make_pipe_name(pipe_id: &Uuid) -> CString {
    CString::new(format!("\\\\.\\pipe\\rust-ipc-{}", pipe_id.to_string())).unwrap()
}

/// Duplicate a given handle from this process to the target one, passing the
/// given flags to DuplicateHandle.
///
/// Unlike win32 DuplicateHandle, this will preserve INVALID_HANDLE_VALUE (which is
/// also the pseudohandle for the current process).
unsafe fn dup_handle_to_process_with_flags(handle: HANDLE, other_process: HANDLE, flags: winapi::DWORD)
                                    -> Result<HANDLE,WinError>
{
    if handle == INVALID_HANDLE_VALUE {
        return Ok(INVALID_HANDLE_VALUE);
    }

    let mut new_handle: HANDLE = INVALID_HANDLE_VALUE;
    let ok = kernel32::DuplicateHandle(*CURRENT_PROCESS_HANDLE as HANDLE, handle,
                                       other_process, &mut new_handle,
                                       0, winapi::FALSE, flags);
    if ok == winapi::FALSE {
        Err(WinError::last("DuplicateHandle"))
    } else {
        Ok(new_handle)
    }
}

/// Duplicate a handle in the current process.
fn dup_handle(handle: &WinHandle) -> Result<WinHandle,WinError> {
    dup_handle_to_process(handle, &WinHandle::new(*CURRENT_PROCESS_HANDLE as HANDLE))
}

/// Duplicate a handle to the target process.
fn dup_handle_to_process(handle: &WinHandle, other_process: &WinHandle) -> Result<WinHandle,WinError> {
    unsafe {
        let h = try!(dup_handle_to_process_with_flags(
            **handle, **other_process, winapi::DUPLICATE_SAME_ACCESS));
        Ok(WinHandle::new(h))
    }
}

/// Duplicate a handle to the target process, closing the source handle.
fn move_handle_to_process(handle: &mut WinHandle, other_process: &WinHandle) -> Result<WinHandle,WinError> {
    unsafe {
        let h = try!(dup_handle_to_process_with_flags(
            handle.take(), **other_process,
            winapi::DUPLICATE_CLOSE_SOURCE | winapi::DUPLICATE_SAME_ACCESS));
        Ok(WinHandle::new(h))
    }
}

#[derive(Debug)]
struct WinHandle {
    h: HANDLE
}

unsafe impl Send for WinHandle { }
unsafe impl Sync for WinHandle { }

impl Drop for WinHandle {
    fn drop(&mut self) {
        unsafe {
            kernel32::CloseHandle(self.h);
        }
    }
}

impl Default for WinHandle {
    fn default() -> WinHandle {
        WinHandle { h: INVALID_HANDLE_VALUE }
    }
}

impl Deref for WinHandle {
    type Target = HANDLE;

    #[inline]
    fn deref(&self) -> &HANDLE {
        &self.h
    }
}

impl PartialEq for WinHandle {
    fn eq(&self, other: &WinHandle) -> bool {
        // FIXME This does not actually implement the desired behaviour:
        // we want a way to compare the underlying objects the handles refer to,
        // rather than just comparing the handles.
        //
        // On Windows 10, we could use:
        // ```
        // unsafe { kernel32::CompareObjectHandles(self.h, other.h) == winapi::TRUE }
        // ```
        //
        // This API call however is not available on older versions.
        self.h == other.h
    }
}

impl WinHandle {
    fn new(h: HANDLE) -> WinHandle {
        WinHandle { h: h }
    }

    fn invalid() -> WinHandle {
        WinHandle { h: INVALID_HANDLE_VALUE }
    }

    fn is_valid(&self) -> bool {
        self.h != INVALID_HANDLE_VALUE
    }

    fn take(&mut self) -> HANDLE {
        mem::replace(&mut self.h, INVALID_HANDLE_VALUE)
    }
}

/// Main object keeping track of a receive handle and its associated state.
///
/// Implements blocking/nonblocking reads of messages from the handle.
#[derive(Debug)]
struct MessageReader {
    /// The pipe read handle.
    handle: WinHandle,

    /// The OVERLAPPED struct for async IO on this receiver.
    ///
    /// We'll only ever have one in flight.
    ///
    /// This must be on the heap, so its memory location --
    /// which is registered in the kernel during an async read --
    /// remains stable even when the enclosing structure is passed around.
    ov: Box<winapi::OVERLAPPED>,

    /// A read buffer for any pending reads.
    read_buf: Vec<u8>,

    /// Whether we have already issued an async read.
    read_in_progress: bool,

    /// Whether we received a BROKEN_PIPE or other error
    /// indicating that the remote end has closed the pipe.
    closed: bool,

    /// ID identifying this reader within a receiver set.
    ///
    /// `None` if the `MessageReader` is not part of any set.
    set_id: Option<u64>,
}

impl MessageReader {
    fn new(handle: WinHandle) -> MessageReader {
        MessageReader {
            handle: handle,
            ov: Box::new(unsafe { mem::zeroed::<winapi::OVERLAPPED>() }),
            read_buf: Vec::new(),
            read_in_progress: false,
            closed: false,
            set_id: None,
        }
    }

    fn cancel_io(&mut self) {
        unsafe {
            if self.read_in_progress {
                kernel32::CancelIoEx(*self.handle, self.ov.deref_mut());
                self.read_in_progress = false;
            }
        }
    }

    /// Kick off an asynchronous read.
    fn start_read(&mut self) -> Result<(),WinError> {
        if self.read_in_progress || self.closed {
            return Ok(());
        }

        win32_trace!("[$ {:?}] start_read", self.handle);

        if self.read_buf.len() == self.read_buf.capacity() {
            self.read_buf.reserve(PIPE_BUFFER_SIZE);
        }

        unsafe {
            // Temporarily extend the vector to span its entire capacity,
            // so we can safely sub-slice it for the actual read.
            let buf_len = self.read_buf.len();
            let buf_cap = self.read_buf.capacity();
            self.read_buf.set_len(buf_cap);

            // issue the read to the buffer, at the current length offset
            *self.ov.deref_mut() = mem::zeroed();
            let mut bytes_read: u32 = 0;
            let ok = {
                let remaining_buf = &mut self.read_buf[buf_len..];
                kernel32::ReadFile(*self.handle,
                                   remaining_buf.as_mut_ptr() as LPVOID,
                                   remaining_buf.len() as u32,
                                   &mut bytes_read,
                                   self.ov.deref_mut())
            };

            // Reset the vector to only expose the already filled part.
            //
            // This means that the async read
            // will actually fill memory beyond the exposed part of the vector.
            // While this use of a vector is officially sanctioned for such cases,
            // it still feel rather icky to me...
            //
            // On the other hand, this way we make sure
            // the buffer never appears to have more valid data
            // than what is actually present,
            // which could pose a potential danger in its own right.
            // Also, it avoids the need to keep a separate state variable --
            // which would bear some risk of getting out of sync.
            self.read_buf.set_len(buf_len);

            // ReadFile can return TRUE; if it does, an IO completion
            // packet is still posted to any port, and the OVERLAPPED
            // structure has the IO operation flagged as complete.
            //
            // Normally, for an async operation, a call like
            // `ReadFile` would return `FALSE`, and the error code
            // would be `ERROR_IO_PENDING`.  But in some situations,
            // `ReadFile` can complete synchronously (returns `TRUE`).
            // Even if it does, a notification that the IO completed
            // is still sent to the IO completion port that this
            // handle is part of, meaning that we don't have to do any
            // special handling for sync-completed operations.
            if ok == winapi::FALSE {
                let err = GetLastError();
                if err == winapi::ERROR_BROKEN_PIPE {
                    win32_trace!("[$ {:?}] BROKEN_PIPE straight from ReadFile", self.handle);
                    self.closed = true;
                    return Ok(());
                }

                if err == winapi::ERROR_IO_PENDING {
                    self.read_in_progress = true;
                    return Ok(());
                }

                Err(WinError::from_system(err, "ReadFile"))
            } else {
                self.read_in_progress = true;
                Ok(())
            }
        }
    }

    /// Called when we receive an IO Completion Packet for this handle.
    ///
    /// Unsafe, since calling this with an invalid object or at the wrong time
    /// could result in uninitialized data being passed off as valid.
    /// While this may seem less critical than other memory errors,
    /// it can also break type safety.
    unsafe fn notify_completion(&mut self, err: u32) -> Result<(),WinError> {
        win32_trace!("[$ {:?}] notify_completion", self.handle);

        // mark a read as no longer in progress even before we check errors
        self.read_in_progress = false;

        if err == winapi::ERROR_BROKEN_PIPE {
            assert!(!self.closed, "we shouldn't get an async BROKEN_PIPE after we already got one");
            self.closed = true;
            return Ok(());
        }

        let nbytes = self.ov.InternalHigh as u32;
        let offset = self.ov.Offset;

        assert!(offset == 0);

        // if the remote end closed...
        if err != winapi::ERROR_SUCCESS {
            // This should never happen
            panic!("[$ {:?}] *** notify_completion: unhandled error reported! {}", self.handle, err);
        }

        let new_size = self.read_buf.len() + nbytes as usize;
        win32_trace!("nbytes: {}, offset {}, buf len {}->{}, capacity {}",
            nbytes, offset, self.read_buf.len(), new_size, self.read_buf.capacity());
        assert!(new_size <= self.read_buf.capacity());
        self.read_buf.set_len(new_size);

        Ok(())
    }

    // This is split between get_message and get_message_inner, so that
    // this function can handle removing bytes from the buffer, since
    // get_message_inner borrows the buffer.
    fn get_message(&mut self) -> Result<Option<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>)>,
                                        WinError> {
        let drain_bytes;
        let result;
        if let Some(message) = Message::from_bytes(&self.read_buf) {
            let mut channels: Vec<OsOpaqueIpcChannel> = vec![];
            let mut shmems: Vec<OsIpcSharedMemory> = vec![];
            let mut big_data = None;

            if let Some(oob) = message.oob_data() {
                win32_trace!("[$ {:?}] msg with total {} bytes, {} channels, {} shmems, big data handle {:?}",
                     self.handle, message.data_len, oob.channel_handles.len(), oob.shmem_handles.len(),
                     oob.big_data_receiver_handle);

                unsafe {
                    for handle in oob.channel_handles.iter() {
                        channels.push(OsOpaqueIpcChannel::new(*handle as HANDLE));
                    }

                    for sh in oob.shmem_handles.iter() {
                        shmems.push(OsIpcSharedMemory::from_handle(sh.0 as HANDLE, sh.1 as usize).unwrap());
                    }

                    if oob.big_data_receiver_handle.is_some() {
                        let (handle, big_data_size) = oob.big_data_receiver_handle.unwrap();
                        let receiver = OsIpcReceiver::from_handle(handle as HANDLE);
                        big_data = Some(try!(receiver.recv_raw(big_data_size as usize)));
                    }
                }
            }

            let buf_data = big_data.unwrap_or_else(|| message.data().to_vec());

            win32_trace!("[$ {:?}] get_message success -> {} bytes, {} channels, {} shmems",
                self.handle, buf_data.len(), channels.len(), shmems.len());
            drain_bytes = Some(message.size());
            result = Some((buf_data, channels, shmems));
        } else {
            drain_bytes = None;
            result = None;
        }

        if let Some(size) = drain_bytes {
            // If the only valid bytes in the buffer are what we just
            // consumed, then just set the vector's length to 0.  This
            // avoids reallocations as in the drain() case, and is
            // a significant speedup.
            if self.read_buf.len() == size {
                self.read_buf.clear();
            } else {
                self.read_buf.drain(0..size);
            }
        }

        Ok(result)
    }

    fn add_to_iocp(&mut self, iocp: HANDLE, set_id: u64) -> Result<(),WinError> {
        unsafe {
            assert!(self.set_id.is_none());

            let ret = kernel32::CreateIoCompletionPort(*self.handle,
                                                       iocp,
                                                       *self.handle as winapi::ULONG_PTR,
                                                       0);
            if ret.is_null() {
                return Err(WinError::last("CreateIoCompletionPort"));
            }

            self.set_id = Some(set_id);

            // Make sure that the reader has a read in flight,
            // otherwise a later select() will hang.
            try!(self.start_read());

            Ok(())
        }
    }

    /// Specialized read for out-of-band data ports.
    ///
    /// Here the buffer size is known in advance,
    /// and the transfer doesn't have our typical message framing.
    ///
    /// It's only valid to call this as the one and only call after creating a MessageReader.
    fn read_raw_sized(&mut self, size: usize) -> Result<Vec<u8>,WinError> {
        assert!(self.read_buf.len() == 0);

        // We use with_capacity() to allocate an uninitialized buffer,
        // since we're going to read into it and don't need to
        // zero it.
        let mut buf = Vec::with_capacity(size);
        while buf.len() < size {
            // Because our handle is asynchronous, we have to do a two-part read --
            // first issue the operation, then wait for its completion.
            unsafe {
                let ov = self.ov.deref_mut();
                *ov = mem::zeroed();

                // Temporarily extend the vector to span its entire capacity,
                // so we can safely sub-slice it for the actual read.
                let buf_len = buf.len();
                let buf_cap = buf.capacity();
                buf.set_len(buf_cap);

                let mut bytes_read: u32 = 0;
                let ok = {
                    let remaining_buf = &mut buf[buf_len..];
                    kernel32::ReadFile(*self.handle,
                                       remaining_buf.as_mut_ptr() as LPVOID,
                                       remaining_buf.len() as u32,
                                       &mut bytes_read,
                                       ov)
                };

                // Restore the original size before error handling,
                // so we never leave the function with the buffer exposing uninitialized data.
                buf.set_len(buf_len);

                if ok == winapi::FALSE && GetLastError() != winapi::ERROR_IO_PENDING {
                    return Err(WinError::last("ReadFile"));
                }

                if ov.Internal as i32 == winapi::STATUS_PENDING {
                    let ok = kernel32::GetOverlappedResult(*self.handle, ov, &mut bytes_read, winapi::TRUE);
                    if ok == winapi::FALSE {
                        return Err(WinError::last("GetOverlappedResult"));
                    }
                } else {
                    bytes_read = ov.InternalHigh as u32;
                }

                let new_len = buf_len + bytes_read as usize;
                buf.set_len(new_len);
            }
        }

        Ok(buf)
    }
}

#[derive(Debug)]
pub struct OsIpcReceiver {
    /// The receive handle and its associated state.
    ///
    /// We can't just deal with raw handles like in the other platform back-ends,
    /// since this implementation -- using plain pipes with no native packet handling --
    /// requires keeping track of various bits of receiver state,
    /// which must not be separated from the handle itself.
    reader: RefCell<MessageReader>,
}

unsafe impl Send for OsIpcReceiver { }

impl PartialEq for OsIpcReceiver {
    fn eq(&self, other: &OsIpcReceiver) -> bool {
        self.reader.borrow().handle == other.reader.borrow().handle
    }
}

impl OsIpcReceiver {
    unsafe fn from_handle(handle: HANDLE) -> OsIpcReceiver {
        OsIpcReceiver {
            reader: RefCell::new(MessageReader::new(WinHandle::new(handle))),
        }
    }

    fn new_named(pipe_name: &CString) -> Result<OsIpcReceiver,WinError> {
        unsafe {
            // create the pipe server
            let handle =
                kernel32::CreateNamedPipeA(pipe_name.as_ptr(),
                                           winapi::PIPE_ACCESS_INBOUND | winapi::FILE_FLAG_OVERLAPPED,
                                           winapi::PIPE_TYPE_BYTE | winapi::PIPE_READMODE_BYTE | winapi::PIPE_REJECT_REMOTE_CLIENTS,
                                           // 1 max instance of this pipe
                                           1,
                                           // out/in buffer sizes
                                           0, PIPE_BUFFER_SIZE as u32,
                                           0, // default timeout for WaitNamedPipe (0 == 50ms as default)
                                           ptr::null_mut());
            if handle == INVALID_HANDLE_VALUE {
                return Err(WinError::last("CreateNamedPipeA"));
            }

            Ok(OsIpcReceiver {
                reader: RefCell::new(MessageReader::new(WinHandle::new(handle))),
            })
        }
    }

    fn prepare_for_transfer(&self) -> Result<bool,WinError> {
        let mut reader = self.reader.borrow_mut();
        // cancel any outstanding IO request
        reader.cancel_io();
        // this is only okay if we have nothing in the read buf
        Ok(reader.read_buf.is_empty())
    }

    pub fn consume(&self) -> OsIpcReceiver {
        let mut handle = dup_handle(&self.reader.borrow().handle).unwrap();
        unsafe { OsIpcReceiver::from_handle(handle.take()) }
    }

    fn receive_message(&self, mut block: bool)
                       -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),WinError> {
        // This is only used for recv/try_recv.  When this is added to an IpcReceiverSet, then
        // the implementation in select() is used.  It does much the same thing, but across multiple
        // channels.

        // This function loops, because in the case of a blocking read, we may need to
        // read multiple sets of bytes from the pipe to receive a complete message.
        unsafe {
            let mut reader = self.reader.borrow_mut();
            assert!(reader.set_id.is_none(), "receive_message is only valid before this OsIpcReceiver was added to a Set");

            loop {
                // First, try to fetch a message, in case we have one pending
                // in the reader's receive buffer
                match try!(reader.get_message()) {
                    Some((data, channels, shmems)) =>
                        return Ok((data, channels, shmems)),
                    None =>
                        {},
                }

                // If the pipe was already closed, we're done -- we've
                // already drained all incoming bytes
                if reader.closed {
                    return Err(WinError::ChannelClosed);
                }

                // Then, issue a read if we don't have one already in flight.
                // We must not issue a read if we have complete unconsumed
                // messages, because getting a message modifies the read_buf.
                try!(reader.start_read());

                // If the last read flagged us closed we're done; we've already
                // drained all incoming bytes earlier in the loop.
                if reader.closed {
                    return Err(WinError::ChannelClosed);
                }

                // Then, get the overlapped result, blocking if we need to.
                let mut nbytes: u32 = 0;
                let mut err = winapi::ERROR_SUCCESS;
                let ok = kernel32::GetOverlappedResult(*reader.handle, reader.ov.deref_mut(), &mut nbytes,
                                                       if block { winapi::TRUE } else { winapi::FALSE });
                if ok == winapi::FALSE {
                    err = GetLastError();
                    if !block && err == winapi::ERROR_IO_INCOMPLETE {
                        // Nonblocking read, no message, read's in flight, we're
                        // done.  An error is expected in this case.
                        return Err(WinError::NoData);
                    }
                    // We pass err through to notify_completion so
                    // that it can handle other errors.
                }

                // Notify that the read completed, which will update the
                // read pointers
                try!(reader.notify_completion(err));

                // If we're not blocking, pretend that we are blocking, since we got part of
                // a message already.  Keep reading until we get a complete message.
                block = true;
            }
        }
    }

    pub fn recv(&self)
                -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),WinError> {
        win32_trace!("recv");
        self.receive_message(true)
    }

    pub fn try_recv(&self)
                    -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),WinError> {
        win32_trace!("try_recv");
        self.receive_message(false)
    }

    /// Do a pipe connect.
    ///
    /// Only used for one-shot servers.
    fn accept(&self) -> Result<(),WinError> {
        unsafe {
            let reader_borrow = self.reader.borrow();
            let handle = *reader_borrow.handle;
            let mut ov = Box::new(mem::zeroed::<winapi::OVERLAPPED>());
            let ok = kernel32::ConnectNamedPipe(handle, ov.deref_mut());

            // we should always get FALSE with async IO
            assert!(ok == winapi::FALSE);
            let err = GetLastError();

            match err {
                // did we successfully connect? (it's reported as an error [ok==false])
                winapi::ERROR_PIPE_CONNECTED => {
                    win32_trace!("[$ {:?}] accept (PIPE_CONNECTED)", handle);
                    Ok(())
                },

                // This is a weird one -- if we create a named pipe (like we do
                // in new(), the client connects, sends data, then drops its handle,
                // a Connect here will get ERROR_NO_DATA -- but there may be data in
                // the pipe that we'll be able to read.  So we need to go do some reads
                // like normal and wait until ReadFile gives us ERROR_NO_DATA.
                winapi::ERROR_NO_DATA => {
                    win32_trace!("[$ {:?}] accept (ERROR_NO_DATA)", handle);
                    Ok(())
                },

                // was it an actual error?
                err if err != winapi::ERROR_IO_PENDING => {
                    win32_trace!("[$ {:?}] accept error -> {}", handle, err);
                    Err(WinError::last("ConnectNamedPipe"))
                },

                // the connect is pending; wait for it to complete
                _ /* winapi::ERROR_IO_PENDING */ => {
                    let mut nbytes: u32 = 0;
                    let ok = kernel32::GetOverlappedResult(handle, ov.deref_mut(), &mut nbytes, winapi::TRUE);
                    if ok == winapi::FALSE {
                        return Err(WinError::last("GetOverlappedResult[ConnectNamedPipe]"));
                    }
                    Ok(())
                },
            }
        }
    }

    /// Does a single explicitly-sized recv from the handle,
    /// consuming the receiver in the process.
    ///
    /// This is used for receiving data from the out-of-band big data buffer.
    fn recv_raw(self, size: usize) -> Result<Vec<u8>, WinError> {
        self.reader.borrow_mut().read_raw_sized(size)
    }
}

#[derive(Debug, PartialEq)]
pub struct OsIpcSender {
    handle: WinHandle,
    // Make sure this is `!Sync`, to match `mpsc::Sender`; and to discourage sharing references.
    //
    // (Rather, senders should just be cloned, as they are shared internally anyway --
    // another layer of sharing only adds unnecessary overhead...)
    nosync_marker: PhantomData<Cell<()>>,
}

unsafe impl Send for OsIpcSender { }

impl Clone for OsIpcSender {
    fn clone(&self) -> OsIpcSender {
        unsafe {
            let mut handle = dup_handle(&self.handle).unwrap();
            OsIpcSender::from_handle(handle.take())
        }
    }
}

/// Atomic write to a handle.
///
/// Fails if the data can't be written in a single system call.
/// This is important, since otherwise concurrent sending
/// could result in parts of different messages getting intermixed,
/// and we would not be able to extract the individual messages.
fn write_msg(handle: HANDLE, bytes: &[u8]) -> Result<(),WinError> {
    if bytes.len() == 0 {
        return Ok(());
    }

    let mut size: u32 = 0;
    unsafe {
        if kernel32::WriteFile(handle,
                               bytes.as_ptr() as LPVOID,
                               bytes.len() as u32,
                               &mut size,
                               ptr::null_mut())
            == winapi::FALSE
        {
            return Err(WinError::last("WriteFile"));
        }
    }

    if size != bytes.len() as u32 {
        panic!("Windows IPC write_msg expected to write full buffer, but only wrote partial (wrote {} out of {} bytes)", size, bytes.len());
    }

    Ok(())
}

/// Non-atomic write to a handle.
///
/// Can be used for writes to an exclusive pipe,
/// where the send being split up into several calls poses no danger.
fn write_buf(handle: HANDLE, bytes: &[u8]) -> Result<(),WinError> {
    let total = bytes.len();
    if total == 0 {
        return Ok(());
    }

    let mut written = 0;
    while written < total {
        let mut sz: u32 = 0;
        unsafe {
            let bytes_to_write = &bytes[written..];
            if kernel32::WriteFile(handle,
                                   bytes_to_write.as_ptr() as LPVOID,
                                   bytes_to_write.len() as u32,
                                   &mut sz,
                                   ptr::null_mut())
                == winapi::FALSE
            {
                return Err(WinError::last("WriteFile"));
            }
        }
        written += sz as usize;
        win32_trace!("[c {:?}] ... wrote {} bytes, total {}/{} err {}", handle, sz, written, bytes.len(), GetLastError());
    }

    Ok(())
}

impl OsIpcSender {
    pub fn connect(name: String) -> Result<OsIpcSender,WinError> {
        let pipe_name = make_pipe_name(&Uuid::parse_str(&name).unwrap());
        OsIpcSender::connect_named(&pipe_name)
    }

    pub fn get_max_fragment_size() -> usize {
        MAX_FRAGMENT_SIZE
    }

    unsafe fn from_handle(handle: HANDLE) -> OsIpcSender {
        OsIpcSender {
            handle: WinHandle::new(handle),
            nosync_marker: PhantomData,
        }
    }

    /// Connect to a pipe server.
    fn connect_named(pipe_name: &CString) -> Result<OsIpcSender,WinError> {
        unsafe {
            let handle =
                kernel32::CreateFileA(pipe_name.as_ptr(),
                                      winapi::GENERIC_WRITE,
                                      0,
                                      ptr::null_mut(), // lpSecurityAttributes
                                      winapi::OPEN_EXISTING,
                                      winapi::FILE_ATTRIBUTE_NORMAL,
                                      ptr::null_mut());
            if handle == INVALID_HANDLE_VALUE {
                return Err(WinError::last("CreateFileA"));
            }

            win32_trace!("[c {:?}] connect_to_server success", handle);

            Ok(OsIpcSender::from_handle(handle))
        }
    }

    fn get_pipe_server_process_id(&self) -> Result<winapi::ULONG,WinError> {
        unsafe {
            let mut server_pid: winapi::ULONG = 0;
            if kernel32::GetNamedPipeServerProcessId(*self.handle, &mut server_pid) == winapi::FALSE {
                return Err(WinError::last("GetNamedPipeServerProcessId"));
            }
            Ok(server_pid)
        }
    }

    fn get_pipe_server_process_handle_and_pid(&self) -> Result<(WinHandle, winapi::ULONG),WinError> {
        unsafe {
            let server_pid = try!(self.get_pipe_server_process_id());
            if server_pid == *CURRENT_PROCESS_ID {
                return Ok((WinHandle::new(*CURRENT_PROCESS_HANDLE as HANDLE), server_pid));
            }

            let raw_handle = kernel32::OpenProcess(winapi::PROCESS_DUP_HANDLE,
                                                   winapi::FALSE,
                                                   server_pid as winapi::DWORD);
            if raw_handle.is_null() {
                return Err(WinError::last("OpenProcess"));
            }

            Ok((WinHandle::new(raw_handle), server_pid))
        }
    }

    fn needs_fragmentation(data_len: usize, oob: &OutOfBandMessage) -> bool {
        let oob_size = if oob.needs_to_be_sent() { bincode::serialized_size(oob) } else { 0 };

        // make sure we don't have too much oob data to begin with
        assert!((oob_size as usize) < (PIPE_BUFFER_SIZE-MessageHeader::size()), "too much oob data");

        let bytes_left_for_data = (PIPE_BUFFER_SIZE-MessageHeader::size()) - (oob_size as usize);
        data_len >= bytes_left_for_data
    }

    /// An internal-use-only send method that sends just raw data, with no header.
    fn send_raw(&self, data: &[u8]) -> Result<(),WinError> {
        win32_trace!("[c {:?}] writing {} bytes raw to (pid {}->{})", *self.handle, data.len(), *CURRENT_PROCESS_ID,
             try!(self.get_pipe_server_process_id()));

        write_buf(*self.handle, data)
    }

    pub fn send(&self,
                data: &[u8],
                ports: Vec<OsIpcChannel>,
                shared_memory_regions: Vec<OsIpcSharedMemory>)
                -> Result<(),WinError>
    {
        // We limit the max size we can send here; we can fix this
        // just by upping the header to be 2x u64 if we really want
        // to.
        assert!(data.len() < u32::max_value() as usize);

        let (server_h, server_pid) = if !shared_memory_regions.is_empty() || !ports.is_empty() {
            try!(self.get_pipe_server_process_handle_and_pid())
        } else {
            (WinHandle::invalid(), 0)
        };

        let mut oob = OutOfBandMessage::new(server_pid);

        for ref shmem in shared_memory_regions {
            // shmem.handle, shmem.length
            let mut remote_handle = try!(dup_handle_to_process(&shmem.handle, &server_h));
            oob.shmem_handles.push((remote_handle.take() as intptr_t, shmem.length as u64));
        }

        for port in ports {
            match port {
                OsIpcChannel::Sender(mut s) => {
                    let mut raw_remote_handle = try!(move_handle_to_process(&mut s.handle, &server_h));
                    oob.channel_handles.push(raw_remote_handle.take() as intptr_t);
                },
                OsIpcChannel::Receiver(r) => {
                    if try!(r.prepare_for_transfer()) == false {
                        panic!("Sending receiver with outstanding partial read buffer, noooooo!  What should even happen?");
                    }

                    let mut raw_remote_handle = try!(move_handle_to_process(&mut r.reader.borrow_mut().handle, &server_h));
                    oob.channel_handles.push(raw_remote_handle.take() as intptr_t);
                },
            }
        }

        // Do we need to fragment?
        let big_data_sender: Option<OsIpcSender> =
            if OsIpcSender::needs_fragmentation(data.len(), &oob) {
                // We need to create a channel for the big data
                let (sender, receiver) = try!(channel());

                let (server_h, server_pid) = if server_h.is_valid() {
                    (server_h, server_pid)
                } else {
                    try!(self.get_pipe_server_process_handle_and_pid())
                };

                // Put the receiver in the OOB data
                let mut raw_receiver_handle = try!(move_handle_to_process(&mut receiver.reader.borrow_mut().handle, &server_h));
                oob.big_data_receiver_handle = Some((raw_receiver_handle.take() as intptr_t, data.len() as u64));
                oob.target_process_id = server_pid;

                Some(sender)
            } else {
                None
            };

        // If we need to send OOB data, serialize it
        let mut oob_data: Vec<u8> = vec![];
        if oob.needs_to_be_sent() {
            oob_data = bincode::serialize(&oob, bincode::Infinite).unwrap();
        }

        unsafe {
            let in_band_data_len = if big_data_sender.is_none() { data.len() } else { 0 };
            let full_in_band_len = MessageHeader::size() + in_band_data_len + oob_data.len();
            assert!(full_in_band_len <= PIPE_BUFFER_SIZE);

            let mut full_message = Vec::<u8>::with_capacity(full_in_band_len);
            full_message.set_len(full_in_band_len);

            let header = full_message.as_mut_ptr() as *mut MessageHeader;
            *header = MessageHeader(in_band_data_len as u32, oob_data.len() as u32);

            if big_data_sender.is_none() {
                &mut full_message[MessageHeader::size()..MessageHeader::size()+data.len()].clone_from_slice(data);
                &mut full_message[MessageHeader::size()+data.len()..].clone_from_slice(&oob_data);
                try!(write_msg(*self.handle, &full_message));
            } else {
                &mut full_message[MessageHeader::size()..].clone_from_slice(&oob_data);
                try!(write_msg(*self.handle, &full_message));
                try!(big_data_sender.unwrap().send_raw(data));
            }
        }

        Ok(())
    }
}

pub enum OsIpcSelectionResult {
    DataReceived(u64, Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),
    ChannelClosed(u64),
}

pub struct OsIpcReceiverSet {
    /// Our incrementor, for unique handle IDs.
    incrementor: Incrementor,

    /// The IOCP that we select on.
    iocp: WinHandle,

    /// The set of receivers, stored as MessageReaders.
    readers: Vec<MessageReader>,
}

impl OsIpcReceiverSet {
    pub fn new() -> Result<OsIpcReceiverSet,WinError> {
        unsafe {
            let iocp = kernel32::CreateIoCompletionPort(INVALID_HANDLE_VALUE,
                                                        ptr::null_mut(),
                                                        0 as winapi::ULONG_PTR,
                                                        0);
            if iocp.is_null() {
                return Err(WinError::last("CreateIoCompletionPort"));
            }

            Ok(OsIpcReceiverSet {
                incrementor: Incrementor::new(),
                iocp: WinHandle::new(iocp),
                readers: vec![],
            })
        }
    }

    pub fn add(&mut self, receiver: OsIpcReceiver) -> Result<u64,WinError> {
        // consume the receiver, and take the reader out
        let mut reader = receiver.reader.into_inner();

        let set_id = self.incrementor.increment();
        try!(reader.add_to_iocp(*self.iocp, set_id));

        win32_trace!("[# {:?}] ReceiverSet add {:?}, id {}", *self.iocp, *reader.handle, set_id);

        self.readers.push(reader);

        Ok(set_id)
    }

    pub fn select(&mut self) -> Result<Vec<OsIpcSelectionResult>,WinError> {
        assert!(!self.readers.is_empty(), "selecting with no objects?");
        win32_trace!("[# {:?}] select() with {} receivers", *self.iocp, self.readers.len());

        // the ultimate results
        let mut selection_results = vec![];

        // Make a quick first-run check for any closed receivers.
        // This will only happen if we have a receiver that
        // gets added to the Set after it was closed (the
        // router_drops_callbacks_on_cloned_sender_shutdown test
        // causes this.)
        self.readers.retain(|ref r| {
            if r.closed {
                selection_results.push(OsIpcSelectionResult::ChannelClosed(r.set_id.unwrap()));
                false
            } else {
                true
            }
        });

        // if we had prematurely closed elements, just process them first
        if !selection_results.is_empty() {
            return Ok(selection_results);
        }

        // Do this in a loop, because we may need to dequeue multiple packets to
        // read a complete message.
        loop {
            let mut nbytes: u32 = 0;
            let mut reader_index: Option<usize> = None;
            let mut io_err = winapi::ERROR_SUCCESS;

            unsafe {
                let mut completion_key: HANDLE = INVALID_HANDLE_VALUE;
                let mut ov_ptr: *mut winapi::OVERLAPPED = ptr::null_mut();
                // XXX use GetQueuedCompletionStatusEx to dequeue multiple CP at once!
                let ok = kernel32::GetQueuedCompletionStatus(*self.iocp,
                                                             &mut nbytes,
                                                             &mut completion_key as *mut _ as *mut winapi::ULONG_PTR,
                                                             &mut ov_ptr,
                                                             winapi::INFINITE);
                win32_trace!("[# {:?}] GetQueuedCS -> ok:{} nbytes:{} key:{:?}", *self.iocp, ok, nbytes, completion_key);
                if ok == winapi::FALSE {
                    // If the OVERLAPPED result is NULL, then the
                    // function call itself failed or timed out.
                    // Otherwise, the async IO operation failed, and
                    // we want to hand io_err to notify_completion below.
                    if ov_ptr.is_null() {
                        return Err(WinError::last("GetQueuedCompletionStatus"));
                    }

                    io_err = GetLastError();
                }

                assert!(!ov_ptr.is_null());
                assert!(completion_key != INVALID_HANDLE_VALUE);

                // Find the matching receiver
                for (index, ref mut reader) in self.readers.iter_mut().enumerate() {
                    if completion_key != *reader.handle {
                        continue;
                    }

                    reader_index = Some(index);
                    break;
                }
            }

            if reader_index.is_none() {
                panic!("Windows IPC ReceiverSet got notification for a receiver it doesn't know about");
            }

            let mut remove_index = None;

            // We need a scope here for the mutable borrow of self.readers;
            // we need to (maybe) remove an element from it below.
            {
                let reader_index = reader_index.unwrap();
                let reader = &mut self.readers[reader_index];

                win32_trace!("[# {:?}] result for receiver {:?}", *self.iocp, *reader.handle);

                // tell it about the completed IO op
                unsafe { try!(reader.notify_completion(io_err)); }

                // then drain as many messages as we can
                loop {
                    match try!(reader.get_message()) {
                        Some((data, channels, shmems)) => {
                            win32_trace!("[# {:?}] receiver {:?} ({}) got a message", *self.iocp, *reader.handle, reader.set_id.unwrap());
                            selection_results.push(OsIpcSelectionResult::DataReceived(reader.set_id.unwrap(), data, channels, shmems));
                        },
                        None => {
                            win32_trace!("[# {:?}] receiver {:?} ({}) -- no message", *self.iocp, *reader.handle, reader.set_id.unwrap());
                            break;
                        },
                    }
                }

                // We may have already been closed, or the read resulted in us being closed.
                // If so, add that to the result and remove the reader from our list.
                if reader.closed {
                    win32_trace!("[# {:?}] receiver {:?} ({}) -- now closed!", *self.iocp, *reader.handle, reader.set_id.unwrap());
                    selection_results.push(OsIpcSelectionResult::ChannelClosed(reader.set_id.unwrap()));
                    remove_index = Some(reader_index);
                } else {
                    try!(reader.start_read());
                }
            }

            if remove_index.is_some() {
                self.readers.swap_remove(remove_index.unwrap());
            }

            // if we didn't dequeue at least one complete message -- we need to loop through GetQueuedCS again;
            // otherwise we're done.
            if !selection_results.is_empty() {
                break;
            }
        }

        win32_trace!("select() -> {} results", selection_results.len());
        Ok(selection_results)
    }
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

#[derive(Debug)]
pub struct OsIpcSharedMemory {
    handle: WinHandle,
    ptr: *mut u8,
    length: usize,
}

unsafe impl Send for OsIpcSharedMemory {}
unsafe impl Sync for OsIpcSharedMemory {}

impl Drop for OsIpcSharedMemory {
    fn drop(&mut self) {
        unsafe {
            kernel32::UnmapViewOfFile(self.ptr as LPVOID);
        }
    }
}

impl Clone for OsIpcSharedMemory {
    fn clone(&self) -> OsIpcSharedMemory {
        unsafe {
            let mut handle = dup_handle(&self.handle).unwrap();
            OsIpcSharedMemory::from_handle(handle.take(), self.length).unwrap()
        }
    }
}

impl PartialEq for OsIpcSharedMemory {
    fn eq(&self, other: &OsIpcSharedMemory) -> bool {
        // Due to the way `WinHandle.eq()` is currently implemented,
        // this only finds equality when comparing the very same SHM structure --
        // it doesn't recognize cloned SHM structures as equal.
        // (Neither when cloned explicitly, nor implicitly through an IPC transfer.)
        //
        // It's not clear though whether the inability to test this
        // is really a meaningful limitation...
        self.handle == other.handle
    }
}

impl Deref for OsIpcSharedMemory {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        assert!(!self.ptr.is_null() && self.handle.is_valid());
        unsafe {
            slice::from_raw_parts(self.ptr, self.length)
        }
    }
}

impl OsIpcSharedMemory {
    #[allow(exceeding_bitshifts)]
    fn new(length: usize) -> Result<OsIpcSharedMemory,WinError> {
        unsafe {
            assert!(length < u32::max_value() as usize);
            let (lhigh, llow) = (0 as u32, (length & 0xffffffffusize) as u32);
            let handle =
                kernel32::CreateFileMappingA(INVALID_HANDLE_VALUE,
                                             ptr::null_mut(),
                                             winapi::PAGE_READWRITE | winapi::SEC_COMMIT,
                                             lhigh, llow,
                                             ptr::null_mut());
            if handle == INVALID_HANDLE_VALUE {
                return Err(WinError::last("CreateFileMapping"));
            }

            OsIpcSharedMemory::from_handle(handle, length)
        }
    }

    // There is no easy way to query the size of the mapping -- you
    // can use NtQuerySection, but that's an undocumented NT kernel
    // API.  Instead we'll just always pass the length along.
    //
    // This function takes ownership of the handle, and will close it
    // when finished.
    unsafe fn from_handle(handle_raw: HANDLE, length: usize) -> Result<OsIpcSharedMemory,WinError> {
        // turn this into a WinHandle, because that will
        // take care of closing it
        let handle = WinHandle::new(handle_raw);
        let address = kernel32::MapViewOfFile(handle_raw,
                                              winapi::FILE_MAP_ALL_ACCESS,
                                              0, 0, 0);
        if address.is_null() {
            return Err(WinError::last("MapViewOfFile"));
        }

        Ok(OsIpcSharedMemory {
            handle: handle,
            ptr: address as *mut u8,
            length: length
        })
    }

    pub fn from_byte(byte: u8, length: usize) -> OsIpcSharedMemory {
        unsafe {
            // panic if we can't create it
            let mem = OsIpcSharedMemory::new(length).unwrap();
            for element in slice::from_raw_parts_mut(mem.ptr, mem.length) {
                *element = byte;
            }
            mem
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> OsIpcSharedMemory {
        unsafe {
            // panic if we can't create it
            let mem = OsIpcSharedMemory::new(bytes.len()).unwrap();
            ptr::copy_nonoverlapping(bytes.as_ptr(), mem.ptr, bytes.len());
            mem
        }
    }
}

pub struct OsIpcOneShotServer {
    receiver: OsIpcReceiver,
}

impl OsIpcOneShotServer {
    pub fn new() -> Result<(OsIpcOneShotServer, String),WinError> {
        let pipe_id = make_pipe_id();
        let pipe_name = make_pipe_name(&pipe_id);
        let receiver = try!(OsIpcReceiver::new_named(&pipe_name));
        Ok((
            OsIpcOneShotServer {
                receiver: receiver,
            },
            pipe_id.to_string()
        ))
    }

    pub fn accept(self) -> Result<(OsIpcReceiver,
                                   Vec<u8>,
                                   Vec<OsOpaqueIpcChannel>,
                                   Vec<OsIpcSharedMemory>),WinError> {
        let receiver = self.receiver;
        try!(receiver.accept());
        let (data, channels, shmems) = try!(receiver.recv());
        Ok((receiver, data, channels, shmems))
    }
}

pub enum OsIpcChannel {
    Sender(OsIpcSender),
    Receiver(OsIpcReceiver),
}

#[derive(PartialEq, Debug)]
pub struct OsOpaqueIpcChannel {
    handle: HANDLE,
}

impl OsOpaqueIpcChannel {
    fn new(handle: HANDLE) -> OsOpaqueIpcChannel {
        OsOpaqueIpcChannel {
            handle: handle,
        }
    }

    pub fn to_receiver(&mut self) -> OsIpcReceiver {
        unsafe { OsIpcReceiver::from_handle(mem::replace(&mut self.handle, INVALID_HANDLE_VALUE)) }
    }

    pub fn to_sender(&mut self) -> OsIpcSender {
        unsafe { OsIpcSender::from_handle(mem::replace(&mut self.handle, INVALID_HANDLE_VALUE)) }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum WinError {
    WindowsResult(u32),
    ChannelClosed,
    NoData,
}

impl WinError {
    pub fn error_string(errnum: u32) -> String {
        // This value is calculated from the macro
        // MAKELANGID(LANG_SYSTEM_DEFAULT, SUBLANG_SYS_DEFAULT)
        let lang_id = 0x0800 as winapi::DWORD;
        let mut buf = [0 as winapi::WCHAR; 2048];

        unsafe {
            let res = kernel32::FormatMessageW(winapi::FORMAT_MESSAGE_FROM_SYSTEM |
                                               winapi::FORMAT_MESSAGE_IGNORE_INSERTS,
                                               ptr::null_mut(),
                                               errnum as winapi::DWORD,
                                               lang_id,
                                               buf.as_mut_ptr(),
                                               buf.len() as winapi::DWORD,
                                               ptr::null_mut()) as usize;
            if res == 0 {
                // Sometimes FormatMessageW can fail e.g. system doesn't like lang_id,
                let fm_err = kernel32::GetLastError();
                return format!("OS Error {} (FormatMessageW() returned error {})",
                               errnum, fm_err);
            }

            match String::from_utf16(&buf[..res]) {
                Ok(msg) => {
                    // Trim trailing CRLF inserted by FormatMessageW
                    msg.trim().to_string()
                },
                Err(..) => format!("OS Error {} (FormatMessageW() returned \
                                    invalid UTF-16)", errnum),
            }
        }
    }

    fn from_system(err: u32, f: &str) -> WinError {
        win32_trace!("WinError: {} ({}) from {}", WinError::error_string(err), err, f);
        WinError::WindowsResult(err)
    }

    fn last(f: &str) -> WinError {
        WinError::from_system(GetLastError(), f)
    }

    pub fn channel_is_closed(&self) -> bool {
        match *self {
            WinError::ChannelClosed => true,
            _ => false,
        }
    }
}

impl From<WinError> for bincode::Error {
    fn from(error: WinError) -> bincode::Error {
        Error::from(error).into()
    }
}

impl From<WinError> for Error {
    fn from(error: WinError) -> Error {
        match error {
            WinError::ChannelClosed => {
                Error::new(ErrorKind::BrokenPipe, "Win channel closed")
            },
            WinError::NoData => {
                Error::new(ErrorKind::WouldBlock, "Win channel has no data available")
            },
            WinError::WindowsResult(err) => {
                Error::from_raw_os_error(err as i32)
            },
        }
    }
}
