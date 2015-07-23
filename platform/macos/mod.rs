// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use platform::macos::mach_sys::{kern_return_t, mach_msg_body_t, mach_msg_header_t};
use platform::macos::mach_sys::{mach_msg_ool_descriptor_t, mach_msg_port_descriptor_t};
use platform::macos::mach_sys::{mach_msg_timeout_t, mach_port_right_t, mach_port_t};
use platform::macos::mach_sys::{mach_task_self_};

use libc::{self, c_char, c_uint, c_void, size_t};
use rand::{self, Rng};
use std::cell::Cell;
use std::ffi::CString;
use std::fmt::{self, Debug, Formatter};
use std::mem;
use std::ops::Deref;
use std::ptr;
use std::slice;
use std::slice::bytes::MutableByteVector;

mod mach_sys;

/// The size that we preallocate on the stack to receive messages. If the message is larger than
/// this, we retry and spill to the heap.
const SMALL_MESSAGE_SIZE: usize = 4096;

/// A string to prepend to our bootstrap ports.
static BOOTSTRAP_PREFIX: &'static str = "org.rust-lang.ipc-channel.";

const BOOTSTRAP_SUCCESS: kern_return_t = 0;
const BOOTSTRAP_NAME_IN_USE: kern_return_t = 1101;
const KERN_SUCCESS: kern_return_t = 0;
const KERN_INVALID_RIGHT: kern_return_t = 17;
const MACH_MSG_OOL_DESCRIPTOR: u8 = 1;
const MACH_MSG_PORT_DESCRIPTOR: u8 = 0;
const MACH_MSG_SUCCESS: kern_return_t = 0;
const MACH_MSG_TIMEOUT_NONE: mach_msg_timeout_t = 0;
const MACH_MSG_TYPE_MOVE_RECEIVE: u8 = 16;
const MACH_MSG_TYPE_MOVE_SEND: u8 = 17;
const MACH_MSG_TYPE_COPY_SEND: u8 = 19;
const MACH_MSG_TYPE_MAKE_SEND: u8 = 20;
const MACH_MSG_TYPE_MAKE_SEND_ONCE: u8 = 21;
const MACH_MSG_TYPE_PORT_SEND: u8 = MACH_MSG_TYPE_MOVE_SEND;
const MACH_MSG_VIRTUAL_COPY: c_uint = 1;
const MACH_MSGH_BITS_COMPLEX: u32 = 0x80000000;
const MACH_NOTIFY_FIRST: i32 = 64;
const MACH_NOTIFY_NO_SENDERS: i32 = MACH_NOTIFY_FIRST + 6;
const MACH_PORT_NULL: mach_port_t = 0;
const MACH_PORT_RIGHT_PORT_SET: mach_port_right_t = 3;
const MACH_PORT_RIGHT_RECEIVE: mach_port_right_t = 1;
const MACH_PORT_RIGHT_SEND: mach_port_right_t = 0;
const MACH_SEND_MSG: i32 = 1;
const MACH_RCV_MSG: i32 = 2;
const MACH_RCV_LARGE: i32 = 4;
const MACH_RCV_TOO_LARGE: i32 = 0x10004004;
const TASK_BOOTSTRAP_PORT: i32 = 4;

#[allow(non_camel_case_types)]
type name_t = *const c_char;

pub fn channel() -> Result<(MachSender, MachReceiver),MachError> {
    let receiver = try!(MachReceiver::new());
    let sender = try!(receiver.sender());
    try!(receiver.request_no_senders_notification());
    Ok((sender, receiver))
}

#[derive(PartialEq, Debug)]
pub struct MachReceiver {
    port: Cell<mach_port_t>,
}

impl Drop for MachReceiver {
    fn drop(&mut self) {
        let port = self.port.get();
        if port != MACH_PORT_NULL {
            unsafe {
                assert!(mach_sys::mach_port_mod_refs(mach_task_self(),
                                                     port,
                                                     MACH_PORT_RIGHT_RECEIVE,
                                                     -1) == KERN_SUCCESS);
            }
        }
    }
}

impl MachReceiver {
    fn new() -> Result<MachReceiver,MachError> {
        let mut port: mach_port_t = 0;
        let os_result = unsafe {
            mach_sys::mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mut port)
        };
        if os_result == KERN_SUCCESS {
            Ok(MachReceiver::from_name(port))
        } else {
            Err(MachError(os_result))
        }
    }

    fn from_name(port: mach_port_t) -> MachReceiver {
        MachReceiver {
            port: Cell::new(port),
        }
    }

    fn consume_port(&self) -> mach_port_t {
        let port = self.port.get();
        debug_assert!(port != MACH_PORT_NULL);
        self.port.set(MACH_PORT_NULL);
        port
    }

    pub fn consume(&self) -> MachReceiver {
        MachReceiver::from_name(self.consume_port())
    }

    fn sender(&self) -> Result<MachSender,MachError> {
        let port = self.port.get();
        debug_assert!(port != MACH_PORT_NULL);
        unsafe {
            let (mut right, mut acquired_right) = (0, 0);
            let os_result = mach_sys::mach_port_extract_right(mach_task_self(),
                                                              port,
                                                              MACH_MSG_TYPE_MAKE_SEND as u32,
                                                              &mut right,
                                                              &mut acquired_right);
            if os_result == KERN_SUCCESS {
                debug_assert!(acquired_right == MACH_MSG_TYPE_PORT_SEND as u32);
                Ok(MachSender::from_name(right))
            } else {
                Err(MachError(os_result))
            }
        }
    }

    fn register_bootstrap_name(&self) -> Result<String,MachError> {
        let port = self.port.get();
        debug_assert!(port != MACH_PORT_NULL);
        unsafe {
            let mut bootstrap_port = 0;
            let os_result = mach_sys::task_get_special_port(mach_task_self(),
                                                            TASK_BOOTSTRAP_PORT,
                                                            &mut bootstrap_port);
            if os_result != KERN_SUCCESS {
                return Err(MachError(os_result))
            }


            // FIXME(pcwalton): Does this leak?
            let (mut right, mut acquired_right) = (0, 0);
            let os_result = mach_sys::mach_port_extract_right(mach_task_self(),
                                                              port,
                                                              MACH_MSG_TYPE_MAKE_SEND as u32,
                                                              &mut right,
                                                              &mut acquired_right);
            if os_result != KERN_SUCCESS {
                return Err(MachError(os_result))
            }
            debug_assert!(acquired_right == MACH_MSG_TYPE_PORT_SEND as u32);

            let mut os_result;
            let mut name;
            loop {
                name = format!("{}{}", BOOTSTRAP_PREFIX, rand::thread_rng().gen::<i64>());
                let c_name = CString::new(name.clone()).unwrap();
                os_result = bootstrap_register2(bootstrap_port, c_name.as_ptr(), right, 0);
                if os_result == BOOTSTRAP_NAME_IN_USE {
                    continue
                }
                if os_result != BOOTSTRAP_SUCCESS {
                    return Err(MachError(os_result))
                }
                break
            }
            Ok(name)
        }
    }

    fn unregister_global_name(name: String) -> Result<(),MachError> {
        unsafe {
            let mut bootstrap_port = 0;
            let os_result = mach_sys::task_get_special_port(mach_task_self(),
                                                            TASK_BOOTSTRAP_PORT,
                                                            &mut bootstrap_port);
            if os_result != KERN_SUCCESS {
                return Err(MachError(os_result))
            }

            let c_name = CString::new(name).unwrap();
            let os_result = bootstrap_register2(bootstrap_port,
                                                c_name.as_ptr(),
                                                MACH_PORT_NULL,
                                                0);
            if os_result == BOOTSTRAP_SUCCESS {
                Ok(())
            } else {
                Err(MachError(os_result))
            }
        }
    }

    fn request_no_senders_notification(&self) -> Result<(),MachError> {
        let port = self.port.get();
        debug_assert!(port != MACH_PORT_NULL);
        unsafe {
            let os_result =
                mach_sys::mach_port_request_notification(mach_task_self(),
                                                         port,
                                                         MACH_NOTIFY_NO_SENDERS,
                                                         0,
                                                         port,
                                                         MACH_MSG_TYPE_MAKE_SEND_ONCE as u32,
                                                         &mut 0);
            if os_result != KERN_SUCCESS {
                return Err(MachError(os_result))
            }
        }
        Ok(())
    }

    pub fn recv(&self)
                -> Result<(Vec<u8>, Vec<OpaqueMachChannel>, Vec<MachSharedMemory>),MachError> {
        select(self.port.get()).and_then(|result| {
            match result {
                MachSelectionResult::DataReceived(_, data, channels, shared_memory_regions) => {
                    Ok((data, channels, shared_memory_regions))
                }
                MachSelectionResult::ChannelClosed(_) => Err(MachError(MACH_NOTIFY_NO_SENDERS)),
            }
        })
    }
}

#[derive(PartialEq, Debug)]
pub struct MachSender {
    port: mach_port_t,
}

impl Drop for MachSender {
    fn drop(&mut self) {
        unsafe {
            let error = mach_sys::mach_port_mod_refs(mach_task_self(),
                                                     self.port,
                                                     MACH_PORT_RIGHT_SEND,
                                                     -1);
            // `KERN_INVALID_RIGHT` is returned if (as far as I can tell) the receiver already shut
            // down. This is fine.
            if error != KERN_SUCCESS && error != KERN_INVALID_RIGHT {
                panic!("mach_port_mod_refs(-1, {}) failed: {:08x}", self.port, error)
            }
        }
    }
}

impl Clone for MachSender {
    fn clone(&self) -> MachSender {
        unsafe {
            assert!(mach_sys::mach_port_mod_refs(mach_task_self(),
                                                 self.port,
                                                 MACH_PORT_RIGHT_SEND,
                                                 1) == KERN_SUCCESS);
        }
        MachSender {
            port: self.port,
        }
    }
}

impl MachSender {
    fn from_name(port: mach_port_t) -> MachSender {
        MachSender {
            port: port,
        }
    }

    pub fn connect(name: String) -> Result<MachSender,MachError> {
        unsafe {
            let mut bootstrap_port = 0;
            let os_result = mach_sys::task_get_special_port(mach_task_self(),
                                                            TASK_BOOTSTRAP_PORT,
                                                            &mut bootstrap_port);
            if os_result != KERN_SUCCESS {
                return Err(MachError(os_result))
            }

            let mut port = 0;
            let c_name = CString::new(name).unwrap();
            let os_result = bootstrap_look_up(bootstrap_port, c_name.as_ptr(), &mut port);
            if os_result == BOOTSTRAP_SUCCESS {
                Ok(MachSender::from_name(port))
            } else {
                Err(MachError(os_result))
            }
        }
    }

    pub fn send(&self,
                data: &[u8],
                ports: Vec<MachChannel>,
                shared_memory_regions: Vec<MachSharedMemory>)
                -> Result<(),MachError> {
        unsafe {
            let size = Message::size_of(data.len(), ports.len(), shared_memory_regions.len());
            let message = libc::malloc(size as size_t) as *mut Message;
            (*message).header.msgh_bits = (MACH_MSG_TYPE_COPY_SEND as u32) |
                MACH_MSGH_BITS_COMPLEX;
            (*message).header.msgh_size = size as u32;
            (*message).header.msgh_local_port = MACH_PORT_NULL;
            (*message).header.msgh_remote_port = self.port;
            (*message).header.msgh_reserved = 0;
            (*message).header.msgh_id = 0;
            (*message).body.msgh_descriptor_count =
                (ports.len() + shared_memory_regions.len()) as u32;

            let mut port_descriptor_dest = message.offset(1) as *mut mach_msg_port_descriptor_t;
            for outgoing_port in ports.into_iter() {
                (*port_descriptor_dest).name = outgoing_port.port();
                (*port_descriptor_dest).pad1 = 0;

                (*port_descriptor_dest).disposition = match outgoing_port {
                    MachChannel::Sender(_) => MACH_MSG_TYPE_MOVE_SEND,
                    MachChannel::Receiver(_) => MACH_MSG_TYPE_MOVE_RECEIVE,
                };

                (*port_descriptor_dest).type_ = MACH_MSG_PORT_DESCRIPTOR;
                port_descriptor_dest = port_descriptor_dest.offset(1);
                mem::forget(outgoing_port);
            }

            let mut shared_memory_descriptor_dest =
                port_descriptor_dest as *mut mach_msg_ool_descriptor_t;
            for shared_memory_region in shared_memory_regions.into_iter() {
                (*shared_memory_descriptor_dest).address =
                    shared_memory_region.as_ptr() as *const c_void as *mut c_void;
                (*shared_memory_descriptor_dest).size = shared_memory_region.len() as u32;
                (*shared_memory_descriptor_dest).deallocate = 1;
                (*shared_memory_descriptor_dest).copy = MACH_MSG_VIRTUAL_COPY as u8;
                (*shared_memory_descriptor_dest).type_ = MACH_MSG_OOL_DESCRIPTOR;
                mem::forget(shared_memory_region);
                shared_memory_descriptor_dest = shared_memory_descriptor_dest.offset(1);
            }

            // Zero out the last word for paranoia's sake.
            *((message as *mut u8).offset(size as isize - 4) as *mut u32) = 0;

            let data_dest = shared_memory_descriptor_dest as *mut u8;
            ptr::copy_nonoverlapping(data.as_ptr(), data_dest, data.len());

            let mut ptr = message as *const u32;
            let end = (message as *const u8).offset(size as isize) as *const u32;
            while ptr < end {
                ptr = ptr.offset(1);
            }

            let os_result = mach_sys::mach_msg(message as *mut _,
                                               MACH_SEND_MSG,
                                               (*message).header.msgh_size,
                                               0,
                                               MACH_PORT_NULL,
                                               MACH_MSG_TIMEOUT_NONE,
                                               MACH_PORT_NULL);
            if os_result != MACH_MSG_SUCCESS {
                return Err(MachError(os_result))
            }
            libc::free(message as *mut _);
            Ok(())
        }
    }
}

pub enum MachChannel {
    Sender(MachSender),
    Receiver(MachReceiver),
}

impl MachChannel {
    fn port(&self) -> mach_port_t {
        match *self {
            MachChannel::Sender(ref sender) => sender.port,
            MachChannel::Receiver(ref receiver) => receiver.port.get(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct OpaqueMachChannel {
    port: mach_port_t,
}

impl Drop for OpaqueMachChannel {
    fn drop(&mut self) {
        // Make sure we don't leak!
        debug_assert!(self.port == MACH_PORT_NULL);
    }
}

impl OpaqueMachChannel {
    fn from_name(name: mach_port_t) -> OpaqueMachChannel {
        OpaqueMachChannel {
            port: name,
        }
    }

    pub fn to_sender(&mut self) -> MachSender {
        MachSender {
            port: mem::replace(&mut self.port, MACH_PORT_NULL),
        }
    }

    pub fn to_receiver(&mut self) -> MachReceiver {
        MachReceiver::from_name(mem::replace(&mut self.port, MACH_PORT_NULL))
    }
}

pub struct MachReceiverSet {
    port: Cell<mach_port_t>,
}

impl MachReceiverSet {
    pub fn new() -> Result<MachReceiverSet,MachError> {
        let mut port: mach_port_t = 0;
        let os_result = unsafe {
            mach_sys::mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &mut port)
        };
        if os_result == KERN_SUCCESS {
            Ok(MachReceiverSet {
                port: Cell::new(port),
            })
        } else {
            Err(MachError(os_result))
        }
    }

    pub fn add(&mut self, receiver: MachReceiver) -> Result<i64,MachError> {
        let receiver_port = receiver.consume_port();
        let os_result = unsafe {
            mach_sys::mach_port_move_member(mach_task_self(), receiver_port, self.port.get())
        };
        if os_result == KERN_SUCCESS {
            Ok(receiver_port as i64)
        } else {
            Err(MachError(os_result))
        }
    }

    pub fn select(&mut self) -> Result<Vec<MachSelectionResult>,MachError> {
        match select(self.port.get()).map(|result| vec![result]) {
            Ok(results) => Ok(results),
            Err(error) => {
                Err(error)
            }
        }
    }
}

pub enum MachSelectionResult {
    DataReceived(i64, Vec<u8>, Vec<OpaqueMachChannel>, Vec<MachSharedMemory>),
    ChannelClosed(i64),
}

impl MachSelectionResult {
    pub fn unwrap(self) -> (i64, Vec<u8>, Vec<OpaqueMachChannel>, Vec<MachSharedMemory>) {
        match self {
            MachSelectionResult::DataReceived(id, data, channels, shared_memory_regions) => {
                (id, data, channels, shared_memory_regions)
            }
            MachSelectionResult::ChannelClosed(id) => {
                panic!("MachSelectionResult::unwrap(): receiver ID {} was closed!", id)
            }
        }
    }
}

fn select(port: mach_port_t) -> Result<MachSelectionResult,MachError> {
    debug_assert!(port != MACH_PORT_NULL);
    unsafe {
        let mut buffer = [0; SMALL_MESSAGE_SIZE];
        let allocated_buffer = None;
        setup_receive_buffer(&mut buffer, port);
        let mut message = &mut buffer[0] as *mut _ as *mut Message;
        match mach_sys::mach_msg(message as *mut _,
                                 MACH_RCV_MSG | MACH_RCV_LARGE,
                                 0,
                                 (*message).header.msgh_size,
                                 port,
                                 MACH_MSG_TIMEOUT_NONE,
                                 MACH_PORT_NULL) {
            MACH_RCV_TOO_LARGE => {
                // Do a loop. There's no way I know of to figure out precisely in advance how big
                // the message actually is!
                let mut extra_size = 8;
                loop {
                    let actual_size = (*message).header.msgh_size + extra_size;
                    let allocated_buffer = Some(libc::malloc(actual_size as size_t));
                    setup_receive_buffer(slice::from_raw_parts_mut(
                                            allocated_buffer.unwrap() as *mut u8,
                                            actual_size as usize),
                                         port);
                    message = allocated_buffer.unwrap() as *mut Message;
                    match mach_sys::mach_msg(message as *mut _,
                                             MACH_RCV_MSG | MACH_RCV_LARGE,
                                             0,
                                             actual_size,
                                             port,
                                             MACH_MSG_TIMEOUT_NONE,
                                             MACH_PORT_NULL) {
                        MACH_MSG_SUCCESS => break,
                        MACH_RCV_TOO_LARGE => {}
                        os_result => return Err(MachError(os_result)),
                    }

                    extra_size *= 2;
                }
            }
            MACH_MSG_SUCCESS => {}
            os_result => return Err(MachError(os_result)),
        }

        let local_port = (*message).header.msgh_local_port;
        if (*message).header.msgh_id == MACH_NOTIFY_NO_SENDERS {
            return Ok(MachSelectionResult::ChannelClosed(local_port as i64))
        }

        let (mut ports, mut shared_memory_regions) = (Vec::new(), Vec::new());
        let mut port_descriptor = message.offset(1) as *mut mach_msg_port_descriptor_t;
        let mut descriptors_remaining = (*message).body.msgh_descriptor_count;
        while descriptors_remaining > 0 {
            if (*port_descriptor).type_ != MACH_MSG_PORT_DESCRIPTOR {
                break
            }
            ports.push(OpaqueMachChannel::from_name((*port_descriptor).name));
            port_descriptor = port_descriptor.offset(1);
            descriptors_remaining -= 1;
        }

        let mut shared_memory_descriptor = port_descriptor as *mut mach_msg_ool_descriptor_t;
        while descriptors_remaining > 0 {
            debug_assert!((*shared_memory_descriptor).type_ == MACH_MSG_OOL_DESCRIPTOR);
            shared_memory_regions.push(MachSharedMemory::from_raw_parts(
                    (*shared_memory_descriptor).address as *mut u8,
                    (*shared_memory_descriptor).size as usize));
            shared_memory_descriptor = shared_memory_descriptor.offset(1);
            descriptors_remaining -= 1;
        }

        let payload_ptr = shared_memory_descriptor as *mut u8;
        let payload_size = message as usize + ((*message).header.msgh_size as usize) -
            (shared_memory_descriptor as usize);
        let payload = slice::from_raw_parts(payload_ptr, payload_size).to_vec();

        if let Some(allocated_buffer) = allocated_buffer {
            libc::free(allocated_buffer)
        }

        Ok(MachSelectionResult::DataReceived(local_port as i64,
                                             payload,
                                             ports,
                                             shared_memory_regions))
    }
}

pub struct MachOneShotServer {
    receiver: Option<MachReceiver>,
    name: String,
}

impl Drop for MachOneShotServer {
    fn drop(&mut self) {
        drop(MachReceiver::unregister_global_name(mem::replace(&mut self.name, String::new())));
    }
}

impl MachOneShotServer {
    pub fn new() -> Result<(MachOneShotServer, String),MachError> {
        let receiver = try!(MachReceiver::new());
        let name = try!(receiver.register_bootstrap_name());
        Ok((MachOneShotServer {
            receiver: Some(receiver),
            name: name.clone(),
        }, name))
    }

    pub fn accept(mut self) -> Result<(MachReceiver,
                                       Vec<u8>,
                                       Vec<OpaqueMachChannel>,
                                       Vec<MachSharedMemory>),MachError> {
        let (bytes, channels, shared_memory_regions) =
            try!(self.receiver.as_mut().unwrap().recv());
        Ok((mem::replace(&mut self.receiver, None).unwrap(),
            bytes,
            channels,
            shared_memory_regions))
    }
}

pub struct MachSharedMemory {
    ptr: Cell<*mut u8>,
    length: usize,
}

unsafe impl Send for MachSharedMemory {}
unsafe impl Sync for MachSharedMemory {}

impl Drop for MachSharedMemory {
    fn drop(&mut self) {
        if !self.ptr.get().is_null() {
            unsafe {
                assert!(mach_sys::vm_deallocate(mach_task_self(),
                                                self.ptr.get() as usize,
                                                self.length) == KERN_SUCCESS);
            }
        }
    }
}

impl Clone for MachSharedMemory {
    fn clone(&self) -> MachSharedMemory {
        // TODO(pcwalton): Use `vm_remap()` or something to avoid a copy.
        MachSharedMemory::from_bytes(&**self)
    }
}

impl PartialEq for MachSharedMemory {
    fn eq(&self, other: &MachSharedMemory) -> bool {
        **self == **other
    }
}

impl Debug for MachSharedMemory {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), fmt::Error> {
        (**self).fmt(formatter)
    }
}

impl Deref for MachSharedMemory {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        if self.ptr.get().is_null() {
            panic!("attempted to access a consumed `MachSharedMemory`")
        }
        unsafe {
            slice::from_raw_parts(self.ptr.get(), self.length)
        }
    }
}

impl MachSharedMemory {
    unsafe fn from_raw_parts(ptr: *mut u8, length: usize) -> MachSharedMemory {
        MachSharedMemory {
            ptr: Cell::new(ptr),
            length: length,
        }
    }

    pub fn from_byte(byte: u8, length: usize) -> MachSharedMemory {
        unsafe {
            let address = allocate_vm_pages(length);
            slice::from_raw_parts_mut(address, length).set_memory(byte);
            MachSharedMemory::from_raw_parts(address, length)
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> MachSharedMemory {
        unsafe {
            let address = allocate_vm_pages(bytes.len());
            ptr::copy_nonoverlapping(bytes.as_ptr(), address, bytes.len());
            MachSharedMemory::from_raw_parts(address, bytes.len())
        }
    }

    pub fn consume(&self) -> MachSharedMemory {
        let ptr = self.ptr.get();
        self.ptr.set(ptr::null_mut());
        unsafe {
            MachSharedMemory::from_raw_parts(ptr, self.length)
        }
    }
}

unsafe fn allocate_vm_pages(length: usize) -> *mut u8 {
    let mut address = 0;
    let result = mach_sys::vm_allocate(mach_task_self(), &mut address, length, 1);
    if result != KERN_SUCCESS {
        panic!("`vm_allocate()` failed: {}", result);
    }
    address as *mut u8
}

unsafe fn setup_receive_buffer(buffer: &mut [u8], port_name: mach_port_t) {
    let message: *mut mach_msg_header_t = mem::transmute(&buffer[0]);
    (*message).msgh_local_port = port_name;
    (*message).msgh_size = buffer.len() as u32
}

unsafe fn mach_task_self() -> mach_port_t {
    mach_task_self_
}

#[repr(C)]
struct Message {
    header: mach_msg_header_t,
    body: mach_msg_body_t,
}

impl Message {
    fn size_of(data_length: usize, port_length: usize, shared_memory_length: usize) -> usize {
        let mut size = mem::size_of::<Message>() +
            mem::size_of::<mach_msg_port_descriptor_t>() * port_length +
            mem::size_of::<mach_msg_ool_descriptor_t>() * shared_memory_length +
            data_length;

        // Round up to the next 4 bytes.
        if (size & 0x3) != 0 {
            size = (size & !0x3) + 4;
        }

        size
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MachError(pub kern_return_t);

impl MachError {
    #[allow(dead_code)]
    pub fn channel_is_closed(&self) -> bool {
        self.0 == MACH_NOTIFY_NO_SENDERS
    }
}

extern {
    fn bootstrap_register2(bp: mach_port_t, service_name: name_t, sp: mach_port_t, flags: u64)
                           -> kern_return_t;
    fn bootstrap_look_up(bp: mach_port_t, service_name: name_t, sp: *mut mach_port_t)
                         -> kern_return_t;
}

