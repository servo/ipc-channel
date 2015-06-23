// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use platform::macos::mach_sys::{kern_return_t, mach_msg_body_t, mach_msg_header_t};
use platform::macos::mach_sys::{mach_msg_port_descriptor_t, mach_msg_timeout_t, mach_port_right_t};
use platform::macos::mach_sys::{mach_port_t, mach_task_self_};

use libc::{self, c_char, size_t};
use rand::{self, Rng};
use std::ffi::CString;
use std::mem;
use std::ptr;
use std::slice;

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
const MACH_MSG_PORT_DESCRIPTOR: u8 = 0;
const MACH_MSG_SUCCESS: kern_return_t = 0;
const MACH_MSG_TIMEOUT_NONE: mach_msg_timeout_t = 0;
const MACH_MSG_TYPE_MOVE_SEND: u8 = 17;
const MACH_MSG_TYPE_COPY_SEND: u8 = 19;
const MACH_MSG_TYPE_MAKE_SEND: u8 = 20;
const MACH_MSG_TYPE_PORT_SEND: u8 = MACH_MSG_TYPE_MOVE_SEND;
const MACH_MSGH_BITS_COMPLEX: u32 = 0x80000000;
const MACH_PORT_NULL: mach_port_t = 0;
const MACH_PORT_RIGHT_RECEIVE: mach_port_right_t = 1;
const MACH_PORT_RIGHT_SEND: mach_port_right_t = 0;
const MACH_SEND_MSG: i32 = 1;
const MACH_RCV_MSG: i32 = 2;
const MACH_RCV_LARGE: i32 = 4;
const MACH_RCV_TOO_LARGE: i32 = 0x10004004;
const TASK_BOOTSTRAP_PORT: i32 = 4;

#[allow(non_camel_case_types)]
type name_t = *const c_char;

#[derive(PartialEq, Debug)]
pub struct MachReceiver {
    port: mach_port_t,
}

impl Drop for MachReceiver {
    fn drop(&mut self) {
        unsafe {
            assert!(mach_sys::mach_port_mod_refs(mach_task_self(),
                                                 self.port,
                                                 MACH_PORT_RIGHT_RECEIVE,
                                                 -1) == KERN_SUCCESS);
        }
    }
}

impl MachReceiver {
    pub fn new() -> MachReceiver {
        let mut port: mach_port_t = 0;
        unsafe {
            assert!(mach_sys::mach_port_allocate(mach_task_self(),
                                                 MACH_PORT_RIGHT_RECEIVE,
                                                 &mut port) == KERN_SUCCESS);
        }
        MachReceiver {
            port: port
        }
    }

    pub fn sender(&self) -> MachSender {
        unsafe {
            let (mut right, mut acquired_right) = (0, 0);
            assert!(mach_sys::mach_port_extract_right(mach_task_self(),
                                                      self.port,
                                                      MACH_MSG_TYPE_MAKE_SEND as u32,
                                                      &mut right,
                                                      &mut acquired_right) == KERN_SUCCESS);
            debug_assert!(acquired_right == MACH_MSG_TYPE_PORT_SEND as u32);
            MachSender::from_name(right)
        }
    }

    pub fn register_global_name(&self) -> String {
        unsafe {
            let mut bootstrap_port = 0;
            assert!(mach_sys::task_get_special_port(mach_task_self(),
                                                    TASK_BOOTSTRAP_PORT,
                                                    &mut bootstrap_port) == KERN_SUCCESS);


            // FIXME(pcwalton): Does this leak?
            let (mut right, mut acquired_right) = (0, 0);
            assert!(mach_sys::mach_port_extract_right(mach_task_self(),
                                                      self.port,
                                                      MACH_MSG_TYPE_MAKE_SEND as u32,
                                                      &mut right,
                                                      &mut acquired_right) == KERN_SUCCESS);
            debug_assert!(acquired_right == MACH_MSG_TYPE_PORT_SEND as u32);

            let mut err;
            let mut name;
            loop {
                name = format!("{}{}", BOOTSTRAP_PREFIX, rand::thread_rng().gen::<i64>());
                let c_name = CString::new(name.clone()).unwrap();
                err = bootstrap_register2(bootstrap_port, c_name.as_ptr(), right, 0);
                if err == BOOTSTRAP_NAME_IN_USE {
                    continue
                }
                if err != BOOTSTRAP_SUCCESS {
                    panic!("bootstrap_register2() failed: {:08x}", err);
                }
                break
            }
            name
        }
    }

    pub fn unregister_global_name(name: String) {
        unsafe {
            let mut bootstrap_port = 0;
            assert!(mach_sys::task_get_special_port(mach_task_self(),
                                                    TASK_BOOTSTRAP_PORT,
                                                    &mut bootstrap_port) == KERN_SUCCESS);

            let c_name = CString::new(name).unwrap();
            assert!(bootstrap_register2(bootstrap_port, c_name.as_ptr(), MACH_PORT_NULL, 0) ==
                    BOOTSTRAP_SUCCESS);
        }
    }

    pub fn recv(&self) -> (Vec<u8>, Vec<MachSender>) {
        unsafe {
            let mut buffer = [0; SMALL_MESSAGE_SIZE];
            let allocated_buffer = None;
            setup_receive_buffer(&mut buffer, self.port);
            let mut message = &mut buffer[0] as *mut _ as *mut Message;
            match mach_sys::mach_msg(message as *mut _,
                                     MACH_RCV_MSG | MACH_RCV_LARGE,
                                     0,
                                     (*message).header.msgh_size,
                                     self.port,
                                     MACH_MSG_TIMEOUT_NONE,
                                     MACH_PORT_NULL) {
                MACH_RCV_TOO_LARGE => {
                    // For some reason the size reported by the kernel is too small by 8. Why?!
                    let actual_size = (*message).header.msgh_size + 8;
                    let allocated_buffer = Some(libc::malloc(actual_size as size_t));
                    setup_receive_buffer(slice::from_raw_parts_mut(
                                            allocated_buffer.unwrap() as *mut u8,
                                            actual_size as usize),
                                         self.port);
                    message = allocated_buffer.unwrap() as *mut Message;
                    match mach_sys::mach_msg(message as *mut _,
                                             MACH_RCV_MSG | MACH_RCV_LARGE,
                                             0,
                                             actual_size,
                                             self.port,
                                             MACH_MSG_TIMEOUT_NONE,
                                             MACH_PORT_NULL) {
                        MACH_MSG_SUCCESS => {}
                        error => panic!("error in mach_msg when receiving (big): {:08x}", error),
                    }
                }
                MACH_MSG_SUCCESS => {}
                error => panic!("error in mach_msg when receiving: {:08x}", error),
            }

            let mut ports = Vec::new();
            let mut port_descriptor = message.offset(1) as *mut mach_msg_port_descriptor_t;
            for _ in 0..(*message).body.msgh_descriptor_count {
                ports.push(MachSender::from_name((*port_descriptor).name));
                port_descriptor = port_descriptor.offset(1);
            }

            let payload_ptr = port_descriptor as *mut u8;
            let payload_size = message as usize + ((*message).header.msgh_size as usize) -
                (port_descriptor as usize);
            let payload = Vec::from_raw_buf(payload_ptr, payload_size);

            if let Some(allocated_buffer) = allocated_buffer {
                libc::free(allocated_buffer)
            }

            (payload, ports)
        }
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
        unsafe {
            let mut urefs = 0;
            mach_sys::mach_port_get_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, &mut urefs);
            println!("send right ref for {} at from_name = {}", port, urefs);
        }
        MachSender {
            port: port,
        }
    }

    pub fn from_global_name(name: String) -> MachSender {
        unsafe {
            let mut bootstrap_port = 0;
            assert!(mach_sys::task_get_special_port(mach_task_self(),
                                                    TASK_BOOTSTRAP_PORT,
                                                    &mut bootstrap_port) == KERN_SUCCESS);

            let mut port = 0;
            let c_name = CString::new(name).unwrap();
            assert!(bootstrap_look_up(bootstrap_port, c_name.as_ptr(), &mut port) ==
                    BOOTSTRAP_SUCCESS);
            MachSender::from_name(port)
        }
    }

    pub fn send(&self, data: &[u8], ports: Vec<MachSender>) {
        unsafe {
            let size = Message::size_of(data.len(), ports.len());
            let message = libc::malloc(size as size_t) as *mut Message;
            (*message).header.msgh_bits = (MACH_MSG_TYPE_COPY_SEND as u32) |
                MACH_MSGH_BITS_COMPLEX;
            (*message).header.msgh_size = size as u32;
            (*message).header.msgh_local_port = MACH_PORT_NULL;
            (*message).header.msgh_remote_port = self.port;
            (*message).header.msgh_reserved = 0;
            (*message).header.msgh_id = 0;
            (*message).body.msgh_descriptor_count = ports.len() as u32;
            let mut port_descriptor_dest = message.offset(1) as *mut mach_msg_port_descriptor_t;
            for outgoing_port in ports.into_iter() {
                (*port_descriptor_dest).name = outgoing_port.port;
                (*port_descriptor_dest).pad1 = 0;
                (*port_descriptor_dest).disposition = MACH_MSG_TYPE_COPY_SEND;
                (*port_descriptor_dest).type_ = MACH_MSG_PORT_DESCRIPTOR;
                port_descriptor_dest = port_descriptor_dest.offset(1);
                mem::forget(outgoing_port);
            }

            // Zero out the last word for paranoia's sake.
            *((message as *mut u8).offset(size as isize - 4) as *mut u32) = 0;

            let data_dest = port_descriptor_dest as *mut u8;
            ptr::copy_nonoverlapping(data.as_ptr(), data_dest, data.len());

            let mut ptr = message as *const u32;
            let end = (message as *const u8).offset(size as isize) as *const u32;
            while ptr < end {
                ptr = ptr.offset(1);
            }

            let err = mach_sys::mach_msg(message as *mut _,
                                         MACH_SEND_MSG,
                                         (*message).header.msgh_size,
                                         0,
                                         MACH_PORT_NULL,
                                         MACH_MSG_TIMEOUT_NONE,
                                         MACH_PORT_NULL);
            if err != MACH_MSG_SUCCESS {
                panic!("failed to send Mach message: {:x} (size: {})", err, size)
            }
            libc::free(message as *mut _);
        }
    }
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
    fn size_of(data_length: usize, port_length: usize) -> usize {
        let mut size = mem::size_of::<Message>() +
            mem::size_of::<mach_msg_port_descriptor_t>() * port_length + data_length;

        // Round up to the next 4 bytes.
        if (size & 0x3) != 0 {
            size = (size & !0x3) + 4;
        }

        size
    }
}

extern {
    fn bootstrap_register2(bp: mach_port_t, service_name: name_t, sp: mach_port_t, flags: u64)
                           -> kern_return_t;
    fn bootstrap_look_up(bp: mach_port_t, service_name: name_t, sp: *mut mach_port_t)
                         -> kern_return_t;
}

