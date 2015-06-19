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

use cocoa::foundation;
use libc::{self, c_char, c_uint, size_t};
use rand::{self, Rng};
use std::ffi::CString;
use std::mem;
use std::ptr;
use std::slice;

mod mach_sys;
mod test;

/// The size that we preallocate on the stack to receive messages. If the message is larger than
/// this, we retry and spill to the heap.
const SMALL_MESSAGE_SIZE: usize = 4096;

/// A string to prepend to our bootstrap ports.
static BOOTSTRAP_PREFIX: &'static str = "org.rust-lang.ipc-channel.";

const BOOTSTRAP_SUCCESS: kern_return_t = 0;
const BOOTSTRAP_NAME_IN_USE: kern_return_t = 1101;
const KERN_SUCCESS: kern_return_t = 0;
const MACH_MSG_PORT_DESCRIPTOR: u8 = 19;
const MACH_MSG_SUCCESS: kern_return_t = 0;
const MACH_MSG_TIMEOUT_NONE: mach_msg_timeout_t = 0;
const MACH_MSG_TYPE_COPY_SEND: u8 = 19;
const MACH_MSGH_BITS_COMPLEX: u32 = 0x80000000;
const MACH_MSGH_BITS_LOCAL_MASK: u32 = 0x0000ff00;
const MACH_PORT_NULL: mach_port_t = 0;
const MACH_PORT_RIGHT_RECEIVE: mach_port_right_t = 1;
const MACH_SEND_MSG: i32 = 1;
const MACH_RCV_MSG: i32 = 2;
const MACH_RCV_LARGE: i32 = 4;
const MACH_RCV_TOO_LARGE: i32 = 0x10004004;
const TASK_BOOTSTRAP_PORT: i32 = 4;

type name_t = *const c_char;

struct MachPort {
    port: mach_port_t,
}

impl Drop for MachPort {
    fn drop(&mut self) {
        unsafe {
            assert!(mach_sys::mach_port_deallocate(mach_task_self(), self.port) == KERN_SUCCESS)
        }
    }
}

impl MachPort {
    pub fn new() -> MachPort {
        let mut port: mach_port_t = 0;
        unsafe {
            assert!(mach_sys::mach_port_allocate(mach_task_self(),
                                                 MACH_PORT_RIGHT_RECEIVE,
                                                 &mut port) == KERN_SUCCESS);
        }
        MachPort {
            port: port
        }
    }

    fn from_name(port: mach_port_t) -> MachPort {
        MachPort {
            port: port,
        }
    }

    pub fn register_global_name(&self) -> String {
        unsafe {
            let mut bootstrap_port = 0;
            assert!(mach_sys::task_get_special_port(mach_task_self(),
                                                    TASK_BOOTSTRAP_PORT,
                                                    &mut bootstrap_port) == KERN_SUCCESS);


            let mut err = 0;
            let mut name;
            loop {
                name = format!("{}{}", BOOTSTRAP_PREFIX, rand::thread_rng().gen::<i64>());
                let c_name = CString::new(name.clone()).unwrap();
                err = bootstrap_register2(bootstrap_port, c_name.as_ptr(), self.port, 0);
                if err == BOOTSTRAP_NAME_IN_USE {
                    continue
                }
                assert!(err == BOOTSTRAP_SUCCESS);
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

    pub fn from_global_name(name: String) -> MachPort {
        unsafe {
            let mut bootstrap_port = 0;
            assert!(mach_sys::task_get_special_port(mach_task_self(),
                                                    TASK_BOOTSTRAP_PORT,
                                                    &mut bootstrap_port) == KERN_SUCCESS);

            let mut port = 0;
            let c_name = CString::new(name.clone()).unwrap();
            assert!(bootstrap_look_up(bootstrap_port, c_name.as_ptr(), &mut port) ==
                    BOOTSTRAP_SUCCESS);
            MachPort::from_name(port)
        }
    }

    pub fn send(&self, data: &[u8], ports: Vec<MachPort>) {
        unsafe {
            let size = Message::size_of(data.len(), ports.len());
            let mut message = libc::malloc(size as size_t) as *mut Message;
            (*message).header.msgh_bits = MACH_MSGH_BITS_COMPLEX;
            (*message).header.msgh_size = size as u32;
            (*message).header.msgh_local_port = MACH_PORT_NULL;
            (*message).header.msgh_remote_port = self.port;
            (*message).header.msgh_id = 0;
            (*message).body.msgh_descriptor_count = ports.len() as u32;
            let mut port_descriptor_dest = message.offset(1) as *mut mach_msg_port_descriptor_t;
            for outgoing_port in ports.into_iter() {
                (*port_descriptor_dest).name = outgoing_port.port;
                (*port_descriptor_dest).disposition = MACH_MSG_TYPE_COPY_SEND;
                (*port_descriptor_dest).type_ = MACH_MSG_PORT_DESCRIPTOR;
                port_descriptor_dest = port_descriptor_dest.offset(1);
                mem::forget(outgoing_port);
            }
            let data_dest = port_descriptor_dest as *mut u8;
            ptr::copy_nonoverlapping(data.as_ptr(), data_dest, data.len());
            assert!(mach_sys::mach_msg(message as *mut _,
                                       MACH_SEND_MSG,
                                       (*message).header.msgh_size,
                                       0,
                                       MACH_PORT_NULL,
                                       MACH_MSG_TIMEOUT_NONE,
                                       MACH_PORT_NULL) == MACH_MSG_SUCCESS);
            libc::free(message as *mut _);
        }
    }

    pub fn recv(&self) -> (Vec<u8>, Vec<MachPort>) {
        unsafe {
            let mut buffer = [0; SMALL_MESSAGE_SIZE];
            let mut allocated_buffer = None;
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
                    let actual_size = (*message).header.msgh_size;
                    let mut allocated_buffer = Some(libc::malloc(actual_size as size_t));
                    setup_receive_buffer(slice::from_raw_parts_mut(
                                            allocated_buffer.unwrap() as *mut u8,
                                            actual_size as usize),
                                         self.port);
                    message = &mut buffer[0] as *mut _ as *mut Message;
                    assert!(mach_sys::mach_msg(message as *mut _,
                                               MACH_RCV_MSG,
                                               0,
                                               actual_size,
                                               self.port,
                                               MACH_MSG_TIMEOUT_NONE,
                                               MACH_PORT_NULL) == MACH_MSG_SUCCESS);
                }
                MACH_MSG_SUCCESS => {}
                error => panic!("error in mach_msg when receiving: {}", error),
            }

            let mut ports = Vec::new();
            let mut port_descriptor = message.offset(1) as *mut mach_msg_port_descriptor_t;
            for _ in 0..(*message).body.msgh_descriptor_count {
                ports.push(MachPort::from_name((*port_descriptor).name));
                port_descriptor = port_descriptor.offset(1);
            }

            let payload_ptr = port_descriptor as *mut u8;
            let payload_size = ((*message).header.msgh_size as usize) - (port_descriptor as usize);
            let payload = Vec::from_raw_buf(payload_ptr, payload_size);

            if let Some(allocated_buffer) = allocated_buffer {
                libc::free(allocated_buffer)
            }

            (payload, ports)
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

fn MACH_MSGH_BITS_LOCAL(bits: u32) -> u32 {
    (bits & MACH_MSGH_BITS_LOCAL_MASK) >> 8
}

#[repr(C)]
struct Message {
    header: mach_msg_header_t,
    body: mach_msg_body_t,
}

impl Message {
    fn size_of(data_length: usize, port_length: usize) -> usize {
        mem::size_of::<Message>() + mem::size_of::<mach_msg_port_descriptor_t>() * port_length +
            data_length
    }
}

extern {
    fn bootstrap_register2(bp: mach_port_t, service_name: name_t, sp: mach_port_t, flags: u64)
                           -> kern_return_t;
    fn bootstrap_look_up(bp: mach_port_t, service_name: name_t, sp: *mut mach_port_t)
                         -> kern_return_t;
}

