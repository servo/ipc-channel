// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(any(feature = "force-inprocess", target_os = "windows", target_os = "android", target_os = "ios"),
			feature(mpsc_select))]
#![cfg_attr(all(feature = "unstable", test), feature(specialization))]

#[macro_use]
extern crate lazy_static;

extern crate bincode;
extern crate libc;
extern crate rand;
extern crate serde;
#[cfg(any(feature = "force-inprocess", target_os = "windows", target_os = "android", target_os = "ios"))]
extern crate uuid;
#[cfg(all(not(feature = "force-inprocess"), any(target_os = "linux",
                                                target_os = "freebsd",
                                                target_os = "netbsd",
                                                target_os = "openbsd")))]
extern crate mio;
#[cfg(all(not(feature = "force-inprocess"), any(target_os = "linux",
                                                target_os = "freebsd",
                                                target_os = "netbsd",
                                                target_os = "openbsd")))]
extern crate fnv;
#[cfg(all(feature = "memfd", not(feature = "force-inprocess"),
          target_os="linux"))]
#[macro_use]
extern crate syscall;

#[cfg(feature = "async")]
extern crate futures;


pub mod ipc;
pub mod platform;
pub mod router;

#[cfg(test)]
mod test;

pub use bincode::{Error, ErrorKind};
