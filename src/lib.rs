// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(all(feature = "unstable", test), feature(specialization))]

extern crate bincode;
#[macro_use]
extern crate crossbeam_channel;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate rand;
extern crate serde;
#[cfg(any(feature = "force-inprocess", target_os = "windows", target_os = "android", target_os = "ios"))]
extern crate uuid;
extern crate tempfile;
#[cfg(all(not(feature = "force-inprocess"), any(target_os = "linux",
                                                target_os = "openbsd",
                                                target_os = "freebsd")))]
extern crate mio;
#[cfg(all(not(feature = "force-inprocess"), any(target_os = "linux",
                                                target_os = "openbsd",
                                                target_os = "freebsd")))]
extern crate fnv;
#[cfg(any(target_os = "linux",
          target_os = "openbsd",
          target_os = "freebsd"))]
extern crate shmemfdrs;

#[cfg(feature = "async")]
extern crate futures;


pub mod ipc;
pub mod platform;
pub mod router;

#[cfg(test)]
mod test;

pub use bincode::{Error, ErrorKind};
