// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![doc = include_str!("../README.md")]
//!
//! # Features
//! ## `force-inprocess`
//!
//! Force the `inprocess` backend to be used instead of the OS specific backend.
//! The `inprocess` backend is a dummy back-end, that behaves like the real ones,
//! but doesn't actually work between processes.

#[cfg(any(
    feature = "force-inprocess",
    target_os = "windows",
    target_os = "android",
    target_os = "ios"
))]
#[cfg(all(not(feature = "force-inprocess"), target_os = "linux"))]
#[cfg(feature = "async")]
use futures;

#[cfg(feature = "async")]
pub mod asynch;

#[cfg(all(not(feature = "force-inprocess"), target_os = "windows"))]
extern crate windows;

pub mod ipc;
pub mod platform;
pub mod router;

#[cfg(test)]
mod test;

pub use bincode::{Error, ErrorKind};
#[cfg(all(not(feature = "force-inprocess"), target_os = "macos"))]
pub use platform::set_bootstrap_prefix;
