// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(all(not(feature = "force-inprocess"), any(target_os = "linux",
                                                target_os = "freebsd",
                                                target_os = "netbsd",
                                                target_os = "openbsd")))]
mod unix;
#[cfg(all(not(feature = "force-inprocess"), any(target_os = "linux",
                                                target_os = "freebsd",
                                                target_os = "netbsd",
                                                target_os = "openbsd")))]
mod os {
    pub use super::unix::*;
}

#[cfg(all(not(feature = "force-inprocess"), target_os = "macos"))]
mod macos;
#[cfg(all(not(feature = "force-inprocess"), target_os = "macos"))]
mod os {
    pub use super::macos::*;
}

#[cfg(any(feature = "force-inprocess", target_os = "windows", target_os = "android", target_os = "ios"))]
mod inprocess;
#[cfg(any(feature = "force-inprocess", target_os = "windows", target_os = "android", target_os = "ios"))]
mod os {
    pub use super::inprocess::*;
}

pub use self::os::{OsIpcChannel, OsIpcOneShotServer, OsIpcReceiver, OsIpcReceiverSet};
pub use self::os::{OsIpcSelectionResult, OsIpcSender, OsIpcSharedMemory};
pub use self::os::{OsOpaqueIpcChannel, channel};

#[cfg(test)]
mod test;
