// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(any(feature = "force-inprocess", not(target_os = "macos")))]
struct Incrementor {
    last_value: u64,
}

#[cfg(any(feature = "force-inprocess", not(target_os = "macos")))]
impl Incrementor {
    fn new() -> Incrementor {
        Incrementor {
            last_value: 0
        }
    }

    fn increment(&mut self) -> u64 {
        self.last_value += 1;
        self.last_value
    }
}

#[cfg(all(not(feature = "force-inprocess"), any(target_os = "linux",
                                                target_os = "freebsd")))]
mod unix;

#[cfg(all(not(feature = "force-inprocess"), target_os = "macos"))]
mod macos;

#[cfg(any(feature = "force-inprocess", target_os = "windows", target_os = "android"))]
mod inprocess;

#[cfg(all(not(feature = "force-inprocess"), any(target_os = "linux",
                                                target_os = "freebsd")))]
mod os {
    pub use super::unix::*;
}

#[cfg(all(not(feature = "force-inprocess"), target_os = "macos"))]
mod os {
    pub use super::macos::*;
}

#[cfg(any(feature = "force-inprocess", target_os = "windows", target_os = "android"))]
mod os {
    pub use super::inprocess::*;
}

pub use self::os::{OsIpcChannel, OsIpcOneShotServer, OsIpcReceiver, OsIpcReceiverSet};
pub use self::os::{OsIpcSelectionResult, OsIpcSender, OsIpcSharedMemory};
pub use self::os::{OsOpaqueIpcChannel, channel};

#[cfg(test)]
mod test;
