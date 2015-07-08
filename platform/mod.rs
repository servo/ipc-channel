// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(target_os="linux")]
pub use platform::linux::channel;
#[cfg(target_os="linux")]
pub use platform::linux::UnixReceiver as OsIpcReceiver;
#[cfg(target_os="linux")]
pub use platform::linux::UnixSender as OsIpcSender;
#[cfg(target_os="linux")]
pub use platform::linux::UnixServer as OsIpcServer;

#[cfg(target_os="macos")]
pub use platform::macos::channel;
#[cfg(target_os="macos")]
pub use platform::macos::MachReceiver as OsIpcReceiver;
#[cfg(target_os="macos")]
pub use platform::macos::MachSender as OsIpcSender;
#[cfg(target_os="macos")]
pub use platform::macos::MachOneShotServer as OsIpcOneShotServer;

#[cfg(target_os="linux")]
mod linux;
#[cfg(target_os="macos")]
mod macos;

#[cfg(test)]
mod test;

