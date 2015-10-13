// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(any(target_os="linux", target_os="android"))]
pub use platform::linux::channel;
#[cfg(any(target_os="linux", target_os="android"))]
pub use platform::linux::UnixReceiver as OsIpcReceiver;
#[cfg(any(target_os="linux", target_os="android"))]
pub use platform::linux::UnixSender as OsIpcSender;
#[cfg(any(target_os="linux", target_os="android"))]
pub use platform::linux::UnixReceiverSet as OsIpcReceiverSet;
#[cfg(any(target_os="linux", target_os="android"))]
pub use platform::linux::UnixSharedMemory as OsIpcSharedMemory;
#[cfg(any(target_os="linux", target_os="android"))]
pub use platform::linux::UnixChannel as OsIpcChannel;
#[cfg(any(target_os="linux", target_os="android"))]
pub use platform::linux::UnixSelectionResult as OsIpcSelectionResult;
#[cfg(any(target_os="linux", target_os="android"))]
pub use platform::linux::OpaqueUnixChannel as OsOpaqueIpcChannel;
#[cfg(any(target_os="linux", target_os="android"))]
pub use platform::linux::UnixOneShotServer as OsIpcOneShotServer;

#[cfg(target_os="macos")]
pub use platform::macos::channel;
#[cfg(target_os="macos")]
pub use platform::macos::MachReceiver as OsIpcReceiver;
#[cfg(target_os="macos")]
pub use platform::macos::MachSender as OsIpcSender;
#[cfg(target_os="macos")]
pub use platform::macos::MachReceiverSet as OsIpcReceiverSet;
#[cfg(target_os="macos")]
pub use platform::macos::MachSharedMemory as OsIpcSharedMemory;
#[cfg(target_os="macos")]
pub use platform::macos::MachChannel as OsIpcChannel;
#[cfg(target_os="macos")]
pub use platform::macos::MachSelectionResult as OsIpcSelectionResult;
#[cfg(target_os="macos")]
pub use platform::macos::OpaqueMachChannel as OsOpaqueIpcChannel;
#[cfg(target_os="macos")]
pub use platform::macos::MachOneShotServer as OsIpcOneShotServer;

// Windows uses in-process mpsc channels IPC for now
#[cfg(target_os="windows")]
pub use platform::inprocess::channel;
#[cfg(target_os="windows")]
pub use platform::inprocess::MpscReceiver as OsIpcReceiver;
#[cfg(target_os="windows")]
pub use platform::inprocess::MpscSender as OsIpcSender;
#[cfg(target_os="windows")]
pub use platform::inprocess::MpscReceiverSet as OsIpcReceiverSet;
#[cfg(target_os="windows")]
pub use platform::inprocess::MpscSharedMemory as OsIpcSharedMemory;
#[cfg(target_os="windows")]
pub use platform::inprocess::MpscChannel as OsIpcChannel;
#[cfg(target_os="windows")]
pub use platform::inprocess::MpscSelectionResult as OsIpcSelectionResult;
#[cfg(target_os="windows")]
pub use platform::inprocess::OpaqueMpscChannel as OsOpaqueIpcChannel;
#[cfg(target_os="windows")]
pub use platform::inprocess::MpscOneShotServer as OsIpcOneShotServer;

#[cfg(any(target_os="linux", target_os="android"))]
mod linux;
#[cfg(target_os="macos")]
mod macos;
#[cfg(target_os="windows")]
mod inprocess;

#[cfg(test)]
mod test;

