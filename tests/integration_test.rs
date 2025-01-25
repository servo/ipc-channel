// Copyright 2025 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(not(any(feature = "force-inprocess", target_os = "android", target_os = "ios")))]
use ipc_channel::ipc::IpcOneShotServer;
#[cfg(not(any(feature = "force-inprocess", target_os = "android", target_os = "ios")))]
use std::{env, process};

// These integration tests may be run on their own by issuing:
// cargo test --test '*'

/// Test spawing a process which then acts as a client to a
/// one-shot server in the parent process.
#[cfg(not(any(feature = "force-inprocess", target_os = "android", target_os = "ios")))]
#[test]
fn spawn_one_shot_server_client() {
    let executable_path: String = env!("CARGO_BIN_EXE_spawn_client_test_helper").to_string();

    let (server, token) =
        IpcOneShotServer::<String>::new().expect("Failed to create IPC one-shot server.");

    let mut command = process::Command::new(executable_path);
    let child_process = command.arg(token);

    let mut child = child_process
        .spawn()
        .expect("Failed to start child process");

    let (_rx, msg) = server.accept().expect("accept failed");
    assert_eq!("test message", msg);

    let result = child.wait().expect("wait for child process failed");
    assert!(
        result.success(),
        "child process failed with exit status code {}",
        result.code().expect("exit status code not available")
    );
}
