# ipc-channel

## Overview

`ipc-channel` is an implementation of the Rust channel API (a form of communicating sequential processes, CSP) over the native OS abstractions. Under the hood, this API uses Mach ports on the Mac and file descriptor passing over Unix sockets on Linux. The `serde` library is used to serialize values for transport over the wire.

As much as possible, `ipc-channel` has been designed to be a drop-in replacement for Rust channels. The mapping from the Rust channel APIs to `ipc-channel` APIs is as follows:

* `channel()` → `ipc::channel().unwrap()`
* `Sender<T>` → `ipc::IpcSender<T>` (requires `T: Serialize`)
* `Receiver<T>` → `ipc::IpcReceiver<T>` (requires `T: Deserialize`)

Note that both `IpcSender<T>` and `IpcReceiver<T>` implement `Serialize` and `Deserialize`, so you can send IPC channels over IPC channels freely, just as you can with Rust channels.

In order to bootstrap an IPC connection across processes, you create an instance of the `IpcOneShotServer` type, register a global name, pass that name into the client process (perhaps with an environment variable or command line flag), and connect to the server in the client.

## Major missing features

* Servers only accept one client at a time. This is fine if you simply want to use this API to split your application up into a fixed number of mutually untrusting processes, but it's not suitable for implementing a system service. An API for multiple clients may be added later if demand exists for it.

* No Windows support exists yet. The right way to implement this will be with named pipes and `DuplicateHandle`.
