`ipc-channel` is an inter-process implementation of Rust channels (which were inspired by CSP[^CSP]).

A Rust channel is a unidirectional, FIFO queue of messages which can be used to send messages between threads in a single operating system process.
For an excellent introduction to Rust channels, see [Using Message Passing to Transfer Data Between Threads](https://doc.rust-lang.org/stable/book/ch16-02-message-passing.html) in the Rust reference. 

`ipc-channel` extends Rust channels to support inter-process communication (IPC) in a single operating system instance. The `serde` library is used to serialize and deserialize messages sent over `ipc-channel`.

As much as possible, `ipc-channel` has been designed to be a drop-in replacement for Rust channels. The mapping from the Rust channel APIs to `ipc-channel` APIs is as follows:

* `channel()` → `ipc::channel().unwrap()`
* `Sender<T>` → `ipc::IpcSender<T>` (requires `T: Serialize`)
* `Receiver<T>` → `ipc::IpcReceiver<T>` (requires `T: Deserialize`)

Note that both `IpcSender<T>` and `IpcReceiver<T>` implement `Serialize` and `Deserialize`, so you can send IPC channels over IPC channels freely, just as you can with Rust channels.

The easiest way to make your types implement `Serialize` and `Deserialize` is to use the `serde_macros` crate from crates.io as a plugin and then annotate the types you want to send with `#[derive(Deserialize, Serialize])`. In many cases, that's all you need to do — the compiler generates all the tedious boilerplate code needed to serialize and deserialize instances of your types.

## Semantic differences from Rust channels

* Rust channels can be either unbounded or bounded whereas ipc-channels are always unbounded and `send()` never blocks.
* Rust channels do not consume OS IPC resources whereas ipc-channels consume IPC resources such as sockets, file descriptors, shared memory segments, named pipes, and such like, depending on the OS.
* Rust channels transfer ownership of messages whereas ipc-channels serialize and deserialize messages.
* Rust channels are type safe whereas ipc-channels depend on client and server programs using identical message types (or at least message types with compatible serial forms).

## Bootstrapping channels between processes

`ipc-channel` provides a one-shot server to help establish a channel between two processes. When a one-shot server is created, a server name is generated and returned along with the server.

The client process calls `connect()` passing the server name and this returns the sender end of an ipc-channel from
the client to the server. Note that there is a restriction in `ipc-channel`: `connect()` may be called at most once per one-shot server.

The server process calls `accept()` on the server to accept connect requests from clients. `accept()` blocks until a client has connected to the server and sent a message. It then returns a pair consisting of the receiver end of the ipc-channel from client to server and the first message received from the client.

So, in order to bootstrap an IPC channel between processes, you create an instance of the `IpcOneShotServer` type, pass the resultant server name into the client process (perhaps via an environment variable or command line flag), and connect to the server in the client. See `spawn_one_shot_server_client()` in `integration_test.rs` for an example of how to do this using a command to spawn the client process and `cross_process_embedded_senders_fork()` in `test.rs` for an example of how to do this using Unix `fork()`[^fork] to create the client process.

## Testing

To run the tests, issue:

~~~not_rust
cargo test
~~~

Some tests are platform dependent, so for completeness it would be necessary to run the tests on all platforms:

* iOS
* macOS†
* Unix variants:
  * Android
  * FreeBD
  * Illumos
  * Linux (Ubuntu†)
  * OpenBSD
* WASI
* Windows†

The platforms marked † are covered by CI.

To run the benchmarks, issue:

~~~not_rust
cargo bench
~~~

## Implementation overview

`ipc-channel` is implemented in terms of native IPC primitives: file descriptor passing over Unix sockets on Unix variants, Mach ports on macOS, and named pipes on Windows.

One-shot server names are implemented as a file system path (for Unix variants, with the file system path bound to the socket) or other kinds of generated names on macOS and Windows.

## Major missing features

* Each one-shot server accepts only one client connect request. This is fine if you simply want to use this API to split your application up into a fixed number of mutually untrusting processes, but it's not suitable for implementing a system service. An API for multiple clients may be added later if demand exists for it.

## Related

* [Rust channel](https://doc.rust-lang.org/std/sync/mpsc/index.html): MPSC (multi-producer, single-consumer) channels in the Rust standard library. The implementation
consists of a single consumer wrapper of a port of Crossbeam channel.
* [Crossbeam channel](https://github.com/crossbeam-rs/crossbeam/tree/master/crossbeam-channel): extends Rust channels to be more like their Go counterparts. Crossbeam channels are MPMC (multi-producer, multi-consumer)
* [Channels](https://docs.rs/channels/latest/channels/): provides Sender and Receiver types for communicating with a channel-like API across generic IO streams.

[^CSP]: Tony Hoare conceived Communicating Sequential Processes (CSP) as a concurrent programming language.
Stephen Brookes and A.W. Roscoe developed a sound mathematical basis for CSP as a process algebra.
CSP can now be used to reason about concurrency and to verify concurrency properties using model checkers such as FDR4.
Go channels were also inspired by CSP.

[^fork]: `fork()` has a number of semantic rough edges and is not recommended for general use. See "A fork() in the road" by Andrew Baumann _et al._, Proceedings of the Workshop on Hot Topics in Operating Systems, ACM, 2019. ([PDF](https://www.microsoft.com/en-us/research/uploads/prod/2019/04/fork-hotos19.pdf))
