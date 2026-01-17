use std::fmt::Display;
use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
/// An error that occurs for serialization or deserialization
pub struct SerDeError(#[from] pub(crate) postcard::Error);

impl Display for SerDeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Serialization/Deserialization error")
    }
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("Error in decoding or encoding: {0}.")]
    SerializationError(#[from] SerDeError),
    #[error("Error in IO: {0}.")]
    Io(#[from] io::Error),
    /// Disconnected is returned when receiving from a channel if
    /// all senders for the channel have been dropped and no messages
    /// remain to be received.
    #[error("Ipc Disconnected.")]
    Disconnected,
}

#[derive(Debug, Error)]
pub enum TryRecvError {
    #[error("IPC error {0}.")]
    IpcError(#[from] IpcError),
    #[error("Channel empty.")]
    Empty,
}

/// TrySelectError is returned by non-blocking variants of IpcReceiverSet::select.
#[derive(Debug, Error)]
pub enum TrySelectError {
    #[error("Error in IO: {0}.")]
    IoError(#[from] io::Error),
    #[error("No messages were received and no disconnections occurred.")]
    Empty,
}
