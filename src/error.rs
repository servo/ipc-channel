use std::fmt::Display;
use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
/// An error that occurs for serialization or deserialization
pub struct SerializationError(#[from] pub(crate) bincode::Error);

impl Display for SerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Serialization error")
    }
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("Error in decoding or encoding: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("Error in IO: {0}")]
    Io(#[from] io::Error),
    #[error("Ipc Disconnected")]
    Disconnected,
}

#[derive(Debug, Error)]
pub enum TryRecvError {
    #[error("IPC error")]
    IpcError(#[from] IpcError),
    #[error("Channel empty")]
    Empty,
}
