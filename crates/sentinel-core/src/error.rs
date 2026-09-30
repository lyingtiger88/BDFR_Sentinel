use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("file exceeds configured maximum size: {actual} > {max} bytes")]
    FileTooLarge { actual: u64, max: u64 },

    #[error("scan engine '{engine}' failed: {message}")]
    Engine { engine: String, message: String },
}
