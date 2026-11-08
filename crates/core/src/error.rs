use std::path::PathBuf;
use thiserror::Error;

/// Errors produced by the blocking engine.
#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("could not read a valid blocklist file: {0}")]
    BlocklistRead(String),

    #[error("permission denied: this operation requires administrator privileges")]
    PermissionDenied,

    #[error("settings file {0} is corrupt; it has been moved aside and cannot be trusted")]
    CorruptSettings(PathBuf),

    #[error("{0} is writable by non-administrators — refusing to store sensitive state there")]
    InsecureDirectory(PathBuf),

    #[error("external command failed ({command}): {message}")]
    Command { command: String, message: String },

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error(
        "application executable could not be found: {0} \
         (use a full path such as app:C:\\Program Files\\Mozilla Firefox\\firefox.exe)"
    )]
    AppNotFound(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }

    /// True when the error looks like a permissions / elevation problem.
    pub fn is_permission_denied(&self) -> bool {
        match self {
            Error::PermissionDenied => true,
            Error::Io(e) => e.kind() == std::io::ErrorKind::PermissionDenied,
            Error::Command { message, .. } => {
                let m = message.to_lowercase();
                m.contains("permission denied")
                    || m.contains("access is denied")
                    || m.contains("operation not permitted")
                    || m.contains("must be run")
                    || m.contains("requires elevation")
            }
            _ => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
