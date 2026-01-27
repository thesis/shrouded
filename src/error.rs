//! Error types for the shroud crate.

use thiserror::Error;

/// Errors that can occur during protected memory operations.
#[derive(Debug, Error)]
pub enum ShroudError {
    /// Failed to allocate protected memory region.
    #[error("failed to allocate protected memory: {0}")]
    AllocationFailed(String),

    /// Failed to lock memory (mlock/VirtualLock).
    #[error("failed to lock memory: {0}")]
    LockFailed(String),

    /// Failed to unlock memory (munlock/VirtualUnlock).
    #[error("failed to unlock memory: {0}")]
    UnlockFailed(String),

    /// Failed to change memory protection.
    #[error("failed to change memory protection: {0}")]
    ProtectFailed(String),

    /// Failed to deallocate memory.
    #[error("failed to deallocate memory: {0}")]
    DeallocationFailed(String),

    /// Memory region is currently locked (PROT_NONE) and cannot be accessed.
    #[error("memory region is locked and cannot be accessed")]
    RegionLocked,

    /// Invalid UTF-8 sequence in string data.
    #[error("invalid UTF-8 sequence: {0}")]
    InvalidUtf8(#[from] core::str::Utf8Error),

    /// Capacity overflow.
    #[error("capacity overflow: requested {requested} bytes, maximum is {maximum}")]
    CapacityOverflow { requested: usize, maximum: usize },

    /// Operation not supported on this platform.
    #[error("operation not supported: {0}")]
    Unsupported(String),

    /// System error with errno/GetLastError code.
    #[error("system error (code {code}): {message}")]
    SystemError { code: i32, message: String },
}

/// Result type alias for shroud operations.
pub type Result<T> = core::result::Result<T, ShroudError>;
