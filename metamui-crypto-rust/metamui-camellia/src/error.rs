/// Error types for Camellia operations

use core::fmt;

/// Errors that can occur during Camellia operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CamelliaError {
    /// Invalid key size (must be 16, 24, or 32 bytes)
    InvalidKeySize { size: usize },
    /// Invalid block size (must be 16 bytes)
    InvalidBlockSize { size: usize },
    /// Invalid IV/nonce size
    InvalidIvSize { size: usize },
    /// Invalid padding
    InvalidPadding,
    /// Authentication failed (for authenticated modes)
    AuthenticationFailed,
    /// Operation is intentionally unavailable until the implementation is complete
    NotImplemented(&'static str),
    /// Buffer too small
    BufferTooSmall { required: usize, provided: usize },
    /// The system random number generator failed
    RngFailure,
}

impl fmt::Display for CamelliaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeySize { size } => {
                write!(f, "Invalid key size: {}. Must be 16, 24, or 32 bytes", size)
            }
            Self::InvalidBlockSize { size } => {
                write!(f, "Invalid block size: {}. Must be 16 bytes", size)
            }
            Self::InvalidIvSize { size } => {
                write!(f, "Invalid IV size: {}. Must be 16 bytes", size)
            }
            Self::InvalidPadding => write!(f, "Invalid PKCS#7 padding"),
            Self::AuthenticationFailed => write!(f, "Authentication tag verification failed"),
            Self::NotImplemented(message) => write!(f, "{message}"),
            Self::BufferTooSmall { required, provided } => {
                write!(f, "Buffer too small: required {}, provided {}", required, provided)
            }
            Self::RngFailure => write!(f, "The system random number generator failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CamelliaError {}
