// AES-CTR-DRBG Error Types

use core::fmt;

/// Errors for AES-256-CTR-DRBG operations.
#[derive(Debug, Clone, PartialEq)]
pub enum AesCtrDrbgError {
    /// Entropy input has wrong length.
    EntropyError(usize),
    /// Reseed counter exceeded maximum interval.
    ReseedRequired,
    /// Invalid request (e.g., too many bytes requested).
    InvalidRequest(&'static str),
    /// DRBG has not been instantiated.
    NotInstantiated,
}

impl fmt::Display for AesCtrDrbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntropyError(len) => write!(f, "entropy must be exactly 48 bytes, got {}", len),
            Self::ReseedRequired => write!(f, "reseed required: counter exceeded interval"),
            Self::InvalidRequest(msg) => write!(f, "invalid request: {}", msg),
            Self::NotInstantiated => write!(f, "DRBG not instantiated"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AesCtrDrbgError {}

/// Result type for AES-CTR-DRBG operations.
pub type Result<T> = core::result::Result<T, AesCtrDrbgError>;
