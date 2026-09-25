/// Error types for PBKDF2 operations

use core::fmt;

/// PBKDF2 error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PBKDF2Error {
    /// Invalid number of iterations (must be >= 1)
    InvalidIterations,
    /// Invalid key length (must be >= 1)
    InvalidKeyLength,
    /// Invalid parameters
    InvalidParameters,
}

impl fmt::Display for PBKDF2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PBKDF2Error::InvalidIterations => write!(f, "Invalid iterations: must be >= 1"),
            PBKDF2Error::InvalidKeyLength => write!(f, "Invalid key length: must be >= 1"),
            PBKDF2Error::InvalidParameters => write!(f, "Invalid parameters"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PBKDF2Error {}