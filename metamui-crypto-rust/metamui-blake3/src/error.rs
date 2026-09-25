/// Error types for BLAKE3 operations
//
// Display is hand-written (not `thiserror`) so the type works under
// `no_std`; `thiserror` 1.x emits `impl std::error::Error` and is std-only.
// This mirrors the workspace convention in
// `metamui-crypto-utilities/src/error.rs`.

use core::fmt;

#[cfg(feature = "std")]
use std::error::Error as StdError;

#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};

/// Error types for BLAKE3 operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blake3Error {
    /// Invalid length error
    InvalidLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length received
        actual: usize
    },

    /// Hex decoding error
    HexDecoding(String),

    /// Key generation error
    KeyGeneration,

    /// Invalid key error
    InvalidKey,

    /// Invalid context error
    InvalidContext(String),

    /// IO error (when std feature is enabled)
    #[cfg(feature = "std")]
    Io(String),
}

impl fmt::Display for Blake3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "Invalid length: expected {}, got {}", expected, actual)
            }
            Self::HexDecoding(msg) => write!(f, "Hex decoding error: {}", msg),
            Self::KeyGeneration => write!(f, "Key generation failed"),
            Self::InvalidKey => write!(f, "Invalid key"),
            Self::InvalidContext(msg) => write!(f, "Invalid context: {}", msg),
            #[cfg(feature = "std")]
            Self::Io(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for Blake3Error {}

impl From<hex::FromHexError> for Blake3Error {
    fn from(err: hex::FromHexError) -> Self {
        Blake3Error::HexDecoding(err.to_string())
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Blake3Error {
    fn from(err: std::io::Error) -> Self {
        Blake3Error::Io(err.to_string())
    }
}

/// Result type for BLAKE3 operations
pub type Blake3Result<T> = Result<T, Blake3Error>;