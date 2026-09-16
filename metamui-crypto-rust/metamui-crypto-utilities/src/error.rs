/// Error types for cryptographic utilities

use core::fmt;

#[cfg(feature = "std")]
use std::error::Error as StdError;

#[cfg(feature = "std")]
use std::string::String;

/// Result type for cryptographic operations
pub type Result<T> = core::result::Result<T, CryptoUtilError>;

/// Errors that can occur in cryptographic utilities
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoUtilError {
    /// Invalid key length
    InvalidKeyLength {
        /// Expected key length
        expected: usize,
        /// Actual key length provided
        actual: usize,
    },
    
    /// Invalid input length
    InvalidInputLength {
        /// Expected input length
        expected: usize,
        /// Actual input length provided
        actual: usize,
    },
    
    /// Invalid parameter
    InvalidParameter(InvalidParameterType),
    
    /// Random number generation failed
    RandomGenerationFailed,
    
    /// Entropy validation failed
    EntropyValidationFailed,
    
    /// HMAC verification failed
    MacVerificationFailed,
    
    /// Invalid encoding
    InvalidEncoding(EncodingError),
    
    /// Invalid mnemonic
    InvalidMnemonic(MnemonicError),
    
    /// Key derivation failed
    KeyDerivationFailed,
    
    /// Padding error
    PaddingError(PaddingErrorType),
    
    /// Operation not supported
    NotSupported(&'static str),
    
    /// Hash operation failed
    HashError(String),
}

/// Types of invalid parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidParameterType {
    /// Salt is too short
    SaltTooShort {
        /// Minimum required salt length
        minimum: usize,
        /// Actual salt length provided
        actual: usize
    },
    /// Iteration count is too low
    IterationCountTooLow {
        /// Minimum required iteration count
        minimum: u32,
        /// Actual iteration count provided
        actual: u32
    },
    /// Output length is invalid
    InvalidOutputLength,
    /// Nonce length is invalid
    InvalidNonceLength,
}

/// Encoding-related errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodingError {
    /// Invalid hex string
    InvalidHex,
    /// Invalid base64 string
    InvalidBase64,
    /// Invalid base58 string
    InvalidBase58,
    /// Invalid UTF-8
    InvalidUtf8,
    /// Data too large to encode safely
    DataTooLarge,
}

/// Mnemonic-related errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MnemonicError {
    /// Invalid word count
    InvalidWordCount(usize),
    /// Invalid word in mnemonic
    InvalidWord(usize),
    /// Invalid checksum
    InvalidChecksum,
    /// Invalid entropy length
    InvalidEntropyLength,
}

/// Padding-related errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingErrorType {
    /// Invalid padding
    InvalidPadding,
    /// Block size mismatch
    InvalidBlockSize,
    /// Message too long for padding scheme
    MessageTooLong,
}

impl fmt::Display for CryptoUtilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => {
                write!(f, "Invalid key length: expected {}, got {}", expected, actual)
            }
            Self::InvalidInputLength { expected, actual } => {
                write!(f, "Invalid input length: expected {}, got {}", expected, actual)
            }
            Self::InvalidParameter(param) => write!(f, "Invalid parameter: {:?}", param),
            Self::RandomGenerationFailed => write!(f, "Random number generation failed"),
            Self::EntropyValidationFailed => write!(f, "Entropy validation failed"),
            Self::MacVerificationFailed => write!(f, "MAC verification failed"),
            Self::InvalidEncoding(enc) => write!(f, "Invalid encoding: {:?}", enc),
            Self::InvalidMnemonic(mnem) => write!(f, "Invalid mnemonic: {:?}", mnem),
            Self::KeyDerivationFailed => write!(f, "Key derivation failed"),
            Self::PaddingError(pad) => write!(f, "Padding error: {:?}", pad),
            Self::NotSupported(feature) => write!(f, "Feature not supported: {}", feature),
            Self::HashError(msg) => write!(f, "Hash operation failed: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for CryptoUtilError {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_display() {
        let err = CryptoUtilError::InvalidKeyLength { expected: 32, actual: 16 };
        assert_eq!(err.to_string(), "Invalid key length: expected 32, got 16");
    }
}