/// Error types for AES-256 operations

use core::fmt;

/// Result type for AES-256 operations
pub type Result<T> = core::result::Result<T, Aes256Error>;

/// AES-256 error types
#[derive(Debug, Clone)]
pub enum Aes256Error {
    /// Invalid key length
    InvalidKeyLength {
        /// Expected key length
        expected: usize,
        /// Actual key length
        actual: usize,
    },
    
    /// Invalid nonce/IV length
    InvalidNonceLength {
        /// Expected nonce length
        expected: usize,
        /// Actual nonce length  
        actual: usize,
    },
    
    /// Invalid block size
    InvalidBlockSize {
        /// Required block size
        block_size: usize,
    },
    
    /// Authentication tag mismatch (GCM mode)
    AuthenticationFailed,
    
    /// Invalid authentication tag length
    InvalidTagLength {
        /// Expected tag length
        expected: usize,
        /// Actual tag length
        actual: usize,
    },
    
    /// Padding error
    PaddingError,
    
    /// Encryption error
    EncryptionError(String),
    
    /// Decryption error  
    DecryptionError(String),
    
    /// Random number generation error
    RandomError(String),
}

impl fmt::Display for Aes256Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Aes256Error::InvalidKeyLength { expected, actual } => {
                write!(f, "Invalid key length: expected {} bytes, got {} bytes", expected, actual)
            }
            Aes256Error::InvalidNonceLength { expected, actual } => {
                write!(f, "Invalid nonce/IV length: expected {} bytes, got {} bytes", expected, actual)
            }
            Aes256Error::InvalidBlockSize { block_size } => {
                write!(f, "Invalid block size: data length must be a multiple of {} bytes", block_size)
            }
            Aes256Error::AuthenticationFailed => {
                write!(f, "Authentication tag verification failed")
            }
            Aes256Error::InvalidTagLength { expected, actual } => {
                write!(f, "Invalid authentication tag length: expected {} bytes, got {} bytes", expected, actual)
            }
            Aes256Error::PaddingError => {
                write!(f, "Invalid PKCS#7 padding")
            }
            Aes256Error::EncryptionError(msg) => {
                write!(f, "Encryption failed: {}", msg)
            }
            Aes256Error::DecryptionError(msg) => {
                write!(f, "Decryption failed: {}", msg)
            }
            Aes256Error::RandomError(msg) => {
                write!(f, "Random number generation failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for Aes256Error {}

impl From<getrandom::Error> for Aes256Error {
    fn from(err: getrandom::Error) -> Self {
        Aes256Error::RandomError(err.to_string())
    }
}