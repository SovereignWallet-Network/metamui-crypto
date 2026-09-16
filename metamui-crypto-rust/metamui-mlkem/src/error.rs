//! Error types for ML-KEM operations

use core::fmt;

/// ML-KEM error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MLKemError {
    /// Invalid parameter or parameter set
    InvalidParameter,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid secret key
    InvalidSecretKey,
    /// Invalid ciphertext
    InvalidCiphertext,
    /// Invalid seed length
    InvalidSeedLength,
    /// Decapsulation failed
    DecapsulationFailed,
    /// Random number generator error
    RngError,
    /// Serialization error
    SerializationError,
    /// Deserialization error
    DeserializationError,
    /// Invalid key size
    InvalidKeySize,
    /// Invalid ciphertext size
    InvalidCiphertextSize,
    /// NTT operation failed
    NttError,
    /// Polynomial operation failed
    PolynomialError,
    /// Compression error
    CompressionError,
    /// Decompression error
    DecompressionError,
}

impl fmt::Display for MLKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MLKemError::InvalidParameter => write!(f, "Invalid ML-KEM parameter or parameter set"),
            MLKemError::InvalidPublicKey => write!(f, "Invalid public key"),
            MLKemError::InvalidSecretKey => write!(f, "Invalid secret key"),
            MLKemError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            MLKemError::InvalidSeedLength => write!(f, "Invalid seed length"),
            MLKemError::DecapsulationFailed => write!(f, "Decapsulation failed"),
            MLKemError::RngError => write!(f, "Random number generator error"),
            MLKemError::SerializationError => write!(f, "Serialization error"),
            MLKemError::DeserializationError => write!(f, "Deserialization error"),
            MLKemError::InvalidKeySize => write!(f, "Invalid key size"),
            MLKemError::InvalidCiphertextSize => write!(f, "Invalid ciphertext size"),
            MLKemError::NttError => write!(f, "NTT operation failed"),
            MLKemError::PolynomialError => write!(f, "Polynomial operation failed"),
            MLKemError::CompressionError => write!(f, "Compression error"),
            MLKemError::DecompressionError => write!(f, "Decompression error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MLKemError {}

/// Result type for ML-KEM operations
pub type Result<T> = core::result::Result<T, MLKemError>;