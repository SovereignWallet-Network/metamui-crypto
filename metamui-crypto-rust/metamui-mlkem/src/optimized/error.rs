//! Error types for ML-KEM-768 optimized implementation

use thiserror::Error;

/// Main error type for ML-KEM operations
#[derive(Debug, Error)]
pub enum MLKemError {
    /// Invalid input parameters provided
    #[error("Invalid input")]
    InvalidInput,
    
    /// Ciphertext validation failed
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    
    /// Public key validation failed
    #[error("Invalid public key")]
    InvalidPublicKey,
    
    /// Secret key validation failed
    #[error("Invalid secret key")]
    InvalidSecretKey,
    
    /// Serialization operation failed
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    /// Deserialization operation failed
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    
    /// Backend-specific error occurred
    #[error("Backend error: {0}")]
    BackendError(String),
    
    /// GPU operation failed
    #[error("GPU error: {0}")]
    GpuError(String),
    
    /// Parallel processing error
    #[error("Parallel processing error: {0}")]
    ParallelError(String),
    
    /// Memory allocation failed
    #[error("Memory allocation error")]
    MemoryError,
    
    /// Requested feature is not supported
    #[error("Feature not supported")]
    NotSupported,
}

/// Result type for ML-KEM operations
pub type Result<T> = std::result::Result<T, MLKemError>;

// Convert from metamui_mlkem mlkem768 error types
impl From<metamui_mlkem::mlkem768::error::MLKemError> for MLKemError {
    fn from(err: metamui_mlkem::mlkem768::error::MLKemError) -> Self {
        match err {
            metamui_mlkem::mlkem768::error::MLKemError::InvalidInput(_) => MLKemError::InvalidInput,
            metamui_mlkem::mlkem768::error::MLKemError::InvalidCiphertext => MLKemError::InvalidCiphertext,
            metamui_mlkem::mlkem768::error::MLKemError::InvalidPublicKey => MLKemError::InvalidPublicKey,
            metamui_mlkem::mlkem768::error::MLKemError::InvalidPrivateKey => MLKemError::InvalidSecretKey,
            _ => MLKemError::BackendError(err.to_string()),
        }
    }
}

#[cfg(feature = "parallel")]
impl From<super::batch::parallel::ParallelError> for MLKemError {
    fn from(err: super::batch::parallel::ParallelError) -> Self {
        MLKemError::ParallelError(err.to_string())
    }
}