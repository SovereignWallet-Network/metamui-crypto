//! Shared error types for the MetaMUI Crypto crates
//!
//! One error hierarchy that the algorithm crates return instead of
//! panicking: `CryptoError` at the top, with `KeyError`, `SignatureError`,
//! `CipherError`, `RandomnessError`, `FormatError`, `AlgorithmError` and
//! `ResourceError` beneath it.

use std::fmt;

/// Result type alias for MetaMUI crypto operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Main error type for all cryptographic operations
#[derive(Debug, Clone, PartialEq)]
pub enum CryptoError {
    /// Invalid algorithm parameters
    InvalidParameter {
        parameter: &'static str,
        value: String,
        expected: &'static str,
    },
    
    /// Key-related errors
    KeyError(KeyError),
    
    /// Signature operation errors
    SignatureError(SignatureError),
    
    /// Encryption/Decryption errors
    CipherError(CipherError),
    
    /// Random number generation failure
    RandomnessError(RandomnessError),
    
    /// Data format or length errors
    FormatError(FormatError),
    
    /// Algorithm-specific errors
    AlgorithmError(AlgorithmError),
    
    /// System resource errors
    ResourceError(ResourceError),
}

/// Key generation and management errors
#[derive(Debug, Clone, PartialEq)]
pub enum KeyError {
    /// Invalid key length
    InvalidLength { expected: usize, actual: usize },
    /// Key derivation failure
    DerivationFailed(String),
    /// Invalid key format
    InvalidFormat(String),
    /// Key material is all zeros (weak key)
    WeakKey,
}

/// Digital signature errors
#[derive(Debug, Clone, PartialEq)]
pub enum SignatureError {
    /// Signing operation failed
    SigningFailed(String),
    /// Signature verification failed
    VerificationFailed,
    /// Invalid signature format
    InvalidSignature,
    /// Message too large for algorithm
    MessageTooLarge { max_size: usize, actual_size: usize },
}

/// Symmetric cipher errors
#[derive(Debug, Clone, PartialEq)]
pub enum CipherError {
    /// Invalid block size
    InvalidBlockSize { expected: usize, actual: usize },
    /// Counter overflow in CTR mode
    CounterOverflow,
    /// Invalid nonce/IV length
    InvalidNonce { expected: usize, actual: usize },
    /// Authentication tag mismatch in AEAD
    AuthenticationFailed,
    /// Padding error
    PaddingError,
}

/// Random number generation errors
#[derive(Debug, Clone, PartialEq)]
pub enum RandomnessError {
    /// System RNG unavailable
    SystemRngUnavailable,
    /// Insufficient entropy
    InsufficientEntropy,
    /// RNG not properly seeded
    NotSeeded,
}

/// Data format and parsing errors
#[derive(Debug, Clone, PartialEq)]
pub enum FormatError {
    /// Invalid data length
    InvalidLength { expected: usize, actual: usize },
    /// Array conversion failed
    ArrayConversionFailed { from: usize, to: usize },
    /// Invalid encoding (hex, base64, etc.)
    InvalidEncoding(String),
    /// Buffer too small
    BufferTooSmall { required: usize, available: usize },
}

/// Algorithm-specific errors
#[derive(Debug, Clone, PartialEq)]
pub enum AlgorithmError {
    /// ML-KEM/Kyber errors
    MLKem(MLKemError),
    /// Dilithium errors
    Dilithium(DilithiumError),
    /// Falcon errors
    Falcon(FalconError),
    /// ChaCha20-Poly1305 errors
    ChaCha20Poly1305(ChaCha20Poly1305Error),
}

/// ML-KEM specific errors
#[derive(Debug, Clone, PartialEq)]
pub enum MLKemError {
    /// Invalid compression parameter
    InvalidCompressionParameter(u8),
    /// Invalid eta value for sampling
    InvalidEta(u8),
    /// Decapsulation failed
    DecapsulationFailed,
    /// Invalid ciphertext
    InvalidCiphertext,
}

/// Dilithium specific errors
#[derive(Debug, Clone, PartialEq)]
pub enum DilithiumError {
    /// Rejection sampling exceeded max iterations
    RejectionSamplingFailed { iterations: u32 },
    /// Invalid security level
    InvalidSecurityLevel(u8),
    /// Hint generation failed
    HintGenerationFailed,
}

/// Falcon specific errors
#[derive(Debug, Clone, PartialEq)]
pub enum FalconError {
    /// NTRU equation solving failed
    NTRUSolvingFailed,
    /// Sampling from Gaussian failed
    GaussianSamplingFailed,
    /// Key generation failed after max attempts
    KeyGenerationFailed { attempts: u32 },
}

/// ChaCha20-Poly1305 specific errors
#[derive(Debug, Clone, PartialEq)]
pub enum ChaCha20Poly1305Error {
    /// Nonce reuse detected
    NonceReuse,
    /// Invalid tag length
    InvalidTagLength,
    /// Stream limit exceeded
    StreamLimitExceeded,
}

/// System resource errors
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceError {
    /// Memory allocation failed
    AllocationFailed { requested: usize },
    /// Mutex/lock poisoned
    LockPoisoned,
    /// Operation timeout
    Timeout { operation: &'static str, duration_ms: u64 },
}

// Error display implementations
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter { parameter, value, expected } => {
                write!(f, "Invalid parameter '{}': got '{}', expected {}", parameter, value, expected)
            }
            Self::KeyError(e) => write!(f, "Key error: {}", e),
            Self::SignatureError(e) => write!(f, "Signature error: {}", e),
            Self::CipherError(e) => write!(f, "Cipher error: {}", e),
            Self::RandomnessError(e) => write!(f, "Randomness error: {}", e),
            Self::FormatError(e) => write!(f, "Format error: {}", e),
            Self::AlgorithmError(e) => write!(f, "Algorithm error: {}", e),
            Self::ResourceError(e) => write!(f, "Resource error: {}", e),
        }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "Invalid key length: expected {} bytes, got {}", expected, actual)
            }
            Self::DerivationFailed(msg) => write!(f, "Key derivation failed: {}", msg),
            Self::InvalidFormat(msg) => write!(f, "Invalid key format: {}", msg),
            Self::WeakKey => write!(f, "Weak key detected (all zeros or trivial pattern)"),
        }
    }
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            Self::VerificationFailed => write!(f, "Signature verification failed"),
            Self::InvalidSignature => write!(f, "Invalid signature format"),
            Self::MessageTooLarge { max_size, actual_size } => {
                write!(f, "Message too large: max {} bytes, got {}", max_size, actual_size)
            }
        }
    }
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlockSize { expected, actual } => {
                write!(f, "Invalid block size: expected {} bytes, got {}", expected, actual)
            }
            Self::CounterOverflow => write!(f, "Counter overflow - maximum number of blocks exceeded"),
            Self::InvalidNonce { expected, actual } => {
                write!(f, "Invalid nonce length: expected {} bytes, got {}", expected, actual)
            }
            Self::AuthenticationFailed => write!(f, "Authentication tag verification failed"),
            Self::PaddingError => write!(f, "Invalid padding"),
        }
    }
}

impl fmt::Display for RandomnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SystemRngUnavailable => write!(f, "System random number generator unavailable"),
            Self::InsufficientEntropy => write!(f, "Insufficient entropy available"),
            Self::NotSeeded => write!(f, "RNG not properly seeded"),
        }
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "Invalid data length: expected {} bytes, got {}", expected, actual)
            }
            Self::ArrayConversionFailed { from, to } => {
                write!(f, "Failed to convert array from {} to {} bytes", from, to)
            }
            Self::InvalidEncoding(msg) => write!(f, "Invalid encoding: {}", msg),
            Self::BufferTooSmall { required, available } => {
                write!(f, "Buffer too small: required {} bytes, only {} available", required, available)
            }
        }
    }
}

impl fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MLKem(e) => write!(f, "ML-KEM error: {}", e),
            Self::Dilithium(e) => write!(f, "Dilithium error: {}", e),
            Self::Falcon(e) => write!(f, "Falcon error: {}", e),
            Self::ChaCha20Poly1305(e) => write!(f, "ChaCha20-Poly1305 error: {}", e),
        }
    }
}

impl fmt::Display for MLKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCompressionParameter(d) => {
                write!(f, "Invalid compression parameter {}, must be 4, 10, or 11", d)
            }
            Self::InvalidEta(eta) => {
                write!(f, "Invalid eta parameter {}, must be 2 or 3", eta)
            }
            Self::DecapsulationFailed => write!(f, "Decapsulation failed - invalid ciphertext"),
            Self::InvalidCiphertext => write!(f, "Invalid ciphertext format"),
        }
    }
}

impl fmt::Display for DilithiumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RejectionSamplingFailed { iterations } => {
                write!(f, "Rejection sampling failed after {} iterations", iterations)
            }
            Self::InvalidSecurityLevel(level) => {
                write!(f, "Invalid security level {}, must be 2, 3, or 5", level)
            }
            Self::HintGenerationFailed => write!(f, "Hint generation failed"),
        }
    }
}

impl fmt::Display for FalconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NTRUSolvingFailed => write!(f, "NTRU equation solving failed"),
            Self::GaussianSamplingFailed => write!(f, "Gaussian sampling failed"),
            Self::KeyGenerationFailed { attempts } => {
                write!(f, "Key generation failed after {} attempts", attempts)
            }
        }
    }
}

impl fmt::Display for ChaCha20Poly1305Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonceReuse => write!(f, "Nonce reuse detected - security compromised"),
            Self::InvalidTagLength => write!(f, "Invalid authentication tag length"),
            Self::StreamLimitExceeded => write!(f, "Stream limit exceeded (2^38-64 bytes)"),
        }
    }
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllocationFailed { requested } => {
                write!(f, "Memory allocation failed for {} bytes", requested)
            }
            Self::LockPoisoned => write!(f, "Lock poisoned by panicking thread"),
            Self::Timeout { operation, duration_ms } => {
                write!(f, "Operation '{}' timed out after {}ms", operation, duration_ms)
            }
        }
    }
}

// Implement std::error::Error for all types
impl std::error::Error for CryptoError {}
impl std::error::Error for KeyError {}
impl std::error::Error for SignatureError {}
impl std::error::Error for CipherError {}
impl std::error::Error for RandomnessError {}
impl std::error::Error for FormatError {}
impl std::error::Error for AlgorithmError {}
impl std::error::Error for MLKemError {}
impl std::error::Error for DilithiumError {}
impl std::error::Error for FalconError {}
impl std::error::Error for ChaCha20Poly1305Error {}
impl std::error::Error for ResourceError {}

/// Conversion utilities for common patterns
impl CryptoError {
    /// Create error for array conversion failures
    pub fn array_conversion(from: usize, to: usize) -> Self {
        Self::FormatError(FormatError::ArrayConversionFailed { from, to })
    }
    
    /// Create error for invalid parameters
    pub fn invalid_param(parameter: &'static str, value: impl ToString, expected: &'static str) -> Self {
        Self::InvalidParameter {
            parameter,
            value: value.to_string(),
            expected,
        }
    }
}

// Conversion from TryFromSliceError
impl From<std::array::TryFromSliceError> for CryptoError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::FormatError(FormatError::ArrayConversionFailed { from: 0, to: 0 })
    }
}

// Conversion from poison errors
impl<T> From<std::sync::PoisonError<T>> for CryptoError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Self::ResourceError(ResourceError::LockPoisoned)
    }
}