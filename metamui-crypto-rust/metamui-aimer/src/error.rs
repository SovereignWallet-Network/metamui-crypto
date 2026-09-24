//! Error types for AIMer

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AimerError {
    /// Invalid key
    InvalidKey,
    
    /// Invalid signature
    InvalidSignature,
    
    /// Invalid key size
    InvalidKeySize,
    
    /// Invalid signature size
    InvalidSignatureSize,
    
    /// Invalid input size
    InvalidInputSize,
    
    /// Invalid party index
    InvalidPartyIndex,
    
    /// MPC protocol failed
    MpcProtocolFailed,
    
    /// Commitment verification failed
    CommitmentMismatch,
    
    /// Signature verification failed
    VerificationFailed,
    
    /// Random number generation failed
    RngError,
    
    /// Random generation failed
    RandomGenerationFailed,
    
    /// Field operation error
    FieldOperationError,
    
    /// Serialization error
    SerializationError,
}

impl fmt::Display for AimerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "Invalid key"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::InvalidKeySize => write!(f, "Invalid key size"),
            Self::InvalidSignatureSize => write!(f, "Invalid signature size"),
            Self::InvalidInputSize => write!(f, "Invalid input size"),
            Self::InvalidPartyIndex => write!(f, "Invalid party index"),
            Self::MpcProtocolFailed => write!(f, "MPC protocol failed"),
            Self::CommitmentMismatch => write!(f, "Commitment verification failed"),
            Self::VerificationFailed => write!(f, "Signature verification failed"),
            Self::RngError => write!(f, "Random number generation failed"),
            Self::RandomGenerationFailed => write!(f, "Random generation failed"),
            Self::FieldOperationError => write!(f, "Field operation error"),
            Self::SerializationError => write!(f, "Serialization error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AimerError {}
