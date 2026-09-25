//! Error types for Ed25519 operations
//! 
//! Copyright (c) 2025 Sovereign Wallet Co., Ltd.
//! Licensed under the Apache License, Version 2.0

use thiserror::Error;

/// Ed25519 error types
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Ed25519Error {
    #[error("Operation not implemented; refusing placeholder cryptographic output")]
    NotImplemented,

    #[error("Invalid point: {0}")]
    InvalidPoint(String),
    
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    
    #[error("Invalid scalar: {0}")]
    InvalidScalar(String),
    
    #[error("Invalid input length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    
    #[error("Verification failed")]
    VerificationFailed,
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Result type for Ed25519 operations
pub type Result<T> = core::result::Result<T, Ed25519Error>;

impl From<Ed25519Error> for &'static str {
    fn from(error: Ed25519Error) -> &'static str {
        match error {
            Ed25519Error::NotImplemented => "Operation not implemented",
            Ed25519Error::InvalidPoint(_) => "Invalid point",
            Ed25519Error::InvalidSignature(_) => "Invalid signature",
            Ed25519Error::InvalidPublicKey(_) => "Invalid public key",
            Ed25519Error::InvalidPrivateKey(_) => "Invalid private key",
            Ed25519Error::KeyGeneration(_) => "Key generation failed",
            Ed25519Error::InvalidScalar(_) => "Invalid scalar",
            Ed25519Error::InvalidLength { .. } => "Invalid length",
            Ed25519Error::VerificationFailed => "Verification failed",
            Ed25519Error::InternalError(_) => "Internal error",
        }
    }
}
