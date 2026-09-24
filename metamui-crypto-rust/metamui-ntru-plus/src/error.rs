//! Error types for NTRU+

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtruPlusError {
    InvalidKeySize,
    InvalidCiphertext,
    InvalidMessage,
    MessageTooLong,
    EncryptionFailed,
    DecryptionFailed,
    KeyGenerationFailed,
    RngError,
    DecapsulationFailed,
}

impl fmt::Display for NtruPlusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeySize => write!(f, "Invalid key size"),
            Self::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            Self::InvalidMessage => write!(f, "Invalid message"),
            Self::MessageTooLong => write!(f, "Message too long"),
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::KeyGenerationFailed => write!(f, "Key generation failed"),
            Self::RngError => write!(f, "Random number generation failed"),
            Self::DecapsulationFailed => write!(f, "Decapsulation verification failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NtruPlusError {}
