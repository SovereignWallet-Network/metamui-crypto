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
    /// Decapsulation failed: the ciphertext or the secret key carries a
    /// coefficient `>= q`, or the re-encryption check rejected the
    /// ciphertext. The reference returns 1 with an all-zero ss in every case.
    DecapsulationFailed,
    /// The public key carries a coefficient `>= q` (specification
    /// 2026-07-10 §6.3); the reference's `crypto_kem_enc` returns 1.
    InvalidPublicKey,
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
            Self::DecapsulationFailed => write!(f, "Decapsulation failed"),
            Self::InvalidPublicKey => write!(f, "Public key is not a canonical encoding"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NtruPlusError {}
