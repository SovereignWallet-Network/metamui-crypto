//! High-level API for HAETAE signature scheme
//!
//! This module provides ergonomic types and methods for working with HAETAE
//! signatures, wrapping the low-level functions with a safer, more idiomatic
//! Rust interface.
//!
//! # Example
//!
//! ```rust,ignore
//! use metamui_haetae::api::{KeyPair, SigningKey, VerifyingKey};
//!
//! // Generate a new keypair
//! let keypair = KeyPair::generate()?;
//!
//! // Sign a message
//! let message = b"Hello, HAETAE!";
//! let signature = keypair.sign(message);
//!
//! // Verify the signature
//! assert!(keypair.verify(message, &signature));
//! ```

use crate::params::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES, CRYPTO_BYTES, SecurityLevel};
use crate::sign::{crypto_sign_signature, crypto_sign_verify, crypto_sign_verify_expanded, ExpandedA1};
#[cfg(feature = "getrandom")]
use crate::sign::crypto_sign_keypair;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Error type for HAETAE operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Signature verification failed
    VerificationFailed,
    /// Invalid signature length
    InvalidSignatureLength,
    /// Key generation failed
    KeyGenerationFailed,
    /// Signing operation failed
    SigningFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::VerificationFailed => write!(f, "Signature verification failed"),
            Error::InvalidSignatureLength => write!(f, "Invalid signature length"),
            Error::KeyGenerationFailed => write!(f, "Key generation failed"),
            Error::SigningFailed => write!(f, "Signing operation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// HAETAE signature
///
/// A cryptographic signature that can be verified against a public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    bytes: [u8; CRYPTO_BYTES],
}

impl Signature {
    /// Create a signature from raw bytes
    ///
    /// Returns `None` if the byte slice is not exactly `CRYPTO_BYTES` long.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CRYPTO_BYTES {
            return None;
        }
        let mut sig_bytes = [0u8; CRYPTO_BYTES];
        sig_bytes.copy_from_slice(bytes);
        Some(Self { bytes: sig_bytes })
    }

    /// Get the signature as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the signature as a byte array
    pub fn to_bytes(&self) -> [u8; CRYPTO_BYTES] {
        self.bytes
    }

    /// Get the length of the signature in bytes
    pub const fn len() -> usize {
        CRYPTO_BYTES
    }
}

/// HAETAE signing key (secret key)
///
/// Used to sign messages. Should be kept secret.
/// Automatically zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey {
    bytes: [u8; CRYPTO_SECRETKEYBYTES],
}

impl SigningKey {
    /// Create a signing key from raw bytes
    pub fn from_bytes(bytes: [u8; CRYPTO_SECRETKEYBYTES]) -> Self {
        Self { bytes }
    }

    /// Get the signing key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the signing key as a byte array
    pub fn to_bytes(&self) -> [u8; CRYPTO_SECRETKEYBYTES] {
        self.bytes
    }

    /// Sign a message
    ///
    /// # Arguments
    /// * `message` - The message to sign
    ///
    /// # Returns
    /// The signature, or an error if signing fails
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        let mut sig_bytes = [0u8; CRYPTO_BYTES];
        let mut siglen = 0;

        let result = crypto_sign_signature(
            &mut sig_bytes,
            &mut siglen,
            message,
            message.len(),
            &self.bytes,
        );

        if result != 0 {
            return Err(Error::SigningFailed);
        }

        Ok(Signature { bytes: sig_bytes })
    }

    /// Get the corresponding verifying key
    pub fn verifying_key(&self) -> VerifyingKey {
        // The public key is embedded in the secret key
        let mut pk_bytes = [0u8; CRYPTO_PUBLICKEYBYTES];
        pk_bytes.copy_from_slice(&self.bytes[..CRYPTO_PUBLICKEYBYTES]);
        VerifyingKey { bytes: pk_bytes }
    }
}

/// HAETAE verifying key (public key)
///
/// Used to verify signatures. Can be freely shared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    bytes: [u8; CRYPTO_PUBLICKEYBYTES],
}

impl VerifyingKey {
    /// Create a verifying key from raw bytes
    pub fn from_bytes(bytes: [u8; CRYPTO_PUBLICKEYBYTES]) -> Self {
        Self { bytes }
    }

    /// Get the verifying key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the verifying key as a byte array
    pub fn to_bytes(&self) -> [u8; CRYPTO_PUBLICKEYBYTES] {
        self.bytes
    }

    /// Verify a signature on a message
    ///
    /// # Arguments
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, `Err(Error::VerificationFailed)` otherwise
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let result = crypto_sign_verify(
            &signature.bytes,
            CRYPTO_BYTES,
            message,
            message.len(),
            &self.bytes,
        );

        if result == 0 {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }

    /// Verify a signature on a message, returning a boolean
    ///
    /// This is a convenience method that returns `true` if verification succeeds
    /// and `false` if it fails.
    pub fn verify_strict(&self, message: &[u8], signature: &Signature) -> bool {
        self.verify(message, signature).is_ok()
    }
}

/// Pre-expanded verifying key for fast repeated verification.
///
/// This caches the expanded A1 matrix (NTT domain) so that verify calls
/// skip K×M SHAKE128 hash expansions. Use when verifying many signatures
/// against the same public key (e.g., batch verification, server-side).
///
/// # Performance
/// - `from_pk()`: same cost as one standard verify (one-time)
/// - `verify()`: ~30-40% faster than standard verify (amortized)
///
/// # Example
/// ```rust,ignore
/// let expanded = ExpandedVerifyingKey::from_pk(&pk_bytes);
/// for (msg, sig) in messages_and_sigs {
///     assert!(expanded.verify(msg, &sig).is_ok());
/// }
/// ```
pub struct ExpandedVerifyingKey {
    expanded_a1: ExpandedA1,
}

impl ExpandedVerifyingKey {
    /// Create from a standard verifying key (one-time hash expansion).
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        Self {
            expanded_a1: ExpandedA1::from_pk(&vk.bytes),
        }
    }

    /// Create from raw public key bytes.
    pub fn from_pk(pk: &[u8; CRYPTO_PUBLICKEYBYTES]) -> Self {
        Self {
            expanded_a1: ExpandedA1::from_pk(pk),
        }
    }

    /// Verify a signature (fast path, skips hash expansion).
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let result = crypto_sign_verify_expanded(
            &signature.bytes,
            CRYPTO_BYTES,
            message,
            message.len(),
            &self.expanded_a1,
        );

        if result == 0 {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }

    /// Verify a signature, returning a boolean.
    pub fn verify_strict(&self, message: &[u8], signature: &Signature) -> bool {
        self.verify(message, signature).is_ok()
    }

    /// Get the original public key bytes.
    pub fn pk_bytes(&self) -> &[u8; CRYPTO_PUBLICKEYBYTES] {
        &self.expanded_a1.pk_bytes
    }
}

/// HAETAE keypair containing both signing and verifying keys
#[derive(Clone)]
pub struct KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl KeyPair {
    /// Generate a new random keypair
    ///
    /// Requires the `getrandom` feature to be enabled.
    ///
    /// # Returns
    /// A new keypair, or an error if key generation fails
    #[cfg(feature = "getrandom")]
    pub fn generate() -> Result<Self, Error> {
        let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];

        let result = crypto_sign_keypair(&mut pk, &mut sk);

        if result != 0 {
            return Err(Error::KeyGenerationFailed);
        }

        Ok(Self {
            signing_key: SigningKey { bytes: sk },
            verifying_key: VerifyingKey { bytes: pk },
        })
    }

    /// Create a keypair from raw bytes
    ///
    /// # Arguments
    /// * `public_key` - The public key bytes
    /// * `secret_key` - The secret key bytes
    pub fn from_bytes(
        public_key: [u8; CRYPTO_PUBLICKEYBYTES],
        secret_key: [u8; CRYPTO_SECRETKEYBYTES],
    ) -> Self {
        Self {
            signing_key: SigningKey { bytes: secret_key },
            verifying_key: VerifyingKey { bytes: public_key },
        }
    }

    /// Get a reference to the signing key
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get a reference to the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Sign a message using this keypair
    ///
    /// # Arguments
    /// * `message` - The message to sign
    ///
    /// # Returns
    /// The signature, or an error if signing fails
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        self.signing_key.sign(message)
    }

    /// Verify a signature on a message using this keypair
    ///
    /// # Arguments
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, `Err(Error::VerificationFailed)` otherwise
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        self.verifying_key.verify(message, signature)
    }

    /// Get the security level of this keypair
    pub fn security_level(&self) -> SecurityLevel {
        #[cfg(feature = "haetae2")]
        return SecurityLevel::Haetae2;

        #[cfg(feature = "haetae3")]
        return SecurityLevel::Haetae3;

        #[cfg(feature = "haetae5")]
        return SecurityLevel::Haetae5;

        #[cfg(not(any(feature = "haetae2", feature = "haetae3", feature = "haetae5")))]
        compile_error!("At least one security level must be enabled");
    }
}

// Zeroize keypair on drop
impl Drop for KeyPair {
    fn drop(&mut self) {
        self.signing_key.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate().expect("Key generation failed");

        // Verify keys are not all zeros
        assert!(keypair.verifying_key().as_bytes().iter().any(|&b| b != 0));
        assert!(keypair.signing_key().as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test message for high-level API";

        // Sign the message
        let signature = keypair.sign(message).expect("Signing failed");

        // Verify the signature
        assert!(keypair.verify(message, &signature).is_ok());
        assert!(keypair.verifying_key().verify_strict(message, &signature));
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_verify_invalid_signature() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test message";

        let mut signature = keypair.sign(message).unwrap();

        // Corrupt the signature
        signature.bytes[0] ^= 1;

        // Verification should fail
        assert!(keypair.verify(message, &signature).is_err());
        assert!(!keypair.verifying_key().verify_strict(message, &signature));
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_verify_wrong_message() {
        let keypair = KeyPair::generate().unwrap();
        let message1 = b"Original message";
        let message2 = b"Different message";

        let signature = keypair.sign(message1).unwrap();

        // Verification with different message should fail
        assert!(keypair.verify(message2, &signature).is_err());
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_signing_key_verifying_key_roundtrip() {
        let keypair = KeyPair::generate().unwrap();

        // Get verifying key from signing key
        let vk_from_sk = keypair.signing_key().verifying_key();

        // Should match the keypair's verifying key
        assert_eq!(vk_from_sk.as_bytes(), keypair.verifying_key().as_bytes());
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_signature_serialization() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test message";

        let signature = keypair.sign(message).unwrap();

        // Convert to bytes and back
        let sig_bytes = signature.to_bytes();
        let signature2 = Signature::from_bytes(&sig_bytes).unwrap();

        // Should verify with reconstructed signature
        assert!(keypair.verify(message, &signature2).is_ok());
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_key_serialization() {
        let keypair = KeyPair::generate().unwrap();

        // Serialize keys
        let pk_bytes = keypair.verifying_key().to_bytes();
        let sk_bytes = keypair.signing_key().to_bytes();

        // Reconstruct keypair
        let keypair2 = KeyPair::from_bytes(pk_bytes, sk_bytes);

        // Sign with original, verify with reconstructed
        let message = b"Test message";
        let signature = keypair.sign(message).unwrap();
        assert!(keypair2.verify(message, &signature).is_ok());
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_expanded_verify() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test expanded verify";

        let signature = keypair.sign(message).unwrap();

        // Create expanded verifying key
        let expanded = ExpandedVerifyingKey::from_verifying_key(keypair.verifying_key());

        // Should verify correctly
        assert!(expanded.verify(message, &signature).is_ok());
        assert!(expanded.verify_strict(message, &signature));
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_expanded_verify_invalid() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Test expanded verify invalid";

        let mut signature = keypair.sign(message).unwrap();
        signature.bytes[0] ^= 1; // corrupt

        let expanded = ExpandedVerifyingKey::from_verifying_key(keypair.verifying_key());
        assert!(expanded.verify(message, &signature).is_err());
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_expanded_verify_multiple_messages() {
        let keypair = KeyPair::generate().unwrap();

        // Expand once, verify many
        let expanded = ExpandedVerifyingKey::from_verifying_key(keypair.verifying_key());

        let messages: &[&[u8]] = &[
            b"Message 1",
            b"Message 2",
            b"A longer test message for HAETAE expanded verify",
            b"",
        ];

        for message in messages {
            let signature = keypair.sign(message).unwrap();
            assert!(
                expanded.verify(message, &signature).is_ok(),
                "Expanded verify failed for message: {:?}",
                message
            );
        }
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn test_expanded_matches_standard_verify() {
        let keypair = KeyPair::generate().unwrap();
        let message = b"Consistency check";
        let signature = keypair.sign(message).unwrap();

        // Both paths should give the same result
        let standard_result = keypair.verifying_key().verify(message, &signature);
        let expanded = ExpandedVerifyingKey::from_verifying_key(keypair.verifying_key());
        let expanded_result = expanded.verify(message, &signature);

        assert_eq!(standard_result.is_ok(), expanded_result.is_ok());
    }
}
