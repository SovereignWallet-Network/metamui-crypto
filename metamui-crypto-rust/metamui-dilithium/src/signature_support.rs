/// Signature crate trait implementations for Dilithium
///
/// This module provides compatibility with the RustCrypto `signature` crate ecosystem,
/// enabling Dilithium to work seamlessly with generic signature APIs.

extern crate alloc;

use crate::{Dilithium2, Dilithium3, Dilithium5};
use signature::{Error as SignatureError, SignatureEncoding, Signer, RandomizedSigner};
use rand_core::CryptoRngCore;

// ============================================================================
// Signature Wrapper Types
// ============================================================================

/// Dilithium2 (ML-DSA-44) signature wrapper
///
/// This wrapper enables Dilithium2 signatures to work with the `signature` crate traits.
#[derive(Clone, Debug)]
pub struct Dilithium2Signature {
    bytes: [u8; Dilithium2::SIGNATURE_SIZE],
}

impl Dilithium2Signature {
    /// Create a signature from raw bytes
    pub fn from_bytes(bytes: &[u8; Dilithium2::SIGNATURE_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Get the signature as a byte slice
    pub fn as_bytes(&self) -> &[u8; Dilithium2::SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl SignatureEncoding for Dilithium2Signature {
    type Repr = [u8; Dilithium2::SIGNATURE_SIZE];
}

impl From<Dilithium2Signature> for [u8; Dilithium2::SIGNATURE_SIZE] {
    fn from(sig: Dilithium2Signature) -> Self {
        sig.bytes
    }
}

impl From<&Dilithium2Signature> for [u8; Dilithium2::SIGNATURE_SIZE] {
    fn from(sig: &Dilithium2Signature) -> Self {
        sig.bytes
    }
}

impl TryFrom<&[u8]> for Dilithium2Signature {
    type Error = SignatureError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != Dilithium2::SIGNATURE_SIZE {
            return Err(SignatureError::new());
        }

        let mut sig_bytes = [0u8; Dilithium2::SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self::from_bytes(&sig_bytes))
    }
}

impl AsRef<[u8]> for Dilithium2Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Dilithium3 (ML-DSA-65) signature wrapper
///
/// This wrapper enables Dilithium3 signatures to work with the `signature` crate traits.
#[derive(Clone, Debug)]
pub struct Dilithium3Signature {
    bytes: [u8; Dilithium3::SIGNATURE_SIZE],
}

impl Dilithium3Signature {
    /// Create a signature from raw bytes
    pub fn from_bytes(bytes: &[u8; Dilithium3::SIGNATURE_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Get the signature as a byte slice
    pub fn as_bytes(&self) -> &[u8; Dilithium3::SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl SignatureEncoding for Dilithium3Signature {
    type Repr = [u8; Dilithium3::SIGNATURE_SIZE];
}

impl From<Dilithium3Signature> for [u8; Dilithium3::SIGNATURE_SIZE] {
    fn from(sig: Dilithium3Signature) -> Self {
        sig.bytes
    }
}

impl From<&Dilithium3Signature> for [u8; Dilithium3::SIGNATURE_SIZE] {
    fn from(sig: &Dilithium3Signature) -> Self {
        sig.bytes
    }
}

impl TryFrom<&[u8]> for Dilithium3Signature {
    type Error = SignatureError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != Dilithium3::SIGNATURE_SIZE {
            return Err(SignatureError::new());
        }

        let mut sig_bytes = [0u8; Dilithium3::SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self::from_bytes(&sig_bytes))
    }
}

impl AsRef<[u8]> for Dilithium3Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Dilithium5 (ML-DSA-87) signature wrapper
///
/// This wrapper enables Dilithium5 signatures to work with the `signature` crate traits.
#[derive(Clone, Debug)]
pub struct Dilithium5Signature {
    bytes: [u8; Dilithium5::SIGNATURE_SIZE],
}

impl Dilithium5Signature {
    /// Create a signature from raw bytes
    pub fn from_bytes(bytes: &[u8; Dilithium5::SIGNATURE_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Get the signature as a byte slice
    pub fn as_bytes(&self) -> &[u8; Dilithium5::SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl SignatureEncoding for Dilithium5Signature {
    type Repr = [u8; Dilithium5::SIGNATURE_SIZE];
}

impl From<Dilithium5Signature> for [u8; Dilithium5::SIGNATURE_SIZE] {
    fn from(sig: Dilithium5Signature) -> Self {
        sig.bytes
    }
}

impl From<&Dilithium5Signature> for [u8; Dilithium5::SIGNATURE_SIZE] {
    fn from(sig: &Dilithium5Signature) -> Self {
        sig.bytes
    }
}

impl TryFrom<&[u8]> for Dilithium5Signature {
    type Error = SignatureError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != Dilithium5::SIGNATURE_SIZE {
            return Err(SignatureError::new());
        }

        let mut sig_bytes = [0u8; Dilithium5::SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(bytes);
        Ok(Self::from_bytes(&sig_bytes))
    }
}

impl AsRef<[u8]> for Dilithium5Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// ============================================================================
// Signing Key Wrappers
// ============================================================================

/// Dilithium2 signing key wrapper for signature crate compatibility
pub struct Dilithium2SigningKey {
    secret_key: [u8; Dilithium2::SECRET_KEY_SIZE],
}

impl Dilithium2SigningKey {
    /// Create a signing key from bytes
    pub fn from_bytes(bytes: &[u8; Dilithium2::SECRET_KEY_SIZE]) -> Self {
        Self { secret_key: *bytes }
    }

    /// Generate a new signing key
    pub fn generate() -> Self {
        let (_, sk) = Dilithium2::generate_keypair();
        Self { secret_key: sk }
    }
}

impl Signer<Dilithium2Signature> for Dilithium2SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Dilithium2Signature, SignatureError> {
        let sig_bytes = Dilithium2::sign(&self.secret_key, msg);
        Ok(Dilithium2Signature::from_bytes(&sig_bytes))
    }
}

impl RandomizedSigner<Dilithium2Signature> for Dilithium2SigningKey {
    fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> Result<Dilithium2Signature, SignatureError> {
        let sig_bytes = Dilithium2::sign_with_rng(&self.secret_key, msg, rng);
        Ok(Dilithium2Signature::from_bytes(&sig_bytes))
    }
}

/// Dilithium3 signing key wrapper for signature crate compatibility
pub struct Dilithium3SigningKey {
    secret_key: [u8; Dilithium3::SECRET_KEY_SIZE],
}

impl Dilithium3SigningKey {
    /// Create a signing key from bytes
    pub fn from_bytes(bytes: &[u8; Dilithium3::SECRET_KEY_SIZE]) -> Self {
        Self { secret_key: *bytes }
    }

    /// Generate a new signing key
    pub fn generate() -> Self {
        let (_, sk) = Dilithium3::generate_keypair();
        Self { secret_key: sk }
    }
}

impl Signer<Dilithium3Signature> for Dilithium3SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Dilithium3Signature, SignatureError> {
        let sig_bytes = Dilithium3::sign(&self.secret_key, msg);
        Ok(Dilithium3Signature::from_bytes(&sig_bytes))
    }
}

impl RandomizedSigner<Dilithium3Signature> for Dilithium3SigningKey {
    fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> Result<Dilithium3Signature, SignatureError> {
        let sig_bytes = Dilithium3::sign_with_rng(&self.secret_key, msg, rng);
        Ok(Dilithium3Signature::from_bytes(&sig_bytes))
    }
}

/// Dilithium5 signing key wrapper for signature crate compatibility
pub struct Dilithium5SigningKey {
    secret_key: [u8; Dilithium5::SECRET_KEY_SIZE],
}

impl Dilithium5SigningKey {
    /// Create a signing key from bytes
    pub fn from_bytes(bytes: &[u8; Dilithium5::SECRET_KEY_SIZE]) -> Self {
        Self { secret_key: *bytes }
    }

    /// Generate a new signing key
    pub fn generate() -> Self {
        let (_, sk) = Dilithium5::generate_keypair();
        Self { secret_key: sk }
    }
}

impl Signer<Dilithium5Signature> for Dilithium5SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Dilithium5Signature, SignatureError> {
        let sig_bytes = Dilithium5::sign(&self.secret_key, msg);
        Ok(Dilithium5Signature::from_bytes(&sig_bytes))
    }
}

impl RandomizedSigner<Dilithium5Signature> for Dilithium5SigningKey {
    fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> Result<Dilithium5Signature, SignatureError> {
        let sig_bytes = Dilithium5::sign_with_rng(&self.secret_key, msg, rng);
        Ok(Dilithium5Signature::from_bytes(&sig_bytes))
    }
}

// ============================================================================
// Verifying Key Wrappers
// ============================================================================

/// Dilithium2 verifying key wrapper
pub struct Dilithium2VerifyingKey {
    public_key: [u8; Dilithium2::PUBLIC_KEY_SIZE],
}

impl Dilithium2VerifyingKey {
    /// Create a verifying key from bytes
    pub fn from_bytes(bytes: &[u8; Dilithium2::PUBLIC_KEY_SIZE]) -> Self {
        Self { public_key: *bytes }
    }

    /// Verify a signature
    pub fn verify(&self, msg: &[u8], signature: &Dilithium2Signature) -> Result<(), SignatureError> {
        if Dilithium2::verify(&self.public_key, msg, signature.as_bytes()) {
            Ok(())
        } else {
            Err(SignatureError::new())
        }
    }
}

/// Dilithium3 verifying key wrapper
pub struct Dilithium3VerifyingKey {
    public_key: [u8; Dilithium3::PUBLIC_KEY_SIZE],
}

impl Dilithium3VerifyingKey {
    /// Create a verifying key from bytes
    pub fn from_bytes(bytes: &[u8; Dilithium3::PUBLIC_KEY_SIZE]) -> Self {
        Self { public_key: *bytes }
    }

    /// Verify a signature
    pub fn verify(&self, msg: &[u8], signature: &Dilithium3Signature) -> Result<(), SignatureError> {
        if Dilithium3::verify(&self.public_key, msg, signature.as_bytes()) {
            Ok(())
        } else {
            Err(SignatureError::new())
        }
    }
}

/// Dilithium5 verifying key wrapper
pub struct Dilithium5VerifyingKey {
    public_key: [u8; Dilithium5::PUBLIC_KEY_SIZE],
}

impl Dilithium5VerifyingKey {
    /// Create a verifying key from bytes
    pub fn from_bytes(bytes: &[u8; Dilithium5::PUBLIC_KEY_SIZE]) -> Self {
        Self { public_key: *bytes }
    }

    /// Verify a signature
    pub fn verify(&self, msg: &[u8], signature: &Dilithium5Signature) -> Result<(), SignatureError> {
        if Dilithium5::verify(&self.public_key, msg, signature.as_bytes()) {
            Ok(())
        } else {
            Err(SignatureError::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_dilithium2_signer_trait() {
        let signing_key = Dilithium2SigningKey::generate();
        let msg = b"Test message for signature crate";

        // Test deterministic signing
        let signature = signing_key.try_sign(msg).unwrap();
        assert_eq!(signature.as_bytes().len(), Dilithium2::SIGNATURE_SIZE);

        println!("✅ Dilithium2 Signer trait test passed");
    }

    #[test]
    fn test_dilithium2_randomized_signer_trait() {
        let signing_key = Dilithium2SigningKey::generate();
        let msg = b"Test message for randomized signing";

        // Test randomized signing
        let signature = signing_key.try_sign_with_rng(&mut OsRng, msg).unwrap();
        assert_eq!(signature.as_bytes().len(), Dilithium2::SIGNATURE_SIZE);

        println!("✅ Dilithium2 RandomizedSigner trait test passed");
    }

    #[test]
    fn test_dilithium3_signature_traits() {
        let signing_key = Dilithium3SigningKey::generate();
        let msg = b"Test Dilithium3 signature traits";

        // Test both signing modes
        let sig1 = signing_key.try_sign(msg).unwrap();
        let sig2 = signing_key.try_sign_with_rng(&mut OsRng, msg).unwrap();

        assert_eq!(sig1.as_bytes().len(), Dilithium3::SIGNATURE_SIZE);
        assert_eq!(sig2.as_bytes().len(), Dilithium3::SIGNATURE_SIZE);

        println!("✅ Dilithium3 signature traits test passed");
    }

    #[test]
    fn test_dilithium5_signature_traits() {
        let signing_key = Dilithium5SigningKey::generate();
        let msg = b"Test Dilithium5 signature traits";

        // Test both signing modes
        let sig1 = signing_key.try_sign(msg).unwrap();
        let sig2 = signing_key.try_sign_with_rng(&mut OsRng, msg).unwrap();

        assert_eq!(sig1.as_bytes().len(), Dilithium5::SIGNATURE_SIZE);
        assert_eq!(sig2.as_bytes().len(), Dilithium5::SIGNATURE_SIZE);

        println!("✅ Dilithium5 signature traits test passed");
    }

    #[test]
    fn test_signature_encoding() {
        use core::convert::TryFrom;

        // Test Dilithium2
        let bytes2 = [0u8; Dilithium2::SIGNATURE_SIZE];
        let sig2 = Dilithium2Signature::try_from(&bytes2[..]).unwrap();
        assert_eq!(sig2.as_ref().len(), Dilithium2::SIGNATURE_SIZE);
        let repr2: [u8; Dilithium2::SIGNATURE_SIZE] = sig2.clone().into();
        assert_eq!(repr2.len(), Dilithium2::SIGNATURE_SIZE);

        // Test Dilithium3
        let bytes3 = [0u8; Dilithium3::SIGNATURE_SIZE];
        let sig3 = Dilithium3Signature::try_from(&bytes3[..]).unwrap();
        assert_eq!(sig3.as_ref().len(), Dilithium3::SIGNATURE_SIZE);
        let repr3: [u8; Dilithium3::SIGNATURE_SIZE] = sig3.clone().into();
        assert_eq!(repr3.len(), Dilithium3::SIGNATURE_SIZE);

        // Test Dilithium5
        let bytes5 = [0u8; Dilithium5::SIGNATURE_SIZE];
        let sig5 = Dilithium5Signature::try_from(&bytes5[..]).unwrap();
        assert_eq!(sig5.as_ref().len(), Dilithium5::SIGNATURE_SIZE);
        let repr5: [u8; Dilithium5::SIGNATURE_SIZE] = sig5.clone().into();
        assert_eq!(repr5.len(), Dilithium5::SIGNATURE_SIZE);

        println!("✅ Signature encoding test passed");
    }
}
