//! Ed25519 signatures (RFC 8032) in portable scalar Rust.
//!
//! Copyright (c) 2025 Sovereign Wallet Co., Ltd.
//! Licensed under the Apache License, Version 2.0
//! Author: Phantom Seokgu Yun <phantom@metamui.id>
//! Repository: https://github.com/SovereignWallet-Network/metamui-crypto
//!
//! Key generation, signing and verification follow RFC 8032 §5.1; signing
//! is deterministic (the nonce is `SHA-512(prefix ‖ M)`) and reproduces the
//! §7.1 vectors byte for byte. Verification is RFC 8032 as written (one
//! policy on every target, decided 2026-09-24): §5.1.3 decoding of `A` and
//! `R`, `S < L`, the cofactored equation `[8][S]B = [8]R + [8][H(R ‖ A ‖ M)]A`,
//! and no small-order screen; `verify` and `verify_strict` are the same
//! policy. The ZIP-215 rule set is a separate crate,
//! `metamui-crypto-ed25519-zip215`.
//!
//! Secret-dependent selection and comparison use `subtle` idioms and
//! secret material is zeroized on drop; no timing measurement has been
//! made. Hashing is the in-tree `metamui-sha2`; no external crypto crate
//! is in the closure. See README.md for the API, the vector files the
//! tests read, and what is and is not claimed.

// Link the wasm32 `getrandom` backend. This crate is a cdylib, so cargo links
// it for wasm32 and that link needs `__getrandom_custom` resolved; the
// definition lives in `metamui-getrandom-unavailable`. An unreferenced
// dependency is never loaded, and therefore never linked, so the import is
// what pulls the rlib in — `as _` because only its linkage is wanted.
#[cfg(target_arch = "wasm32")]
use metamui_getrandom_unavailable as _;


use metamui_security_utils::memory::Zeroize;
use subtle::{Choice, ConstantTimeEq};
use metamui_sha2::sha512::Sha512Hasher;

pub mod error;
pub mod field;
pub mod point;
pub mod scalar;
pub mod constant_time;
pub mod batch;
pub mod montgomery;
pub mod ed25519_montgomery;

pub use error::{Ed25519Error, Result};
pub use field::FieldElement;
pub use point::EdwardsPoint;
pub use scalar::Scalar;
pub use constant_time::ConstantTimeEd25519;
pub use batch::{batch_verify, batch_verify_same_message, BatchVerifier};

/// Ed25519 public key size (32 bytes)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 private key size (64 bytes = 32-byte seed + 32-byte public key)
pub const PRIVATE_KEY_SIZE: usize = 64;

/// Ed25519 signature size (64 bytes = 32-byte R + 32-byte S)
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 seed size (32 bytes)
pub const SEED_SIZE: usize = 32;

/// Ed25519 public key (32 bytes)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

/// Ed25519 private key (64 bytes: 32-byte seed + 32-byte prefix)
#[derive(Clone, Debug)]
pub struct PrivateKey([u8; 64]);

/// Ed25519 signature (64 bytes: 32-byte R + 32-byte S)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Signature([u8; 64]);

/// Ed25519 keypair
#[derive(Clone, Debug)]
pub struct Keypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl PublicKey {
    /// Create a public key from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Ok(PublicKey(*bytes))
    }
    
    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    /// Verify a signature: RFC 8032 §5.1.7 as written (MetaMUI policy of
    /// 2026-09-24).
    ///
    /// A and R are decoded per §5.1.3 (y >= p, x = 0 with the sign bit set,
    /// and a missing square root all fail); S >= L is refused; the signature is
    /// accepted iff the cofactored equation [8][S]B = [8]R + [8][k]A holds,
    /// k = SHA-512(R || A || M) mod L over the received encodings. Small-order
    /// A and R are not screened. A malformed encoding (bad A or R, S >= L) is
    /// reported as `Err`; a well-formed signature that fails the equation is
    /// `Ok(false)`. See [`ConstantTimeEd25519::verify_constant_time`].
    pub fn verify(&self, signature: &Signature, message: &[u8]) -> Result<bool> {
        ConstantTimeEd25519::verify_constant_time(&signature.0, message, &self.0)
    }

    /// Verify a signature under RFC 8032 as written — identical to
    /// [`PublicKey::verify`].
    ///
    /// Both entry points implement the same policy; `verify_strict` is kept
    /// so existing callers compile unchanged. Until 2026-09-24 it meant
    /// "`verify`, then re-check S < L and that R decodes" on top of a core
    /// that accepted non-canonical R/A encodings and rejected small-order
    /// public keys (the libsodium / ed25519-dalek `verify_strict` profile).
    /// The owner-decided policy replaced that profile with RFC 8032 as
    /// written: non-canonical encodings of A and R are now rejected by the
    /// decoder, and small-order A and R are no longer screened.
    /// Oracle: test-vectors/ed25519/ed25519-policy-vectors.json.
    pub fn verify_strict(&self, signature: &Signature, message: &[u8]) -> Result<bool> {
        self.verify(signature, message)
    }
}

impl PrivateKey {
    /// Create a private key from a 32-byte seed
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let (_public_key_bytes, private_key_bytes) = ConstantTimeEd25519::generate_keypair_constant_time(seed)?;
        Ok(PrivateKey(private_key_bytes))
    }
    
    /// Get the associated public key
    pub fn public_key(&self) -> PublicKey {
        // Extract the seed from the private key
        let seed = &self.0[0..32];
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed);
        
        // Regenerate public key
        let (public_key_bytes, _) = ConstantTimeEd25519::generate_keypair_constant_time(&seed_array)
            .expect("Public key generation should not fail");
        
        PublicKey(public_key_bytes)
    }
    
    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        let seed = &self.0[0..32];
        let prefix = &self.0[32..64];
        
        // Compute scalar from seed
        let mut hasher = Sha512Hasher::new();
        hasher.update(seed);
        let hash = hasher.finalize();
        
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash[0..32]);
        
        // Clamp the scalar
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;
        
        // Use from_bytes_mod_order since clamped scalars can be >= L
        let a = Scalar::from_bytes_mod_order(&scalar_bytes);
        
        // Compute r = H(prefix || M)
        let mut r_hasher = Sha512Hasher::new();
        r_hasher.update(prefix);
        r_hasher.update(message);
        let r_hash = r_hasher.finalize();
        
        let r = Scalar::from_bytes_mod_order(&r_hash);
        
        // Compute R = [r]B
        let base_point = EdwardsPoint::generator();
        let r_point = ConstantTimeEd25519::scalar_mult_constant_time(&r, &base_point);
        let r_bytes = r_point.encode();
        
        // Compute h = H(R || A || M)
        let public_key = self.public_key();
        let mut h_hasher = Sha512Hasher::new();
        h_hasher.update(&r_bytes);
        h_hasher.update(public_key.as_bytes());
        h_hasher.update(message);
        let h_hash = h_hasher.finalize();
        
        let h = Scalar::from_bytes_mod_order(&h_hash);
        
        // Compute S = r + h*a
        let s = r + h * a;
        let s_bytes = s.to_bytes();
        
        // Construct signature
        let mut signature_bytes = [0u8; 64];
        signature_bytes[0..32].copy_from_slice(&r_bytes);
        signature_bytes[32..64].copy_from_slice(&s_bytes);
        
        Ok(Signature(signature_bytes))
    }
    
    /// Get the byte representation (returns seed only for security)
    pub fn as_seed(&self) -> &[u8; 32] {
        // Only return the seed part for security
        let seed_ref: &[u8; 32] = self.0[0..32].try_into().expect("Slice length is 32");
        seed_ref
    }
}

impl Signature {
    /// Create a signature from bytes
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Signature(bytes)
    }
    
    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
    
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
    
    /// Validate signature components: R decodes per RFC 8032 §5.1.3 and
    /// S < L.
    pub fn is_valid(&self) -> bool {
        // Check if R component decodes to a valid point
        let r_bytes: [u8; 32] = match self.0[0..32].try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        
        if ConstantTimeEd25519::decode_point_constant_time(&r_bytes).is_err() {
            return false;
        }
        
        // Check if S component is a valid scalar
        let s_bytes: [u8; 32] = match self.0[32..64].try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        
        Scalar::from_bytes(&s_bytes).is_some()
    }
}

impl Keypair {
    /// Generate a new random keypair
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|_| Ed25519Error::KeyGeneration("Failed to generate random seed".to_string()))?;
        
        Self::from_seed(&seed)
    }
    
    /// Create a keypair from a seed
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let private = PrivateKey::from_seed(seed)?;
        let public = private.public_key();
        
        Ok(Keypair { public, private })
    }
    
    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        self.private.sign(message)
    }
    
    /// Verify a signature
    pub fn verify(&self, signature: &Signature, message: &[u8]) -> Result<bool> {
        self.public.verify(signature, message)
    }
}

// Secure memory clearing on drop
impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        // Private key will be cleared by its own Drop implementation
    }
}

// Constant-time equality for sensitive types
impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// High-level convenience functions
/// 
/// Generate a new keypair
pub fn generate_keypair() -> Result<Keypair> {
    Keypair::generate()
}

/// Generate a keypair from a seed
pub fn keypair_from_seed(seed: &[u8; 32]) -> Result<Keypair> {
    Keypair::from_seed(seed)
}

/// Sign a message with a private key
pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Result<Signature> {
    private_key.sign(message)
}

/// Derive public key from private key
pub fn public_key_from_private(private_key: &PrivateKey) -> PublicKey {
    private_key.public_key()
}

/// Verify a signature with a public key (RFC 8032 as written; see
/// [`PublicKey::verify`]).
pub fn verify(signature: &Signature, message: &[u8], public_key: &PublicKey) -> Result<bool> {
    public_key.verify(signature, message)
}

/// Verify a signature under RFC 8032 as written — identical to [`verify`]
/// (see [`PublicKey::verify_strict`] for what this used to mean).
pub fn verify_strict(signature: &Signature, message: &[u8], public_key: &PublicKey) -> Result<bool> {
    public_key.verify_strict(signature, message)
}

// BatchVerifier is exported from the batch module above

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    
    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair().expect("Keypair generation should succeed");
        assert_eq!(keypair.public.as_bytes().len(), 32);
        assert_eq!(keypair.private.as_seed().len(), 32);
    }
    
    #[test]
    fn test_deterministic_keys() {
        let seed = [42u8; 32];
        
        let keypair1 = keypair_from_seed(&seed).expect("Keypair generation should succeed");
        let keypair2 = keypair_from_seed(&seed).expect("Keypair generation should succeed");
        
        assert_eq!(keypair1.public.as_bytes(), keypair2.public.as_bytes());
        assert_eq!(keypair1.private.as_seed(), keypair2.private.as_seed());
    }
    
    #[test]
    fn test_signing_and_verification() {
        let keypair = generate_keypair().expect("Keypair generation should succeed");
        let message = b"test message";
        
        let signature = keypair.sign(message).expect("Signing should succeed");
        assert!(signature.is_valid());
        
        let is_valid = keypair.verify(&signature, message).expect("Verification should succeed");
        assert!(is_valid);
        
        // Test with wrong message
        let wrong_message = b"wrong message";
        let is_valid_wrong = keypair.verify(&signature, wrong_message).expect("Verification should succeed");
        assert!(!is_valid_wrong);
    }
    
    #[test]
    fn test_known_test_vector() {
        // RFC 8032 §7.1 TEST 1 (empty message). Ed25519 signing is
        // deterministic, so the produced signature must reproduce the
        // published vector BYTE-EXACTLY — see
        // test-vectors/ed25519/rfc8032-vectors.json (tc_id=1).
        let seed = hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_public = hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_signature = hex!("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        let message = b"";

        let keypair = keypair_from_seed(&seed).expect("Keypair generation should succeed");
        assert_eq!(keypair.public.as_bytes(), &expected_public);

        let signature = keypair.sign(message).expect("Signing should succeed");

        // Byte-exact match against the RFC 8032 reference signature.
        assert_eq!(
            signature.to_bytes(),
            expected_signature,
            "Signature must be byte-exact to RFC 8032 TEST 1"
        );

        let is_valid = keypair.verify(&signature, message).expect("Verification should succeed");
        assert!(is_valid, "Our signature should verify");
    }
    
    #[test]
    fn test_batch_verification() {
        let mut messages = Vec::new();
        let mut signatures = Vec::new();
        let mut public_keys = Vec::new();
        let mut sig_refs = Vec::new();
        let mut pk_refs = Vec::new();
        
        // Add multiple signatures
        for i in 0..5 {
            let seed = [i as u8; 32];
            let keypair = keypair_from_seed(&seed).expect("Keypair generation should succeed");
            let message = format!("message {}", i).into_bytes();
            let signature = keypair.sign(&message).expect("Signing should succeed");
            
            messages.push(message);
            let sig_bytes: [u8; 64] = signature.to_bytes();
            signatures.push(sig_bytes);
            public_keys.push(keypair.public.to_bytes());
        }
        
        // Create references
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_ref()).collect();
        for sig in &signatures {
            sig_refs.push(sig);
        }
        for pk in &public_keys {
            pk_refs.push(pk);
        }
        
        let results = batch::batch_verify(&msg_refs, &sig_refs, &pk_refs);
        
        // All should be valid
        for result in results {
            assert!(result);
        }
    }
    
    #[test]
    fn test_malformed_signatures() {
        let keypair = generate_keypair().expect("Keypair generation should succeed");
        let message = b"test message";
        
        // Test with malformed signature - set S to be >= L  
        let mut invalid_sig_bytes = [0u8; 64];
        // Set a valid R point (identity)
        invalid_sig_bytes[0] = 0x01; // This encodes to identity point
        // Set S to be L (which is invalid, S must be < L)
        invalid_sig_bytes[32..64].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ]);
        
        let invalid_signature = Signature(invalid_sig_bytes);
        // This signature has S >= L, so it should be invalid
        assert!(!invalid_signature.is_valid());
        
        // Verification should return false for invalid signatures, not error
        match keypair.verify(&invalid_signature, message) {
            Ok(result) => assert!(!result, "Invalid signature should not verify"),
            Err(_) => {
                // It's also acceptable to return an error for malformed signatures
                // This is actually more secure as it fails fast
            }
        }
    }
}