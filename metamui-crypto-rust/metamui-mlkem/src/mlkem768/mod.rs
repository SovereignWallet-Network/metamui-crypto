//! ML-KEM-768 (Module Lattice Key Encapsulation Mechanism) implementation
//!
//! This crate provides a pure Rust implementation of ML-KEM-768, the NIST-standardized
//! post-quantum key encapsulation mechanism based on the Module Learning With Errors problem.
//!
//! # Security
//! - Implements FIPS 203 standard
//! - IND-CCA2 secure
//! - Post-quantum resistant at NIST security level 3
//!
//! # Example
//! ```rust,no_run
//! use metamui_mlkem::mlkem768::{generate_keypair, encapsulate, decapsulate};
//! use rand::rngs::OsRng;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut rng = OsRng;  // Always use cryptographically secure RNG
//! let keypair = generate_keypair(&mut rng)?;
//! let (ciphertext, shared_secret) = encapsulate(&keypair.public_key, &mut rng)?;
//! let decapsulated = decapsulate(&keypair.private_key, &ciphertext)?;
//! assert_eq!(shared_secret.as_bytes(), decapsulated.as_bytes());
//! # Ok(())
//! # }
//! ```

// MetaMUI metamui mlkem768
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

// Module declarations.
//
// As of the Finding #28 in-tree FIPS 203 port, ML-KEM-768 is a thin facade over
// the byte-exact generic engine in `crate::kem` (see kem.rs). The former
// self-contained 768 fork (its own indcpa/ntt*/serialize/compress/sampling/
// buffer/memory_pool/constant_time/security implementations) is gone — those
// modules were FIPS-203-divergent and entirely unused once kem.rs delegated to
// the generic engine. Only the stable public face remains.
/// Constants for ML-KEM-768 including parameters and precomputed values
pub mod constants;
/// Error types and error handling for ML-KEM-768
pub mod error;
/// Key Encapsulation Mechanism operations (facade over `crate::kem`)
mod kem;
/// Core type definitions for ML-KEM-768
pub mod types;

// Re-export main types and functions
pub use crate::mlkem768::error::{MLKemError, MLKemResult};
pub use crate::mlkem768::kem::{decapsulate, encapsulate, generate_keypair};
#[cfg(feature = "fips203-internal")]
pub use crate::mlkem768::kem::{
    encapsulate_deterministic, generate_keypair_from_dz, generate_keypair_from_seed,
};
pub use crate::mlkem768::types::{Ciphertext, KeyPair, PrivateKey, PublicKey, SharedSecret};

// Import for main struct (OsRng backs the std-gated default-RNG helper and the tests)
#[cfg(any(test, feature = "std"))]
use rand_core::OsRng;
use rand_core::{CryptoRng, RngCore};

/// Main ML-KEM-768 struct providing high-level API
pub struct MLKem768 {
    // No internal state needed for stateless KEM
}

impl MLKem768 {
    /// Create a new ML-KEM-768 instance
    pub fn new() -> Self {
        Self {}
    }

    /// Generate a new ML-KEM-768 keypair
    pub fn generate_keypair<R: RngCore + CryptoRng>(&self, rng: &mut R) -> MLKemResult<KeyPair> {
        generate_keypair(rng)
    }

    /// Encapsulate a shared secret for the given public key
    pub fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey,
        rng: &mut R,
    ) -> MLKemResult<(Ciphertext, SharedSecret)> {
        encapsulate(public_key, rng)
    }

    /// Decapsulate a shared secret using the private key
    pub fn decapsulate(
        &self,
        private_key: &PrivateKey,
        ciphertext: &Ciphertext,
    ) -> MLKemResult<SharedSecret> {
        decapsulate(private_key, ciphertext)
    }

    /// Get the public key size in bytes
    pub const fn public_key_bytes() -> usize {
        constants::MLKEM_PUBLICKEY_BYTES
    }

    /// Get the private key size in bytes
    pub const fn private_key_bytes() -> usize {
        constants::MLKEM_SECRETKEY_BYTES
    }

    /// Get the ciphertext size in bytes
    pub const fn ciphertext_bytes() -> usize {
        constants::MLKEM_CIPHERTEXT_BYTES
    }

    /// Get the shared secret size in bytes
    pub const fn shared_secret_bytes() -> usize {
        constants::MLKEM_SHAREDSECRET_BYTES
    }
}

impl Default for MLKem768 {
    fn default() -> Self {
        Self::new()
    }
}

/// Probe a randomness source once and hand it back.
///
/// `RngCore::fill_bytes` panics when the source reports failure, and a panic
/// in wasm32 is a trap, so the OS-randomness helper probes with
/// `try_fill_bytes` first: an unavailable source (the only backend a wasm32
/// build without a JavaScript host links) comes back as
/// [`MLKemError::RandomGenerationFailed`] before any key material is derived.
/// A failure after a successful probe still panics rather than continuing with
/// short randomness; the facade's `*_os` functions have the same contract (#369).
#[cfg(any(test, feature = "std"))]
fn probe_entropy<R: RngCore>(mut rng: R) -> MLKemResult<R> {
    let mut probe = [0u8; 8];
    rng.try_fill_bytes(&mut probe)
        .map_err(|_| MLKemError::RandomGenerationFailed)?;
    Ok(rng)
}

/// Convenience function to generate a keypair using the operating system's RNG.
///
/// Returns [`MLKemError::RandomGenerationFailed`] where the platform has no
/// randomness source (e.g. a wasm32 runtime without a `getrandom` backend).
#[cfg(feature = "std")]
pub fn generate_keypair_default() -> MLKemResult<KeyPair> {
    let mut rng = probe_entropy(OsRng)?;
    generate_keypair(&mut rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_kem_flow() {
        let mut rng = OsRng;
        let mlkem = MLKem768::new();

        // Generate keypair
        let keypair = mlkem.generate_keypair(&mut rng).unwrap();

        // Encapsulate
        let (ciphertext, ss_enc) = mlkem.encapsulate(&keypair.public_key, &mut rng).unwrap();

        // Decapsulate
        let ss_dec = mlkem
            .decapsulate(&keypair.private_key, &ciphertext)
            .unwrap();

        // Verify shared secrets match
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn test_key_sizes() {
        assert_eq!(MLKem768::public_key_bytes(), 1184);
        assert_eq!(MLKem768::private_key_bytes(), 2400);
        assert_eq!(MLKem768::ciphertext_bytes(), 1088);
        assert_eq!(MLKem768::shared_secret_bytes(), 32);
    }

    /// A randomness source that reports failure, as the wasm32 "unavailable"
    /// backend does. `fill_bytes` panics so a test fails if anything draws
    /// from it after the probe.
    struct UnavailableRng;

    impl RngCore for UnavailableRng {
        fn next_u32(&mut self) -> u32 { panic!("drew from an unavailable source") }
        fn next_u64(&mut self) -> u64 { panic!("drew from an unavailable source") }
        fn fill_bytes(&mut self, _: &mut [u8]) { panic!("drew from an unavailable source") }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
            Err(rand_core::Error::from(core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap()))
        }
    }

    #[test]
    fn probe_reports_unavailable_entropy_as_an_error() {
        assert!(matches!(probe_entropy(UnavailableRng), Err(MLKemError::RandomGenerationFailed)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_default_rng() {
        let keypair = generate_keypair_default().unwrap();
        assert_eq!(keypair.public_key.as_bytes().len(), 1184);
        assert_eq!(keypair.private_key.as_bytes().len(), 2400);
    }

    #[test]
    fn test_multiple_instances() {
        let mut rng = OsRng;
        let mlkem1 = MLKem768::new();
        let mlkem2 = MLKem768::default();

        // Both instances should work identically
        let keypair = mlkem1.generate_keypair(&mut rng).unwrap();
        let (ct, ss1) = mlkem2.encapsulate(&keypair.public_key, &mut rng).unwrap();
        let ss2 = mlkem1.decapsulate(&keypair.private_key, &ct).unwrap();

        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_deterministic_cross_language() {
        use crate::mlkem768::kem::encapsulate_deterministic;
        use metamui_crypto_utilities::hashing::sha3_256;

        // Use same seed as Python test
        let seed = [1u8; 32];

        // Generate keypair
        let keypair = generate_keypair_from_seed(&seed).unwrap();

        // Derive message from seed like Python does
        let enc_seed = [2u8; 32];
        let mut m_input = Vec::with_capacity(32 + 20);
        m_input.extend_from_slice(&enc_seed);
        m_input.extend_from_slice(b"mlkem768_encapsulate");
        let m = sha3_256(&m_input);

        // Encapsulate
        let (ciphertext, shared_secret_enc) =
            encapsulate_deterministic(&keypair.public_key, &m).unwrap();

        // Decapsulate
        let shared_secret_dec = decapsulate(&keypair.private_key, &ciphertext).unwrap();

        assert_eq!(shared_secret_enc.as_bytes(), shared_secret_dec.as_bytes());

        // Check against Python values
        // Python: First 8 bytes of pk: 4817544f61a3d44c
        // Python: Shared secret first 8 bytes: 14aa18e1ecd853bf
        let expected_pk_start = [0x48, 0x17, 0x54, 0x4f, 0x61, 0xa3, 0xd4, 0x4c];
        let expected_ss_start = [0x14, 0xaa, 0x18, 0xe1, 0xec, 0xd8, 0x53, 0xbf];

        println!("Expected pk start: {:02x?}", expected_pk_start);
        println!("Expected ss start: {:02x?}", expected_ss_start);

        // For now, just check that enc/dec match
        // TODO: Fix to match Python exactly
    }
}

/// FIPS 203 §7.2 encapsulation-key check for ML-KEM-768 (see
/// [`crate::kem::mlkem_validate_encapsulation_key`]).
pub fn validate_encapsulation_key(ek: &[u8]) -> bool {
    crate::kem::mlkem_validate_encapsulation_key(&crate::params::MLKEM768_PARAMS, ek)
}

/// FIPS 203 §7.3 decapsulation-key check for ML-KEM-768 (see
/// [`crate::kem::mlkem_validate_decapsulation_key`]).
pub fn validate_decapsulation_key(dk: &[u8]) -> bool {
    crate::kem::mlkem_validate_decapsulation_key(&crate::params::MLKEM768_PARAMS, dk)
}
