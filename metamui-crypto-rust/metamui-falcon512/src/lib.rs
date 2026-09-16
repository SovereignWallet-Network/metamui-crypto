//! Falcon512 Post-Quantum Signature Implementation

#![allow(dead_code)]
#![allow(unused_variables)]

// Link the wasm32 `getrandom` backend. This crate is a cdylib, so cargo links
// it for wasm32 and that link needs `__getrandom_custom` resolved; the
// definition lives in `metamui-getrandom-unavailable`. An unreferenced
// dependency is never loaded, and therefore never linked, so the import is
// what pulls the rlib in — `as _` because only its linkage is wanted.
#[cfg(target_arch = "wasm32")]
use metamui_getrandom_unavailable as _;


// ============= Core imports =============
// Always need alloc for Vec
extern crate alloc;

use std::vec::Vec;

// ============= WASM-specific setup =============
#[cfg(feature = "wasm-bindgen")]
use wasm_bindgen::prelude::*;


// Core modules
pub mod constants;
/// Wire-size table for every Falcon signature profile (compressed / padded / CT).
pub mod sizes;
/// Deterministic KAT seam (NIST CTR_DRBG schedule replay, SHAKE-seeded keygen/sign) for Tier-B diagnostics.
///
/// Compiled only with the `kat-internal` feature, like every other seeded or
/// known-answer entry point of this crate: applications draw randomness from a
/// caller-supplied `CryptoRng` (or the `*_hedged` helpers) and are never offered
/// a seed.
#[cfg(feature = "kat-internal")]
pub mod kat_api;
#[cfg(feature = "fn-dsa-draft")]
pub mod fn_dsa_draft;
pub mod error;
pub mod poly;
pub mod falcon;
pub mod rng;
pub mod falcon_variants;
pub mod signature_format;
pub mod ntru_solver_robust;
pub mod gaussian_sampler;
pub mod falcon_fpr;
pub mod drbg;
#[cfg(feature = "kat-internal")]
pub mod kat_nist;
pub mod secure_zeroize;
pub mod self_test;
pub mod precision_monitor;
pub mod babai_nearest_plane;
pub mod iterative_refinement;
pub mod verification_config;
pub mod statistics_reporter;
pub mod extended_key;
pub mod sign_extended;
pub mod batch_operations;

// Canonical signing via negacyclic FFT + LDL tree + FFSampling
pub mod falcon_canonical;
/// Discrete Gaussian sampler over the integers (Falcon spec Algorithms 12-15).
/// This is what `falcon_canonical::ffsampling` samples its LDL leaves with;
/// before it existed the leaf did deterministic Babai rounding (#139).
pub mod sampler_z;

// Main implementation - now using corrected algorithms
mod falcon_complete;

// Retry strategy for signing
pub mod retry_strategy;

// ACVP support
pub mod acvp_parser;

#[cfg(feature = "acvp")]
pub mod acvp_generator;

// Deterministic RNG for testing (`kat-internal` only)
#[cfg(feature = "kat-internal")]
pub mod deterministic_rng;
#[cfg(feature = "kat-internal")]
pub mod deterministic_mode;

// Differential testing framework
#[cfg(feature = "kat-internal")]
pub mod differential_testing;

// Security audit and validation
#[cfg(feature = "kat-internal")]
pub mod security_audit;

// Restored mathematical modules from git history
pub mod ffsampling_falcon;
pub mod ntru_working;
pub mod ntru_optimized;
pub mod gaussian_fast;
pub mod gaussian_sampler_proper;
pub mod gaussian_tuned;
pub mod poly_xgcd_cyclotomic;
pub mod poly_modular;

// Gaussian sampling - using new calibrated implementation

// Compression
pub mod compression;
mod compression_proper;
pub mod compression_simple;
pub mod compression_ternary;
pub mod signature_compression_666;
pub mod s0_reconstruction;
pub mod equation_verification;
pub mod sign_compressed;
pub mod simple_sampler;
pub mod simple_sampler_improved;

// FFT and NTT operations
mod fft;
pub mod fft_hybrid;
mod ntt_optimized;
mod ntt_negacyclic;
pub mod ntt_falcon;

// Fast Fourier Sampling - using new corrected implementation

// New numerically stable implementations
pub mod fft_stable;
pub mod ntru_basis;
pub mod gram_matrix;
pub mod ldl_tree;
pub mod ffsampling_correct;
pub mod gaussian_calibrated;
pub mod sign_corrected;
pub mod validation;

// Constant-time operations
mod constant_time;
mod constant_time_ops;
mod side_channel_protection;
pub mod side_channel_hardening;

// NTRU Solver - single reference implementation
mod ntru_exact;

// Polynomial operations
mod poly_arithmetic;
mod karatsuba;

// Lattice operations
mod lattice_reduction;
mod babai_algorithm;
mod orthogonalization; // Re-enabled - fixed dependencies

// SHAKE256 implementation
pub mod shake;

// Falcon-1024 implementation
pub mod falcon1024;
pub(crate) mod deep_stack;

// Unified API for both variants
pub mod unified_api;

// NIST test vector validation
#[cfg(feature = "kat-internal")]
pub mod nist_validation;

// Validation and testing
#[cfg(feature = "kat-internal")]
pub mod test_helpers;
mod nist_kat_validation;
pub mod signature_verification;
#[cfg(feature = "kat-internal")]
pub mod nist_kat_framework;
#[cfg(feature = "kat-internal")]
pub mod nist_vector_parser;
#[cfg(feature = "kat-internal")]
pub mod nist_vectors;
#[cfg(feature = "kat-internal")]
pub mod nist_vectors_generated;
#[cfg(feature = "kat-internal")]
pub mod nist_api;
#[cfg(feature = "kat-internal")]
pub mod nist_kat_test;

// Reference implementation
pub mod falcon_reference;

// Enhanced key generation
pub mod keygen_enhanced;
mod keygen_improved;

pub mod nist_encoding;
pub mod nist_hash;
pub mod nist_signature;
pub mod nist_golomb_rice;
pub mod nist_golomb_rice_optimized;
pub mod golomb_rice_complete;
pub mod nist_tree_encoding;
mod kat_validation;

// Optimizations
mod numerical_stability;

// SIMD dispatch: runtime detection → fastest available implementation
// Hierarchy: AVX-512 > AVX2 > NEON > Portable (scalar)
pub mod dispatch;
pub mod simd;

// Metal GPU batch operations (macOS only)
#[cfg(all(feature = "metal", target_os = "macos"))]
pub mod metal;

// Threshold optimization (March 2025 milestone)
pub mod threshold_optimization;
pub mod dual_threshold_monitor;
pub mod threshold_integration; // Re-enabled - fixed dependencies

use error::Result;

// Re-export commonly used items
pub use constants::{N, Q};
pub use retry_strategy::{SigningConfig, SigningMode, SigningResult, SigningStats};
pub use error::Falcon512Error;

// Import necessary items for the public API
use poly::Poly;

// FIPS 140-3 Self-Test Status
use core::sync::atomic::{AtomicBool, Ordering};
static SELF_TESTS_PASSED: AtomicBool = AtomicBool::new(false);

/// Initialize Falcon-512 module with self-tests
/// 
/// This function MUST be called before using any Falcon-512 operations
/// in FIPS mode. It runs the required power-on self-tests.
pub fn initialize() -> Result<()> {
    // Run power-on self-tests
    if !self_test::run_post()? {
        return Err(Falcon512Error::SelfTestFailed);
    }
    
    // Mark tests as passed
    SELF_TESTS_PASSED.store(true, Ordering::SeqCst);
    
    Ok(())
}

/// Check if self-tests have passed
pub fn self_tests_passed() -> bool {
    SELF_TESTS_PASSED.load(Ordering::SeqCst)
}

/// Ensure self-tests have been run (for FIPS mode)
#[inline]
fn ensure_self_tests() -> Result<()> {
    if cfg!(feature = "fips") && !self_tests_passed() {
        return Err(Falcon512Error::SelfTestNotRun);
    }
    Ok(())
}

// Public key structure
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub h: Poly,
}

impl PublicKey {
    /// Deserialize from NIST format: [header(0x09)] [14-bit packed h] (897 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == constants::PUBLIC_KEY_SIZE {
            // NIST format: 1 header + 896 data
            let h = nist_encoding::decode_public_key(bytes, constants::LOGN)?;
            Ok(PublicKey { h: Poly::new(h) })
        } else if bytes.len() == N * 2 {
            // Legacy raw format: 2 bytes per i16 coefficient
            let coeffs: Vec<i16> = bytes.chunks(2)
                .map(|chunk| {
                    if chunk.len() == 2 {
                        i16::from_le_bytes([chunk[0], chunk[1]])
                    } else {
                        0
                    }
                })
                .collect();
            Ok(PublicKey { h: Poly::new(coeffs) })
        } else {
            Err(error::Falcon512Error::InvalidPublicKey)
        }
    }

    /// Serialize to NIST format: [header(0x09)] [14-bit packed h] (897 bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        nist_encoding::encode_public_key(&self.h.coeffs, constants::LOGN)
    }
}

// Private key structure
#[derive(Clone, Debug)]
pub struct PrivateKey {
    pub f: Poly,
    pub g: Poly,
    pub big_f: Poly,
    pub big_g: Poly,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        use crate::secure_zeroize::secure_zero_i16;
        
        // Securely zeroize all polynomial coefficients
        secure_zero_i16(&mut self.f.coeffs);
        secure_zero_i16(&mut self.g.coeffs);
        secure_zero_i16(&mut self.big_f.coeffs);
        secure_zero_i16(&mut self.big_g.coeffs);
    }
}

impl zeroize::Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        use crate::secure_zeroize::secure_zero_i16;
        
        secure_zero_i16(&mut self.f.coeffs);
        secure_zero_i16(&mut self.g.coeffs);
        secure_zero_i16(&mut self.big_f.coeffs);
        secure_zero_i16(&mut self.big_g.coeffs);
    }
}

impl PrivateKey {
    /// Deserialize from multiple formats:
    /// - 2305 bytes: tree encoding with header(0x59) + f(3bit) + g(3bit) + F(8bit) + G(8bit)
    /// - 1281 bytes: NIST reference encoding [header(0x59)] [f:6bit] [g:6bit] [F:8bit], G recovered
    /// - 4096+ bytes: legacy raw format (4 polynomials x 2 bytes per i16)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == 2305 {
            // Tree format: header + f + g + F + G (all stored)
            use nist_tree_encoding::decode_private_key_tree;
            let (f, g, big_f, big_g) = decode_private_key_tree(bytes)?;

            Ok(PrivateKey {
                f: Poly::new(f),
                g: Poly::new(g),
                big_f: Poly::new(big_f),
                big_g: Poly::new(big_g),
            })
        } else if bytes.len() == 1281 {
            // NIST reference format: header + f(6bit) + g(6bit) + F(8bit)
            let (f, g, big_f) = nist_encoding::decode_private_key(bytes, constants::LOGN)?;

            // Recover G from NTRU equation: f·G − g·F = q  →  G = (q + g·F) · f⁻¹ mod q
            let big_g = ntt_falcon::recover_big_g(&f, &g, &big_f)?;

            Ok(PrivateKey {
                f: Poly::new(f),
                g: Poly::new(g),
                big_f: Poly::new(big_f),
                big_g: Poly::new(big_g),
            })
        } else if bytes.len() >= N * 2 * 4 {
            // Legacy raw format: 4 polynomials × 2 bytes per i16
            let bytes_per_poly = N * 2;
            let to_poly = |b: &[u8]| -> Poly {
                let coeffs: Vec<i16> = b.chunks(2)
                    .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();
                Poly::new(coeffs)
            };

            Ok(PrivateKey {
                f: to_poly(&bytes[0..bytes_per_poly]),
                g: to_poly(&bytes[bytes_per_poly..bytes_per_poly * 2]),
                big_f: to_poly(&bytes[bytes_per_poly * 2..bytes_per_poly * 3]),
                big_g: to_poly(&bytes[bytes_per_poly * 3..bytes_per_poly * 4]),
            })
        } else {
            Err(error::Falcon512Error::InvalidPrivateKey)
        }
    }

    /// Check that this key's LDL tree keeps every leaf width inside the
    /// `(0, SIGMA_MAX]` band `sampler_z` requires.
    ///
    /// Keys from post-#141 keygen satisfy this by construction (the GS bound);
    /// keys minted before it can violate it, deterministically and per-key.
    /// Such a key would sign from the wrong distribution — the
    /// transcript-leaking defect class #141 fixed — so callers should reject
    /// it at load/import time and regenerate. Returns
    /// `Err(Falcon512Error::LdlSigmaOutOfBand)` for a bad key.
    ///
    /// Cost: one Gram-matrix + LDL-tree build (roughly half a signing
    /// attempt), no sampling. Signing itself re-checks the same property and
    /// fails closed, so this is an earlier, better-attributed error, not the
    /// only line of defense.
    pub fn validate_sigma_band(&self) -> Result<()> {
        falcon_canonical::validate_ldl_band(
            &self.f.coeffs,
            &self.g.coeffs,
            &self.big_f.coeffs,
            &self.big_g.coeffs,
            constants::SIGMA,
        )
    }

    /// `from_bytes` followed by `validate_sigma_band`: the import path every
    /// production key loader should use, so a key minted by the pre-#141 keygen
    /// is rejected with `LdlSigmaOutOfBand` at load time rather than at signing.
    pub fn from_bytes_validated(bytes: &[u8]) -> Result<Self> {
        let sk = Self::from_bytes(bytes)?;
        sk.validate_sigma_band()?;
        Ok(sk)
    }

    /// Serialize to NIST reference format: [header(0x59)] [f:6bit] [g:6bit] [F:8bit] (1281 bytes)
    ///
    /// # Panics
    /// If a coefficient does not fit the encoding, which no key from
    /// `generate_keypair` or `from_bytes` has; a key assembled from arbitrary
    /// polynomials should use [`PrivateKey::try_to_bytes`] (#341).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("Falcon-512 private key coefficients outside the NIST encoding range")
    }

    /// Serialize to NIST reference format, refusing a key whose coefficients do
    /// not fit it (`InvalidPrivateKey`) instead of encoding a different key.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        nist_encoding::encode_private_key(
            &self.f.coeffs,
            &self.g.coeffs,
            &self.big_f.coeffs,
            constants::LOGN,
        )
    }
}

// Keypair structure
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

// Public API functions that use the real implementation

/// Generate a Falcon-512 key pair with a caller-supplied RNG.
///
/// The NTRU solve behind this runs on an 8 MB worker thread (see
/// `deep_stack`): on Windows' 1 MB default thread stack it overflowed the
/// `main` thread of any consumer that called it directly, while every unit
/// test passed on the harness's 2 MB threads. That is why `R: Send`.
pub fn generate_keypair<R: rand::RngCore + Send>(rng: &mut R) -> Result<KeyPair> {
    // Check self-tests in FIPS mode
    ensure_self_tests()?;

    // Use working NTRU keygen that produces keys satisfying f*G - g*F = q
    // This is critical for the corrected basis [[g,-f],[G,-F]] to work properly
    let (f, g, big_f, big_g) = ntru_working::ntru_keygen_working(rng)?;

    // Compute public key h = g/f mod q
    let h = ntt_falcon::compute_public_key_ntt(&f, &g)?;

    let public_key = PublicKey {
        h: Poly { coeffs: h },
    };

    let private_key = PrivateKey {
        f: Poly { coeffs: f },
        g: Poly { coeffs: g },
        big_f: Poly { coeffs: big_f },
        big_g: Poly { coeffs: big_g },
    };

    Ok(KeyPair { public_key, private_key })
}

/// Sign in the Round-3 **compressed** profile with a caller-supplied RNG.
///
/// Output: `[0x39] [nonce(40)] [Golomb-Rice(s1)]`, variable length, at most
/// `sizes::falcon512::SIG_COMPRESSED_MAX` (752) bytes — never 690, which is the
/// NIST signed-message overhead, not a signature bound. Size receiving buffers
/// from `sizes`, or use `sign_padded` for a fixed 666-byte output.
///
/// The output is a pure function of `(message, private_key, rng stream)`: a
/// deterministically seeded `rng` yields byte-identical signatures. Production
/// callers without a consensus-determinism requirement should prefer
/// `sign_hedged`, which draws the nonce and the sampler randomness from the OS.
pub fn sign<R: rand::RngCore>(message: &[u8], private_key: &PrivateKey, rng: &mut R) -> Result<Vec<u8>> {
    // Check self-tests in FIPS mode
    ensure_self_tests()?;
    
    // Use standard retry strategy (30 attempts)
    let config = retry_strategy::SigningConfig::from_mode(retry_strategy::SigningMode::Standard);
    let result = retry_strategy::sign_with_retry(message, private_key, rng, &config)?;
    Ok(result.signature)
}

/// Sign a message with custom retry configuration
pub fn sign_with_config<R: rand::RngCore>(
    message: &[u8], 
    private_key: &PrivateKey, 
    rng: &mut R,
    config: &retry_strategy::SigningConfig
) -> Result<retry_strategy::SigningResult> {
    // Check self-tests in FIPS mode
    ensure_self_tests()?;
    
    retry_strategy::sign_with_retry(message, private_key, rng, config)
}

/// Sign in the Round-3 **padded** profile: exactly `sizes::falcon512::SIG_PADDED`
/// (666) bytes, `[0x39] [nonce(40)] [Golomb-Rice(s1)] [zero padding]` — the
/// `falcon.h` FALCON_SIG_PADDED format PQClean ships as `falcon-padded-512`,
/// gated against its NIST KAT in `tests/falcon_padded_upstream_kat.rs`.
/// A body that does not fit is retried with a fresh nonce, never truncated.
pub fn sign_padded<R: rand::RngCore>(
    message: &[u8],
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    ensure_self_tests()?;
    falcon_complete::sign_padded_complete(message, private_key, rng)
}

/// Verify a **padded**-profile signature (exactly 666 bytes; non-zero padding
/// or any other length is rejected).
pub fn verify_padded(message: &[u8], signature: &[u8], public_key: &PublicKey) -> Result<bool> {
    ensure_self_tests()?;
    falcon_complete::verify_padded_complete(message, signature, public_key)
}

/// Probe a randomness source once and hand it back.
///
/// `RngCore::fill_bytes` panics when the source reports failure, and a panic
/// in wasm32 is a trap, so the hedged entry points probe with
/// `try_fill_bytes` first: an unavailable source (the only backend a wasm32
/// build without a JavaScript host links) comes back as
/// [`Falcon512Error::EntropyUnavailable`] before anything is signed. A failure
/// after a successful probe still panics rather than signing with short
/// randomness; the facade's `*_os` functions have the same contract (#369).
fn probe_entropy<R: rand::RngCore>(mut rng: R) -> Result<R> {
    let mut probe = [0u8; 8];
    rng.try_fill_bytes(&mut probe)
        .map_err(|_| Falcon512Error::EntropyUnavailable)?;
    Ok(rng)
}

/// Sign in the compressed profile with operating-system randomness (hedged):
/// the documented production entry point for callers that do not need
/// consensus-deterministic signatures. Where the platform has no randomness
/// source (e.g. a wasm32 runtime without a `getrandom` backend) it returns
/// [`Falcon512Error::EntropyUnavailable`] and signs nothing.
#[cfg(feature = "std")]
pub fn sign_hedged(message: &[u8], private_key: &PrivateKey) -> Result<Vec<u8>> {
    let mut rng = probe_entropy(rand::rngs::OsRng)?;
    sign(message, private_key, &mut rng)
}

/// `sign_padded` with operating-system randomness (hedged). Returns
/// [`Falcon512Error::EntropyUnavailable`] where the platform has no
/// randomness source, like [`sign_hedged`].
#[cfg(feature = "std")]
pub fn sign_padded_hedged(message: &[u8], private_key: &PrivateKey) -> Result<Vec<u8>> {
    let mut rng = probe_entropy(rand::rngs::OsRng)?;
    sign_padded(message, private_key, &mut rng)
}

/// Sign a message without retry (for testing or when caller handles retry).
///
/// Not a production entry point: use `sign` / `sign_hedged` / `sign_padded`.
pub fn sign_no_retry<R: rand::RngCore>(message: &[u8], private_key: &PrivateKey, rng: &mut R) -> Result<Vec<u8>> {
    // Check self-tests in FIPS mode
    ensure_self_tests()?;
    
    // Use the real sign from falcon_complete
    falcon_complete::sign_complete(message, private_key, rng)
}

pub fn verify(message: &[u8], signature: &[u8], public_key: &PublicKey) -> Result<bool> {
    // Check self-tests in FIPS mode
    ensure_self_tests()?;
    
    // Use the real verify from falcon_complete
    falcon_complete::verify_complete(message, signature, public_key)
}

/// Verify a signature with custom configuration
pub fn verify_with_config(
    message: &[u8], 
    signature: &[u8], 
    public_key: &PublicKey,
    config: &verification_config::VerificationConfig
) -> Result<bool> {
    // Check self-tests in FIPS mode
    ensure_self_tests()?;
    
    // Delegate to the complete implementation with config
    falcon_complete::verify_complete_with_config(message, signature, public_key, config)
}

// WASM bindings
#[cfg(feature = "wasm-bindgen")]
pub mod wasm;

// Test configuration module (always available for self-tests)
pub mod test_config;

// #[cfg(test)]
// mod tests_complete;  // Depends on deleted ntru_solver_complete

// #[cfg(test)]
// mod test_nist_debug;  // Module file not found

#[cfg(test)]
mod tests {
    use super::*;

    /// A randomness source that reports failure, as the wasm32 "unavailable"
    /// backend does. `fill_bytes` panics so a test fails if anything draws
    /// from it after the probe.
    struct UnavailableRng;

    impl rand::RngCore for UnavailableRng {
        fn next_u32(&mut self) -> u32 { panic!("drew from an unavailable source") }
        fn next_u64(&mut self) -> u64 { panic!("drew from an unavailable source") }
        fn fill_bytes(&mut self, _: &mut [u8]) { panic!("drew from an unavailable source") }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> core::result::Result<(), rand::Error> {
            Err(rand::Error::new("randomness source unavailable"))
        }
    }

    #[test]
    fn probe_reports_unavailable_entropy_as_an_error() {
        assert!(matches!(probe_entropy(UnavailableRng), Err(Falcon512Error::EntropyUnavailable)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn hedged_signing_still_signs_with_os_randomness() {
        use rand::SeedableRng;
        let kp = generate_keypair(&mut rand::rngs::StdRng::seed_from_u64(369)).unwrap();
        let msg = b"#369 hedged signing";
        let sig = sign_hedged(msg, &kp.private_key).unwrap();
        assert!(verify(msg, &sig, &kp.public_key).unwrap());
        let padded = sign_padded_hedged(msg, &kp.private_key).unwrap();
        assert!(verify_padded(msg, &padded, &kp.public_key).unwrap());
    }
    
    #[test]
    fn test_constants() {
        assert_eq!(N, 512);
        assert_eq!(Q, 12289);
    }
    
    #[test]
    fn test_keygen() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        
        let mut rng = StdRng::seed_from_u64(12345);
        let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
        
        // Check that keys have the expected structure
        assert_eq!(keypair.public_key.h.coeffs.len(), N);
        assert_eq!(keypair.private_key.f.coeffs.len(), N);
        assert_eq!(keypair.private_key.g.coeffs.len(), N);
    }
    
    #[test]
    fn test_sign_verify() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        
        let mut rng = StdRng::seed_from_u64(12345);
        let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
        
        let message = b"Test message";
        let signature = sign(message, &keypair.private_key, &mut rng).expect("Signing should succeed");
        
        // Falcon-512 signatures are typically around 666 bytes when compressed
        assert!(signature.len() > 0);
        assert!(signature.len() <= 2560); // Uncompressed signature size
        
        let valid = verify(message, &signature, &keypair.public_key).expect("Verification should succeed");
        assert!(valid);
        
        // Test that wrong message fails verification
        let wrong_message = b"Wrong message";
        let invalid = verify(wrong_message, &signature, &keypair.public_key).expect("Verification should succeed");
        assert!(!invalid, "Wrong message should fail verification");
    }
    
    #[test]
    fn test_different_keys() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        
        let mut rng1 = StdRng::seed_from_u64(12345);
        let keypair1 = generate_keypair(&mut rng1).expect("Key generation should succeed");
        
        let mut rng2 = StdRng::seed_from_u64(67890);
        let keypair2 = generate_keypair(&mut rng2).expect("Key generation should succeed");
        
        // Keys should be different
        assert_ne!(keypair1.public_key.h.coeffs, keypair2.public_key.h.coeffs);
    }
}
