//! SLH-DSA (SPHINCS+) - Stateless Hash-Based Digital Signature Algorithm
//!
//! This crate implements SLH-DSA as specified in NIST FIPS 205: stateless
//! hash-based signatures over the twelve parameter sets (128s/f, 192s/f,
//! 256s/f, each with SHAKE256 and with SHA-2), verified against the NIST ACVP
//! answer files. Every code path is portable scalar Rust.
//!
//! FIPS 205 §9 names `slh_keygen_internal` and `slh_sign_internal` — the
//! variants that take the seeds and the randomizer from the caller — as
//! testing interfaces that an application must not be offered. They exist
//! here as `slh_keygen_from_seeds`, `signing::slh_sign_core` and
//! `signing::slh_sign_internal`, together with the ACVP fixture generator
//! `test_vector_generator`, and are compiled only with the `kat-internal`
//! feature. The randomized `slh_keygen` / `SigningKey::generate` and the
//! FIPS 205 deterministic variant `signing::slh_sign_deterministic`
//! (randomizer = PK.seed) are the application surface.
//!
//! # Example
//! ```ignore
//! use metamui_slhdsa::{SlhDsa128s, SigningKey, VerifyingKey};
//! use rand::rngs::OsRng;
//!
//! // Generate a keypair
//! let signing_key = SigningKey::<SlhDsa128s>::generate(&mut OsRng);
//! let verifying_key = signing_key.verifying_key();
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let signature = signing_key.sign(message);
//!
//! // Verify the signature
//! assert!(verifying_key.verify(message, &signature).is_ok());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
// SLH-DSA (FIPS 205) — many spec-defined constants and Merkle-tree
// fields whose names match the spec directly. Leave rust_2018_idioms
// enforced; relax missing_docs until the public API is fully annotated.
#![allow(missing_docs)]
#![warn(rust_2018_idioms)]

// Link the wasm32 `getrandom` backend. This crate is a cdylib, so cargo links
// it for wasm32 and that link needs `__getrandom_custom` resolved; the
// definition lives in `metamui-getrandom-unavailable`. An unreferenced
// dependency is never loaded, and therefore never linked, so the import is
// what pulls the rlib in — `as _` because only its linkage is wanted.
#[cfg(target_arch = "wasm32")]
use metamui_getrandom_unavailable as _;


#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

// Core modules
pub mod address;
pub mod fors;
pub mod hash;
pub mod hypertree;
pub mod params;
pub mod signing;
pub mod types;
pub mod verification;
pub mod wots;
pub mod xmss;

// Re-exports
pub use params::{
    ParameterSet, Parameters, SlhDsa128f, SlhDsa128s, SlhDsa192f, SlhDsa192s, SlhDsa256f,
    SlhDsa256s,
    // SHA2 variants
    SlhDsa128fSha2, SlhDsa128sSha2, SlhDsa192fSha2, SlhDsa192sSha2, SlhDsa256fSha2,
    SlhDsa256sSha2,
};
pub use signing::PreHashAlgorithm;
pub use types::{Signature, SigningKey, VerifyingKey};

// ACVP test vector support. The parser is plain JSON handling; the generator
// seeds a ChaCha20 stream and drives the seeded entry points, so it is part
// of the `kat-internal` surface.
#[cfg(feature = "std")]
pub mod acvp_parser;
#[cfg(feature = "kat-internal")]
pub mod test_vector_generator;

// Errors
use core::fmt;

/// Error type for SLH-DSA operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid key size
    InvalidKeySize,
    /// Invalid signature size
    InvalidSignatureSize,
    /// Signature verification failed
    VerificationFailed,
    /// Invalid parameter set
    InvalidParameters,
    /// Random number generator error
    RngError,
    /// Context string longer than [`MAX_CONTEXT_BYTES`] (FIPS 205 Algorithms 22–25)
    ContextTooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKeySize => write!(f, "Invalid key size"),
            Error::InvalidSignatureSize => write!(f, "Invalid signature size"),
            Error::VerificationFailed => write!(f, "Signature verification failed"),
            Error::InvalidParameters => write!(f, "Invalid parameter set"),
            Error::RngError => write!(f, "Random number generator error"),
            Error::ContextTooLong => write!(f, "Context longer than 255 bytes"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Longest context string FIPS 205 admits. M' carries |ctx| in one byte, so
/// a longer context would wrap it: a 256-byte ctx C would be encoded as the
/// empty context followed by C, and (C, m) would sign or verify as (ε, C ‖ m).
pub const MAX_CONTEXT_BYTES: usize = 255;

/// Result type for SLH-DSA operations
pub type Result<T> = core::result::Result<T, Error>;

// High-level API functions
use rand_core::{CryptoRng, RngCore};

/// Generate a new SLH-DSA keypair
pub fn slh_keygen<P: Parameters, R: RngCore + CryptoRng>(rng: &mut R) -> (Vec<u8>, Vec<u8>) {
    let mut sk = vec![0u8; P::SK_BYTES];
    let mut pk = vec![0u8; P::PK_BYTES];

    // Generate random seeds
    rng.fill_bytes(&mut sk);

    // Split secret key into components
    let sk_seed = &sk[..P::N];
    let _sk_prf = &sk[P::N..2 * P::N];
    let pk_seed = &sk[2 * P::N..3 * P::N];
    // Copy public seed to public key
    pk[..P::N].copy_from_slice(pk_seed);

    // Generate public key root using hypertree
    let pk_root = hypertree::hypertree_root::<P>(sk_seed, pk_seed);
    pk[P::N..].copy_from_slice(&pk_root);
    sk[3 * P::N..4 * P::N].copy_from_slice(&pk_root);

    (pk, sk)
}

/// Generate a keypair from caller-supplied seeds — FIPS 205 Algorithm 18
/// `slh_keygen_internal(SK.seed, SK.prf, PK.seed)`.
///
/// Test-only: compiled with the `kat-internal` feature (see the crate docs).
/// The ACVP keyGen gate rebuilds every answer-file key through it; an
/// application generates keys with `slh_keygen` or `SigningKey::generate`.
#[cfg(feature = "kat-internal")]
pub fn slh_keygen_from_seeds<P: Parameters>(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if sk_seed.len() != P::N || sk_prf.len() != P::N || pk_seed.len() != P::N {
        return Err(Error::InvalidKeySize);
    }
    let mut sk = Vec::with_capacity(P::SK_BYTES);
    sk.extend_from_slice(sk_seed);
    sk.extend_from_slice(sk_prf);
    sk.extend_from_slice(pk_seed);

    let pk_root = hypertree::hypertree_root::<P>(sk_seed, pk_seed);
    sk.extend_from_slice(&pk_root);

    let mut pk = Vec::with_capacity(P::PK_BYTES);
    pk.extend_from_slice(pk_seed);
    pk.extend_from_slice(&pk_root);

    Ok((pk, sk))
}

/// Sign a message with SLH-DSA
pub fn slh_sign<P: Parameters, R: RngCore + CryptoRng>(
    sk: &[u8],
    msg: &[u8],
    rng: Option<&mut R>,
) -> Result<Vec<u8>> {
    if sk.len() != P::SK_BYTES {
        return Err(Error::InvalidKeySize);
    }

    let sk_seed = &sk[..P::N];
    let sk_prf = &sk[P::N..2 * P::N];
    let pk_seed = &sk[2 * P::N..3 * P::N];
    let pk_root = &sk[3 * P::N..];

    signing::slh_sign::<P, R>(sk_seed, sk_prf, pk_seed, pk_root, msg, rng, &[])
}

/// Verify a SLH-DSA signature
pub fn slh_verify<P: Parameters>(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    if pk.len() != P::PK_BYTES {
        return Err(Error::InvalidKeySize);
    }

    let pk_seed = &pk[..P::N];
    let pk_root = &pk[P::N..];

    verification::slh_verify::<P>(pk_seed, pk_root, msg, &[], sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", Error::InvalidKeySize), "Invalid key size");
        assert_eq!(
            format!("{}", Error::VerificationFailed),
            "Signature verification failed"
        );
    }
}
