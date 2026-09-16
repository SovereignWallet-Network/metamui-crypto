//! ML-KEM (Module Lattice Key Encapsulation Mechanism) implementation
//!
//! This crate provides a pure Rust implementation of ML-KEM with all parameter sets
//! as specified in NIST FIPS 203. ML-KEM is the standardized version of CRYSTALS-Kyber.
//!
//! # Security Levels
//! - ML-KEM-512: NIST Level 1 (≥ AES-128)
//! - ML-KEM-768: NIST Level 3 (≥ AES-192)
//! - ML-KEM-1024: NIST Level 5 (≥ AES-256)
//!
//! # Example
//! ```ignore
//! use metamui_mlkem::{MLKem768, Kem};
//!
//! let (public_key, secret_key) = MLKem768::generate_keypair()?;
//! let (ciphertext, shared_secret) = MLKem768::encapsulate(&public_key)?;
//! let decapsulated = MLKem768::decapsulate(&ciphertext, &secret_key)?;
//! assert_eq!(shared_secret, decapsulated);
//! ```
//!
//! # Test-only entry points
//! FIPS 203 §6 defines `ML-KEM.KeyGen_internal(d, z)` and
//! `ML-KEM.Encaps_internal(ek, m)` for testing, and says applications must not
//! be offered them. They exist here as `generate_keypair_from_dz` and
//! `encapsulate_deterministic`, next to the MetaMUI single-seed convention
//! `generate_keypair_from_seed`, and are compiled only with the
//! `fips203-internal` feature. The randomized `generate_keypair` and
//! `encapsulate` draw their inputs and run the same internal bodies, so the
//! ACVP vectors verify the functions applications call.

// MetaMUI ML-KEM
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

#![warn(missing_docs)]

extern crate alloc;

// Link the wasm32 `getrandom` backend the manifest declares. A dependency no
// source file names is never loaded, so the manifest line alone lets `cargo
// check` pass while every wasm32 link that reaches `OsRng` fails with
// `undefined symbol: __getrandom_custom`. The import is what pulls the rlib
// in — `as _` because only its linkage is wanted (metamui-falcon512 does the
// same).
#[cfg(target_arch = "wasm32")]
use metamui_getrandom_unavailable as _;

use rand_core::{CryptoRng, RngCore};

// Module declarations
pub mod error;
pub mod params;
pub mod polynomial;
pub mod ntt;
mod sampling;
mod compress;
mod indcpa;
pub(crate) mod kem;

// ACVP test vector support
#[cfg(feature = "std")]
pub mod acvp_parser;
#[cfg(feature = "std")]
pub mod test_vector_generator;

// Parameter set implementations
#[cfg(feature = "mlkem512")]
pub mod mlkem512;
#[cfg(feature = "mlkem768")]
pub mod mlkem768;
#[cfg(feature = "mlkem1024")]
pub mod mlkem1024;

// Re-exports
pub use error::MLKemError;
pub use params::{MLKemParams, MLKemParameterSet};

/// Common trait for all ML-KEM parameter sets
pub trait Kem {
    /// Public key type
    type PublicKey: AsRef<[u8]> + AsMut<[u8]>;
    /// Secret key type
    type SecretKey: AsRef<[u8]> + AsMut<[u8]>;
    /// Ciphertext type
    type Ciphertext: AsRef<[u8]> + AsMut<[u8]>;
    /// Shared secret type
    type SharedSecret: AsRef<[u8]> + AsMut<[u8]>;

    /// Generate a new keypair
    fn generate_keypair<R: RngCore + CryptoRng>(
        rng: &mut R
    ) -> Result<(Self::PublicKey, Self::SecretKey), MLKemError>;

    /// Encapsulate a shared secret
    fn encapsulate<R: RngCore + CryptoRng>(
        public_key: &Self::PublicKey,
        rng: &mut R
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), MLKemError>;

    /// Decapsulate a shared secret
    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext
    ) -> Result<Self::SharedSecret, MLKemError>;
}

/// ML-KEM-512 implementation
#[cfg(feature = "mlkem512")]
pub struct MLKem512;

/// ML-KEM-1024 implementation
#[cfg(feature = "mlkem1024")]
pub struct MLKem1024;

// Re-export ML-KEM-768 key types and functions at crate root for convenience
#[cfg(feature = "mlkem768")]
pub use mlkem768::MLKem768;
#[cfg(feature = "mlkem768")]
pub use mlkem768::{decapsulate, encapsulate, generate_keypair};
#[cfg(all(feature = "mlkem768", feature = "fips203-internal"))]
pub use mlkem768::generate_keypair_from_seed;
#[cfg(feature = "mlkem768")]
pub use mlkem768::types::{Ciphertext, KeyPair, PrivateKey, PublicKey, SharedSecret};
#[cfg(all(feature = "mlkem768", feature = "std"))]
pub use mlkem768::generate_keypair_default;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_sets() {
        #[cfg(feature = "mlkem512")]
        {
            let params = params::MLKEM512_PARAMS;
            assert_eq!(params.k, 2);
            assert_eq!(params.n, 256);
        }

        #[cfg(feature = "mlkem768")]
        {
            let params = params::MLKEM768_PARAMS;
            assert_eq!(params.k, 3);
            assert_eq!(params.n, 256);
        }

        #[cfg(feature = "mlkem1024")]
        {
            let params = params::MLKEM1024_PARAMS;
            assert_eq!(params.k, 4);
            assert_eq!(params.n, 256);
        }
    }
}