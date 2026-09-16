#![warn(missing_docs)]

// MetaMUI metamui crypto utilities
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! MetaMUI Cryptographic Utilities
//! 
//! A comprehensive collection of cryptographic utilities and primitives
//! used across the MetaMUI ecosystem. This library provides:
//! 
//! - Secure random number generation
//! - Message authentication codes (HMAC, Poly1305, SipHash)
//! - Key derivation functions (HKDF, PBKDF2, Argon2)
//! - Mnemonic generation and handling (BIP39)
//! - Encoding utilities (Hex, Base64, Base58)
//! - Padding schemes (PKCS7, ISO10126)
//! - Constant-time operations
//! - Memory security utilities



/// Random number generation utilities
pub mod random;

/// Cryptographic hash functions
pub mod hashing;

/// Message authentication codes
pub mod mac;

/// Key derivation functions
pub mod kdf;

/// Mnemonic seed phrase utilities
#[cfg(feature = "mnemonic")]
pub mod mnemonic;

/// Encoding and decoding utilities
#[cfg(feature = "encoding")]
pub mod encoding;

/// Padding schemes
#[cfg(feature = "padding")]
pub mod padding;

/// Constant-time and secure operations
pub mod operations;

/// General utilities (bit operations, endianness, math)
pub mod utilities;

/// Memory pool for efficient buffer allocation
#[cfg(feature = "std")]
pub mod memory_pool;

/// Error types for crypto utilities
pub mod error;

/// FlatHash for deterministic JSON hashing
#[cfg(feature = "flathash")]
pub mod flathash;

// Re-export commonly used items
pub use error::{CryptoUtilError, Result};
pub use random::Random;

#[cfg(any(test, feature = "test-utils"))]
pub use random::test_rng::{DeterministicRng, TestRng};

#[cfg(feature = "hmac")]
pub use mac::hmac::Hmac;

#[cfg(feature = "kdf")]
pub use kdf::{hkdf::Hkdf, pbkdf2::Pbkdf2};

#[cfg(feature = "mnemonic")]
pub use mnemonic::bip39::Bip39;

pub use operations::{constant_time::ConstantTime, secure_clear::Clear};

#[cfg(feature = "flathash")]
pub use flathash::{MetaMUIFlatHash, flat_hash, flat_hash_hex, FlatHash, FLATHASH_OUTPUT_SIZE};

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        error::{CryptoUtilError, Result},
        random::Random,
        operations::{constant_time::ConstantTime, secure_clear::Clear},
    };
    
    #[cfg(feature = "hmac")]
    pub use crate::mac::hmac::Hmac;
    
    #[cfg(feature = "kdf")]
    pub use crate::kdf::{hkdf::Hkdf, pbkdf2::Pbkdf2};
    
    #[cfg(feature = "encoding")]
    pub use crate::encoding::{hex, base64, base58};
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_imports() {
        // Ensure basic imports work
        let _ = Random::new();
    }
}
