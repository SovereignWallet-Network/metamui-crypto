// MetaMUI Blake2b
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// See LICENSE for full terms.
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! # BLAKE2b
//!
//! BLAKE2b (RFC 7693) with 256-, 384- and 512-bit outputs, any output length
//! from 1 to 64 bytes, and keyed hashing.
//!
//! Every code path is portable scalar Rust, the same on every target. The
//! one-shot BLAKE2b-512 entry points go through the [`backend`] hook, whose
//! default is the portable hasher; this crate ships no other backend.
//!
//! ## Basic Usage
//!
//! ```rust
//! use metamui_blake2b::{blake2b256, blake2b_512};
//!
//! let hash256 = blake2b256(b"Hello, BLAKE2b!");
//! let hash512 = blake2b_512(b"Hello, BLAKE2b!");
//! ```

use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod backend;
mod blake2b;

pub use blake2b::Blake2bHasher;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// BLAKE2b-256 output size (32 bytes)
pub const BLAKE2B_256_SIZE: usize = 32;

/// BLAKE2b-384 output size (48 bytes)
pub const BLAKE2B_384_SIZE: usize = 48;

/// BLAKE2b-512 output size (64 bytes)
pub const BLAKE2B_512_OUTPUT_SIZE: usize = 64;

/// BLAKE2b block size (128 bytes)
pub const BLAKE2B_BLOCKBYTES: usize = 128;

/// Alias for backward compatibility with metamui-blake2b256
pub const BLAKE2B256_OUTPUT_SIZE: usize = BLAKE2B_256_SIZE;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// BLAKE2b-256 hash result
pub type Blake2b256Hash = [u8; BLAKE2B_256_SIZE];

/// BLAKE2b-384 hash result
pub type Blake2b384Hash = [u8; BLAKE2B_384_SIZE];

// ---------------------------------------------------------------------------
// Blake2b512Hash struct (preserves API from old metamui-blake2b512)
// ---------------------------------------------------------------------------

/// BLAKE2b-512 hash result
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Blake2b512Hash(pub [u8; BLAKE2B_512_OUTPUT_SIZE]);

impl Default for Blake2b512Hash {
    fn default() -> Self {
        Blake2b512Hash([0u8; BLAKE2B_512_OUTPUT_SIZE])
    }
}

impl Blake2b512Hash {
    pub fn len(&self) -> usize { BLAKE2B_512_OUTPUT_SIZE }
    pub fn is_empty(&self) -> bool { false }
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
    pub fn to_bytes(&self) -> [u8; BLAKE2B_512_OUTPUT_SIZE] { self.0 }
}

impl From<[u8; BLAKE2B_512_OUTPUT_SIZE]> for Blake2b512Hash {
    fn from(bytes: [u8; BLAKE2B_512_OUTPUT_SIZE]) -> Self { Blake2b512Hash(bytes) }
}

impl AsRef<[u8]> for Blake2b512Hash {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

// ---------------------------------------------------------------------------
// Blake2b256 Substrate-compat wrapper (preserves API from old metamui-blake2b256)
// ---------------------------------------------------------------------------

/// Blake2b-256 hash wrapper for Substrate compatibility
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Blake2b256([u8; BLAKE2B_256_SIZE]);

impl Blake2b256 {
    pub fn from_raw(bytes: [u8; BLAKE2B_256_SIZE]) -> Self { Self(bytes) }
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
    pub fn into_inner(self) -> [u8; BLAKE2B_256_SIZE] { self.0 }
}

impl fmt::Display for Blake2b256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Blake2b256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blake2b256({})", hex::encode(self.0))
    }
}

impl From<[u8; BLAKE2B_256_SIZE]> for Blake2b256 {
    fn from(bytes: [u8; BLAKE2B_256_SIZE]) -> Self { Self(bytes) }
}

impl AsRef<[u8]> for Blake2b256 {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error types for BLAKE2b operations
#[derive(thiserror::Error, Debug)]
pub enum Blake2bError {
    #[error("Invalid input data: {0}")]
    InvalidInput(String),
    #[error("Hashing operation failed: {0}")]
    HashingFailed(String),
}

// ---------------------------------------------------------------------------
// MetaMUIBlake2b512 canonical hasher struct
// ---------------------------------------------------------------------------

/// MetaMUI Blake2b-512 hash implementation
pub struct MetaMUIBlake2b512;

impl MetaMUIBlake2b512 {
    pub fn new() -> Self { Self }

    /// Unkeyed BLAKE2b-512 of `data`, through the installed [`backend`]
    /// (the portable hasher unless another was installed).
    pub fn hash(&self, data: &[u8]) -> Result<Blake2b512Hash, Blake2bError> {
        Ok((backend::backend().blake2b_512)(data))
    }

    pub fn hash_hex(&self, data: &[u8]) -> Result<String, Blake2bError> {
        let hash = self.hash(data)?;
        Ok(format!("0x{}", hex::encode(hash.0)))
    }

    pub fn hash_multiple(&self, data_items: &[&[u8]]) -> Result<Blake2b512Hash, Blake2bError> {
        let mut hasher = Blake2bHasher::new_with_output_size(64);
        for item in data_items {
            hasher.update(item);
        }
        Ok(hasher.finalize_512())
    }

    pub fn verify_hash(&self, data: &[u8], expected_hash: &Blake2b512Hash) -> bool {
        match self.hash(data) {
            Ok(computed_hash) => &computed_hash == expected_hash,
            Err(_) => false,
        }
    }

    pub fn algorithm_name(&self) -> &'static str { "Blake2b-512" }
    pub fn output_size(&self) -> usize { BLAKE2B_512_OUTPUT_SIZE }
}

impl Default for MetaMUIBlake2b512 {
    fn default() -> Self { Self::new() }
}

impl fmt::Display for MetaMUIBlake2b512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MetaMUIBlake2b512(output_size={})", self.output_size())
    }
}

impl fmt::Debug for MetaMUIBlake2b512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetaMUIBlake2b512")
            .field("algorithm", &self.algorithm_name())
            .field("output_size", &self.output_size())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------

/// Compute Blake2b-256 hash of data
pub fn blake2b256(data: &[u8]) -> Blake2b256Hash {
    let mut hasher = Blake2bHasher::new_with_output_size(32);
    hasher.update(data);
    hasher.finalize_256()
}

/// Compute Blake2b-384 hash of data
pub fn blake2b384(data: &[u8]) -> Blake2b384Hash {
    let mut hasher = Blake2bHasher::new_with_output_size(48);
    hasher.update(data);
    let result = hasher.finalize_variable();
    let mut hash = [0u8; BLAKE2B_384_SIZE];
    hash.copy_from_slice(&result);
    hash
}

/// Compute Blake2b-256 hash and return as Blake2b256 wrapper type
pub fn hash(data: &[u8]) -> Blake2b256 {
    Blake2b256(blake2b256(data))
}

/// Substrate-compatible blake2_256 function
pub fn blake2_256(data: &[u8]) -> [u8; 32] {
    blake2b256(data)
}

/// Compute Blake2b-512 hash
pub fn blake2b_512(data: &[u8]) -> Blake2b512Hash {
    let hasher = MetaMUIBlake2b512::new();
    hasher.hash(data).expect("Blake2b-512 hashing should not fail")
}

/// Compute Blake2b-512 hash as hex string
pub fn blake2b_512_hex(data: &[u8]) -> String {
    let hasher = MetaMUIBlake2b512::new();
    hasher.hash_hex(data).expect("Blake2b-512 hashing should not fail")
}

/// Compute Blake2b with variable output length (1-64 bytes)
pub fn blake2b_variable(data: &[u8], outlen: usize) -> Vec<u8> {
    let mut hasher = Blake2bHasher::new_with_output_size(outlen);
    hasher.update(data);
    hasher.finalize_variable()
}

/// Compute keyed Blake2b with variable output length
pub fn blake2b_variable_keyed(key: &[u8], data: &[u8], outlen: usize) -> Vec<u8> {
    let mut hasher = Blake2bHasher::new_keyed_with_output_size(key, outlen);
    hasher.update(data);
    hasher.finalize_variable()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b256_empty() {
        let result = blake2b256(b"");
        assert_eq!(hex::encode(result), "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
    }

    #[test]
    fn test_blake2b256_abc() {
        let result = blake2b256(b"abc");
        assert_eq!(hex::encode(result), "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
    }

    #[test]
    fn test_blake2b512_empty() {
        let hash = blake2b_512(b"");
        assert_eq!(hex::encode(hash.0), "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    }

    #[test]
    fn test_blake2b512_abc() {
        let hash = blake2b_512(b"abc");
        assert_eq!(hex::encode(hash.0), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    }

    #[test]
    fn test_blake2b256_type() {
        let h = hash(b"test");
        assert_eq!(h.as_bytes().len(), 32);
        let display = format!("{}", h);
        assert_eq!(display.len(), 64);
        let debug = format!("{:?}", h);
        assert!(debug.starts_with("Blake2b256("));
    }

    #[test]
    fn test_substrate_compatibility() {
        let data = b"substrate test";
        assert_eq!(blake2_256(data), blake2b256(data));
    }

    #[test]
    fn test_blake2b512_multiple() {
        let hasher = MetaMUIBlake2b512::new();
        let data_items = vec![b"Hello, ".as_slice(), b"world!".as_slice()];
        let h = hasher.hash_multiple(&data_items).unwrap();
        let direct = blake2b_512(b"Hello, world!");
        assert_eq!(h, direct);
    }

    #[test]
    fn test_blake2b512_verify() {
        let hasher = MetaMUIBlake2b512::new();
        let data = b"test data";
        let h = hasher.hash(data).unwrap();
        assert!(hasher.verify_hash(data, &h));
        let wrong = Blake2b512Hash([0u8; 64]);
        assert!(!hasher.verify_hash(data, &wrong));
    }

    #[test]
    fn test_variable_output() {
        for size in [1, 16, 32, 48, 64] {
            let result = blake2b_variable(b"test", size);
            assert_eq!(result.len(), size);
        }
    }
}
