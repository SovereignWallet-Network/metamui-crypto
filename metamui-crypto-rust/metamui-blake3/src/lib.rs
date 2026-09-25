// MetaMUI Blake3
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

//! # MetaMUI BLAKE3
//!
//! BLAKE3 in portable Rust: hash, keyed hash, key derivation and the
//! extendable output, verified against the official BLAKE3 vectors.
//!
//! Every code path is portable scalar Rust, the same on every target; there
//! is no SIMD, assembly or GPU path and no CPU-feature detection. The
//! many-input operations go through [`backend`], whose default is the
//! portable implementation; a separate crate may install another once.
//!
//! ## Quick Start
//!
//! ```rust
//! use metamui_blake3::MetaMUIBlake3;
//!
//! // One-shot hashing
//! let hash = MetaMUIBlake3::new().hash(b"Hello, world!");
//! println!("{}", hash.to_hex());
//!
//! // The `blake3` crate's API, for drop-in use
//! let same = metamui_blake3::hash(b"Hello, world!");
//! assert_eq!(same.as_bytes(), hash.as_bytes());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
// `doc_auto_cfg` was folded into `doc_cfg` in Rust 1.92 and naming it is now a hard
// error, which failed every docs.rs build of this crate (#215).
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

// Link the wasm32 `getrandom` backend. This crate is built for wasm32 by the
// npm wrapper, and that link needs `__getrandom_custom` resolved; the
// definition lives in `metamui-getrandom-unavailable`. An unreferenced
// dependency is never loaded, and therefore never linked, so the import is
// what pulls the rlib in — `as _` because only its linkage is wanted.
#[cfg(target_arch = "wasm32")]
use metamui_getrandom_unavailable as _;

#[cfg(not(feature = "std"))]
extern crate alloc;

/// BLAKE3 Cryptographic Hash Function
///
/// This crate provides a safe, high-performance implementation of the BLAKE3 cryptographic hash
/// function with SIMD optimizations and multithreading support.
///
/// BLAKE3 is a cryptographic hash function that is:
/// - Much faster than MD5, SHA-1, SHA-2, SHA-3, and BLAKE2
/// - Secure, with no known attacks
/// - Highly parallelizable across any number of threads and SIMD lanes
/// - Capable of verified streaming and incremental updates
/// - A tree-based design that provides many useful features
///
/// # Examples
///
/// Basic hashing:
///
/// ```
/// use metamui_blake3::MetaMUIBlake3;
///
/// let hasher = MetaMUIBlake3::new();
/// let hash = hasher.hash(b"hello world");
/// println!("Hash: {}", hex::encode(hash));
/// ```
///
/// Key derivation:
///
/// ```
/// use metamui_blake3::MetaMUIBlake3;
///
/// let key = MetaMUIBlake3::derive_key("context", b"secret", 32);
/// println!("Derived key: {}", hex::encode(key));
/// ```

#[cfg(feature = "std")]
extern crate std;

use metamui_security_utils::Zeroize;

// Import shared utilities
use metamui_crypto_utilities::encoding::hex;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::{String, ToString}, format};
#[cfg(feature = "std")]
use std::{vec, vec::Vec};

mod error;
mod traits;

// The backend hook of the many-input operations (default: portable).
pub mod backend;

// Batch processing API
#[cfg(feature = "batch-api")]
pub mod batch;

// Key Derivation Function (consolidated from metamui-blake3-kdf)
#[cfg(feature = "kdf")]
pub mod kdf;

// Parallel tree hashing module (requires multithreading feature)
#[cfg(feature = "multithreading")]
pub mod parallel;

/// Core BLAKE3 algorithm implementation
///
/// Low-level BLAKE3 primitives and state management.
pub mod blake3;

/// Compatibility shim matching the `blake3` crate (crates.io) API.
///
/// Enables zero-change migration: just swap the Cargo.toml dependency
/// and existing `blake3::hash()`, `blake3::Hasher`, etc. calls work unchanged.
pub mod compat;

pub use error::*;
pub use traits::*;

/// BLAKE3 of each of several independent inputs, through the installed
/// [`backend`] (portable unless another was installed).
pub fn hash_many(inputs: &[&[u8]]) -> Vec<Blake3Hash> {
    let mut out = vec![[0u8; HASH_SIZE]; inputs.len()];
    backend::hash_many(inputs, &mut out);
    out.into_iter().map(Blake3Hash).collect()
}

// Re-export compat API at crate root so that `blake3 = { package = "metamui-blake3" }`
// gives consumers `blake3::hash()`, `blake3::Hasher`, `blake3::Hash` for free.
pub use compat::{hash, keyed_hash, Hash, Hasher};

// Re-export correct parallel tree hashing functions for convenience
#[cfg(feature = "multithreading")]
pub use parallel::{
    hash as hash_parallel,
    // hash_keyed is not currently re-exported from parallel::tree in mod.rs, need to check if it should be
};

// Module alias for backward compatibility with examples
#[cfg(feature = "multithreading")]
pub use parallel as blake3_parallel;

/// Size of BLAKE3 hash output in bytes (32 bytes / 256 bits)
pub const HASH_SIZE: usize = 32;

/// Size of BLAKE3 key in bytes (32 bytes / 256 bits)
pub const KEY_SIZE: usize = 32;

/// BLAKE3 hash output
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Blake3Hash([u8; HASH_SIZE]);

impl Blake3Hash {
    /// Create a new Blake3Hash from a byte array
    pub fn new(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the hash as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the hash as a byte array
    pub fn to_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }

    /// Create Blake3Hash from a slice, returning an error if the length is incorrect
    pub fn from_slice(slice: &[u8]) -> Blake3Result<Self> {
        if slice.len() != HASH_SIZE {
            return Err(Blake3Error::InvalidLength {
                expected: HASH_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; HASH_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Parse a hex string into a Blake3Hash using shared utility
    pub fn from_hex(hex_str: &str) -> Blake3Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| Blake3Error::HexDecoding(e.to_string()))?;
        Self::from_slice(&bytes)
    }

    /// Convert the hash to a hex string using shared utility
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Convert the hash to a hex string with 0x prefix using shared utility
    pub fn to_hex_prefixed(&self) -> String {
        format!("0x{}", hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for Blake3Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; HASH_SIZE]> for Blake3Hash {
    fn from(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }
}

// Note: Conversions to/from external blake3 crate types removed
// as we're using pure Rust implementation

/// BLAKE3 key for keyed hashing

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Blake3Key([u8; KEY_SIZE]);

impl Blake3Key {
    /// Create a new Blake3Key from a byte array
    pub fn new(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the key as a byte array
    pub fn to_bytes(self) -> [u8; KEY_SIZE] {
        self.0
    }

    /// Create Blake3Key from a slice, returning an error if the length is incorrect
    pub fn from_slice(slice: &[u8]) -> Blake3Result<Self> {
        if slice.len() != KEY_SIZE {
            return Err(Blake3Error::InvalidLength {
                expected: KEY_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Generate a random key using the system random number generator
    #[cfg(feature = "std")]
    pub fn random() -> Blake3Result<Self> {
        use metamui_security_utils::fill_random_bytes;

        let mut key_bytes = [0u8; KEY_SIZE];
        fill_random_bytes(&mut key_bytes)
            .map_err(|_| Blake3Error::KeyGeneration)?;

        Ok(Self(key_bytes))
    }

    /// Parse a hex string into a Blake3Key
    pub fn from_hex(hex_str: &str) -> Blake3Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| Blake3Error::HexDecoding(e.to_string()))?;
        Self::from_slice(&bytes)
    }
}

impl core::fmt::Debug for Blake3Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Blake3Key")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Zeroize for Blake3Key {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// High-level BLAKE3 hasher with extended functionality
#[derive(Clone)]
pub struct MetaMUIBlake3 {
    hasher: blake3::Blake3Hasher,
}

impl MetaMUIBlake3 {
    /// Create a new BLAKE3 hasher
    pub fn new() -> Self {
        Self {
            hasher: blake3::Blake3Hasher::new(),
        }
    }

    /// Create a new keyed BLAKE3 hasher
    pub fn new_keyed(key: &Blake3Key) -> Self {
        Self {
            hasher: blake3::Blake3Hasher::new_keyed(&key.0),
        }
    }

    /// Create a new BLAKE3 hasher for key derivation
    pub fn new_derive_key(context: &str) -> Self {
        Self {
            hasher: blake3::Blake3Hasher::new_derive_key(context),
        }
    }

    /// Hash data and return the result
    pub fn hash(&self, data: &[u8]) -> Blake3Hash {
        Blake3Hash::new(blake3::native_blake3(data))
    }

    /// Hash data with a key
    pub fn hash_keyed(key: &Blake3Key, data: &[u8]) -> Blake3Hash {
        Blake3Hash::new(blake3::native_blake3_keyed(&key.0, data))
    }

    /// Derive a key from input key material.
    ///
    /// Output of any length comes from the BLAKE3 XOF over the
    /// DERIVE_KEY_MATERIAL root, exactly like the reference
    /// implementation. (The old non-32-byte path concatenated separate
    /// derive_key calls over material||counter — a homemade construction
    /// no other BLAKE3 implementation can reproduce. Ground truth:
    /// test-vectors/blake3/blake3-official-vectors.json.)
    pub fn derive_key(context: &str, input_key_material: &[u8], output_length: usize) -> Vec<u8> {
        let mut hasher = blake3::Blake3Hasher::new_derive_key(context);
        hasher.update(input_key_material);
        hasher.finalize_len(output_length)
    }

    /// Start incremental hashing
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize incremental hashing and return the result
    pub fn finalize(&self) -> Blake3Hash {
        Blake3Hash::new(self.hasher.finalize())
    }

    /// The first 32 bytes of the XOF, as a `Vec` (the same bytes as
    /// [`finalize`](Self::finalize)); use
    /// [`finalize_variable`](Self::finalize_variable) for any other length.
    pub fn finalize_xof(&self) -> Vec<u8> {
        self.hasher.finalize().to_vec()
    }

    /// Reset the hasher to its initial state
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Get the current hash without finalizing (allows continued updates)
    pub fn finalize_seek(&self, _seek: u64) -> Blake3Hash {
        // Native implementation doesn't support seek yet
        Blake3Hash::new(self.hasher.finalize())
    }

    /// Generate arbitrary-length output (BLAKE3 XOF).
    ///
    /// The old implementation chained hash(base||counter) for outputs
    /// beyond 32 bytes — incompatible with BLAKE3's defined XOF at every
    /// input size. Now delegates to the root-block re-compression in the
    /// core (validated against the official 131-byte vectors).
    pub fn finalize_variable(&self, output_length: usize) -> Vec<u8> {
        self.hasher.finalize_len(output_length)
    }

    /// Hash several independent inputs in parallel (requires "multithreading" feature)
    #[cfg(feature = "multithreading")]
    pub fn hash_chunks_parallel(chunks: &[&[u8]]) -> Vec<Blake3Hash> {
        parallel::ParallelHasher::hash_many(chunks)
    }
}

impl Default for MetaMUIBlake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for MetaMUIBlake3 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MetaMUIBlake3").finish()
    }
}

/// Blake3 MAC (Message Authentication Code) functionality
pub struct Blake3Mac {
    key: Blake3Key,
}

impl Blake3Mac {
    /// Create a new Blake3Mac with the given key
    pub fn new(key: Blake3Key) -> Self {
        Self { key }
    }

    /// Generate a MAC for the given data
    pub fn mac(&self, data: &[u8]) -> Blake3Hash {
        MetaMUIBlake3::hash_keyed(&self.key, data)
    }

    /// Verify a MAC for the given data
    pub fn verify(&self, data: &[u8], expected_mac: &Blake3Hash) -> bool {
        let computed_mac = self.mac(data);
        // Constant-time comparison
        use metamui_security_utils::constant_time::ConstantTimeEq;
        computed_mac.0.ct_eq(&expected_mac.0).into()
    }
}

impl core::fmt::Debug for Blake3Mac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Blake3Mac")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Zeroize for Blake3Mac {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for Blake3Mac {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_hashing() {
        let hasher = MetaMUIBlake3::new();
        let hash = hasher.hash(b"hello world");
        
        // BLAKE3 of "hello world"
        let expected = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
        assert_eq!(hash.to_hex(), expected);
    }

    #[test]
    fn test_keyed_hashing() {
        let key = Blake3Key::new([1u8; 32]);
        let hash = MetaMUIBlake3::hash_keyed(&key, b"hello world");
        
        // This should be different from unkeyed hash
        let unkeyed = MetaMUIBlake3::new().hash(b"hello world");
        assert_ne!(hash, unkeyed);
    }

    #[test]
    fn test_incremental_hashing() {
        let mut hasher = MetaMUIBlake3::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let hash = hasher.finalize();
        
        let direct_hash = MetaMUIBlake3::new().hash(b"hello world");
        assert_eq!(hash, direct_hash);
    }

    #[test]
    fn test_derive_key() {
        let derived = MetaMUIBlake3::derive_key("test context", b"input key material", 32);
        assert_eq!(derived.len(), 32);
        
        // Same input should produce same output
        let derived2 = MetaMUIBlake3::derive_key("test context", b"input key material", 32);
        assert_eq!(derived, derived2);
        
        // Different context should produce different output
        let derived3 = MetaMUIBlake3::derive_key("different context", b"input key material", 32);
        assert_ne!(derived, derived3);
    }

    #[test]
    fn test_xof() {
        let hasher = MetaMUIBlake3::new();
        let short_output = hasher.finalize_variable(16);
        let long_output = hasher.finalize_variable(64);
        
        assert_eq!(short_output.len(), 16);
        assert_eq!(long_output.len(), 64);
        
        // Short output should be prefix of long output
        assert_eq!(&short_output[..], &long_output[..16]);
    }

    #[test]
    fn test_mac() {
        let key = Blake3Key::new([42u8; 32]);
        let mac = Blake3Mac::new(key);
        
        let tag = mac.mac(b"test message");
        assert!(mac.verify(b"test message", &tag));
        assert!(!mac.verify(b"different message", &tag));
    }

    #[test]
    fn test_hex_conversion() {
        let hash = MetaMUIBlake3::new().hash(b"test");
        let hex = hash.to_hex();
        let parsed = Blake3Hash::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_error_handling() {
        // Test invalid length
        assert!(Blake3Hash::from_slice(&[0u8; 31]).is_err());
        assert!(Blake3Hash::from_slice(&[0u8; 33]).is_err());
        
        // Test invalid hex
        assert!(Blake3Hash::from_hex("invalid hex").is_err());
    }
}
