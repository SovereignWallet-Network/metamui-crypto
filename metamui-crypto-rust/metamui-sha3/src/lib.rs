#![cfg_attr(not(feature = "std"), no_std)]

// MetaMUI metamui sha3
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! # SHA3 - Secure Hash Algorithm 3
//! 
//! Production-ready SHA3 implementation with Keccak sponge construction.
//! Provides NIST FIPS 202 compliant SHA3 hash functions.
//!
//! ## Features
//! 
//! - Complete Keccak-f[1600] permutation with 24 rounds
//! - SHA3-256: 256-bit output, 1088-bit rate
//! - SHA3-384: 384-bit output, 832-bit rate  
//! - SHA3-512: 512-bit output, 576-bit rate
//! - Proper SHA3 padding and domain separation (0x06)
//! - Constant-time operations for security
//! - No external dependencies - pure Rust implementation
//! - `no_std` compatible
//!
//! ## Basic Usage
//!
//! ```rust
//! use metamui_sha3::{Sha3_256, Sha3_384, Sha3_512};
//!
//! // Hash with fixed output length
//! let input = b"Hello, SHA3!";
//! let hash256 = Sha3_256::hash(input);
//! let hash384 = Sha3_384::hash(input);
//! let hash512 = Sha3_512::hash(input);
//! 
//! // Incremental hashing
//! let mut sha3 = Sha3_256::new();
//! sha3.update(b"Hello, ");
//! sha3.update(b"SHA3!");
//! let hash = sha3.finalize();
//! ```

#[cfg(not(feature = "std"))]
extern crate alloc;



pub mod keccak;
mod sha3;

pub use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

/// Convenience function for SHA3-224
pub fn sha3_224(data: &[u8]) -> [u8; 28] {
    Sha3_224::hash(data)
}

/// Convenience function for SHA3-256
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::hash(data)
}

/// Convenience function for SHA3-384
pub fn sha3_384(data: &[u8]) -> [u8; 48] {
    Sha3_384::hash(data)
}

/// Convenience function for SHA3-512
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    Sha3_512::hash(data)
}