// MetaMUI SHA-2 Family Implementation
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! # MetaMUI SHA-2 Family
//!
//! Pure Rust implementations of the SHA-2 cryptographic hash function family
//! as specified in FIPS 180-4 (Secure Hash Standard), with HMAC support
//! per RFC 2104 / RFC 4231.
//!
//! This crate provides:
//! - [`sha224`] — SHA-224 (28-byte digest)
//! - [`sha256`] — SHA-256 (32-byte digest) + HMAC-SHA-256
//! - [`sha384`] — SHA-384 (48-byte digest) + HMAC-SHA-384
//! - [`sha512`] — SHA-512 (64-byte digest) + HMAC-SHA-512
//! - [`sha512_224`] / [`sha512_256`] — the FIPS 180-4 §5.3.6 truncated
//!   SHA-512 variants (28- and 32-byte digests)
//!
//! SHA-224 and SHA-512/t exist for the FIPS 204 / FIPS 205 pre-hash table
//! (`metamui-prehash-oids`); the streaming [`Sha256Hasher`] and
//! [`Sha512Hasher`] are what the in-tree signature schemes hash with.
//!
//! ## Quick Start
//!
//! ```rust
//! use metamui_sha2::{sha256, sha384, sha512};
//!
//! let h256 = sha256(b"abc");
//! let h384 = sha384(b"abc");
//! let h512 = sha512(b"abc");
//!
//! assert_eq!(h256.len(), 32);
//! assert_eq!(h384.len(), 48);
//! assert_eq!(h512.len(), 64);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod sha224;
pub mod sha256;
pub mod sha384;
pub mod sha512;
pub mod sha512t;

// Top-level convenience re-exports
pub use sha224::{sha224, Sha224Hasher};
pub use sha256::{sha256, MetaMUISha256, Sha256Error, Sha256Hasher};
pub use sha384::{sha384, MetaMUISha384, Sha384Error};
pub use sha512::{sha512, MetaMUISha512, Sha512Error, Sha512Hasher};
pub use sha512t::{sha512_224, sha512_256, Sha512_224Hasher, Sha512_256Hasher};
