#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
// Camellia is an internal block cipher crate with many round-key /
// S-box constants and mode-specific fields whose names match the
// Camellia spec directly. Leave rust_2018_idioms enforced; relax
// missing_docs until the public API is fully annotated.
#![allow(missing_docs)]
#![warn(rust_2018_idioms)]

// MetaMUI metamui camellia
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


//! Pure Rust implementation of Camellia block cipher
//!
//! This crate provides a pure Rust implementation of the Camellia encryption algorithm,
//! developed by NTT and Mitsubishi Electric. Camellia is approved by ISO/IEC, NESSIE,
//! and CRYPTREC.
//!
//! # Features
//! - Camellia-128, Camellia-192, and Camellia-256
//! - Multiple block cipher modes: ECB, CBC, CTR, GCM
//! - Portable scalar Rust only; designed for constant time and unmeasured (see README)
//! - No unsafe code
//! - Optional `no_std` support
//!
//! # Examples
//!
//! ```rust
//! use metamui_camellia::{Camellia256, BlockCipher};
//!
//! let key = [0u8; 32]; // 256-bit key
//! let plaintext = [0u8; 16]; // 128-bit block
//!
//! let cipher = Camellia256::new(&key);
//! let mut block = plaintext;
//! cipher.encrypt_block(&mut block);
//! ```

#[cfg(not(feature = "std"))]
extern crate alloc;

mod constants;
mod core;
mod error;
pub mod modes;
mod types;

pub use crate::core::{Camellia, Camellia128, Camellia192, Camellia256};
pub use crate::error::CamelliaError;
pub use crate::modes::{cbc, ctr, ecb, gcm};
pub use crate::types::{Key128, Key192, Key256};

/// Block size for Camellia (128 bits / 16 bytes)
pub const BLOCK_SIZE: usize = 16;

/// Trait for block cipher operations
pub trait BlockCipher {
    /// Encrypt a single block in place
    fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]);
    
    /// Decrypt a single block in place
    fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]);
    
    /// Get the name of the cipher
    fn cipher_name(&self) -> &'static str;
    
    /// Get the key size in bytes
    fn key_size(&self) -> usize;
}

/// Type alias for results using CamelliaError  
pub type Result<T> = ::core::result::Result<T, CamelliaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_size() {
        assert_eq!(BLOCK_SIZE, 16);
    }

    #[test]
    fn test_cipher_names() {
        let key128 = [0u8; 16];
        let key192 = [0u8; 24];
        let key256 = [0u8; 32];
        
        let cipher128 = Camellia128::new(&key128);
        let cipher192 = Camellia192::new(&key192);
        let cipher256 = Camellia256::new(&key256);
        
        assert_eq!(cipher128.cipher_name(), "Camellia-128");
        assert_eq!(cipher192.cipher_name(), "Camellia-192");
        assert_eq!(cipher256.cipher_name(), "Camellia-256");
    }
}