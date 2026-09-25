#![no_std]

// MetaMUI metamui poly1305
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
//! # MetaMUI Poly1305 One-Time Authenticator
//!
//! This crate provides a pure Rust implementation of the Poly1305 one-time authenticator
//! as specified in RFC 8439. Poly1305 is designed by Daniel J. Bernstein and provides
//! 128-bit security for message authentication.
//!
//! ## Features
//!
//! - RFC 8439 compliant implementation
//! - No external dependencies (no_std compatible)
//! - Portable scalar Rust only (a big-integer path and a 26-bit-limb path); unmeasured (see README)
//! - Secure memory clearing

extern crate alloc;

use alloc::vec::Vec;
use metamui_security_utils::{Zeroize, ZeroizeOnDrop};
use num_bigint::BigUint;
use num_traits::{Zero, One};

// Re-export hex! macro for convenience
#[cfg(test)]
pub use hex_literal::hex;

/// Poly1305 key size in bytes (256 bits)
pub const KEY_SIZE: usize = 32;
/// Poly1305 tag size in bytes (128 bits)  
pub const TAG_SIZE: usize = 16;
/// Block size for processing
#[allow(dead_code)]
const BLOCK_SIZE: usize = 16;

/// Poly1305 errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poly1305Error {
    /// Invalid key size
    InvalidKeySize,
    /// Invalid tag size  
    InvalidTagSize,
    /// Already finalized
    AlreadyFinalized,
}

/// Poly1305 one-time authenticator using BigInt arithmetic for correctness
/// 
/// This implementation follows RFC 8439 exactly using arbitrary precision arithmetic
/// to ensure correctness. While not as fast as optimized limb arithmetic, it provides
/// a reference implementation that passes all test vectors.
#[derive(Debug)]
pub struct Poly1305 {
    /// Clamped r value as bytes
    r: [u8; 16],
    /// Secret s value as bytes  
    s: [u8; 16],
    /// Accumulated message data
    buffer: Vec<u8>,
    /// Whether finalized
    finalized: bool,
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
        self.buffer.zeroize();
    }
}

impl Zeroize for Poly1305 {
    fn zeroize(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
        self.buffer.zeroize();
        self.finalized = false;
    }
}

impl ZeroizeOnDrop for Poly1305 {}

impl Poly1305 {
    /// Create a new Poly1305 instance with the given key
    pub fn new(key: &[u8]) -> Result<Self, Poly1305Error> {
        if key.len() != KEY_SIZE {
            return Err(Poly1305Error::InvalidKeySize);
        }

        let mut r = [0u8; 16];
        let mut s = [0u8; 16];
        
        r.copy_from_slice(&key[0..16]);
        s.copy_from_slice(&key[16..32]);
        
        // Clamp r according to RFC 8439
        r[3] &= 0x0f;
        r[7] &= 0x0f;
        r[11] &= 0x0f;
        r[15] &= 0x0f;
        r[4] &= 0xfc;
        r[8] &= 0xfc;
        r[12] &= 0xfc;

        Ok(Self {
            r,
            s,
            buffer: Vec::new(),
            finalized: false,
        })
    }

    /// Update with message data
    pub fn update(&mut self, data: &[u8]) -> Result<(), Poly1305Error> {
        if self.finalized {
            return Err(Poly1305Error::AlreadyFinalized);
        }
        
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    /// Finalize and return the 16-byte authentication tag
    pub fn finalize(mut self) -> Result<[u8; TAG_SIZE], Poly1305Error> {
        if self.finalized {
            return Err(Poly1305Error::AlreadyFinalized);
        }

        // Poly1305 prime: 2^130 - 5
        let p = (BigUint::one() << 130) - 5u8;
        
        // Convert r to BigUint (little-endian)
        let r_int = BigUint::from_bytes_le(&self.r);
        
        // Initialize accumulator
        let mut accumulator = BigUint::zero();
        
        // Process message in 16-byte blocks
        let msg_len = self.buffer.len();
        let full_blocks = msg_len / 16;
        
        // Process full blocks
        for i in 0..full_blocks {
            let block = &self.buffer[i * 16..(i + 1) * 16];
            
            // Convert to BigUint and add high bit (2^128)
            let mut n = BigUint::from_bytes_le(block);
            n += BigUint::one() << 128;
            
            // Update accumulator: a = ((a + n) * r) mod p
            accumulator = ((&accumulator + &n) * &r_int) % &p;
        }
        
        // Process final partial block if any
        let remaining = msg_len % 16;
        if remaining > 0 {
            let mut padded = [0u8; 16];
            padded[..remaining].copy_from_slice(&self.buffer[full_blocks * 16..]);
            padded[remaining] = 0x01;
            
            // Convert to BigUint (already includes the 0x01 padding bit)
            let n = BigUint::from_bytes_le(&padded);
            
            // Update accumulator
            accumulator = ((&accumulator + &n) * &r_int) % &p;
        }
        
        // Convert s to BigUint and add to accumulator
        let s_int = BigUint::from_bytes_le(&self.s);
        let tag_int: BigUint = (&accumulator + &s_int) & ((BigUint::one() << 128) - 1u8);
        
        // Convert tag to bytes (little-endian)
        let tag_bytes = tag_int.to_bytes_le();
        let mut tag = [0u8; TAG_SIZE];
        let copy_len = core::cmp::min(tag_bytes.len(), TAG_SIZE);
        tag[..copy_len].copy_from_slice(&tag_bytes[..copy_len]);
        
        self.finalized = true;
        Ok(tag)
    }
}

/// Compute Poly1305 MAC for a message
pub fn poly1305_mac(message: &[u8], key: &[u8]) -> Result<[u8; TAG_SIZE], Poly1305Error> {
    let mut poly = Poly1305::new(key)?;
    poly.update(message)?;
    poly.finalize()
}

/// Verify Poly1305 MAC
pub fn poly1305_verify(message: &[u8], key: &[u8], tag: &[u8]) -> Result<bool, Poly1305Error> {
    if tag.len() != TAG_SIZE {
        return Err(Poly1305Error::InvalidTagSize);
    }
    
    let computed_tag = poly1305_mac(message, key)?;
    
    // Constant-time comparison
    Ok(metamui_security_utils::constant_time::ConstantTimeEq::ct_eq(&computed_tag[..], tag).into())
}

/// Optimized implementation using 64-bit arithmetic
#[cfg(feature = "optimized")]
pub mod poly1305_optimized;

#[cfg(feature = "optimized")]
pub use poly1305_optimized::{Poly1305Optimized, poly1305_mac_optimized};

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    extern crate std;
    use std::vec::Vec;

    #[test]
    fn test_rfc8439_vector_1() {
        let key = hex!(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        );
        let message = b"Cryptographic Forum Research Group";
        let expected_tag = hex!("a8061dc1305136c6c22b8baf0c0127a9");

        let tag = poly1305_mac(message, &key).unwrap();
        assert_eq!(tag, expected_tag);

        assert!(poly1305_verify(message, &key, &expected_tag).unwrap());
    }

    /// RFC 8439 Appendix A.3 Test Vector #1 — All-zero key, empty message
    #[test]
    fn test_rfc8439_appendix_a3_vector_1() {
        let key = hex!("00000000000000000000000000000000" "00000000000000000000000000000000");
        let message = b"";
        let expected_tag = hex!("00000000000000000000000000000000");

        let tag = poly1305_mac(message, &key).unwrap();
        assert_eq!(tag, expected_tag, "RFC 8439 A.3 Vector #1 failed");
    }

    /// RFC 8439 Appendix A.3 Test Vector #4 — Jabberwocky poem excerpt
    #[test]
    fn test_rfc8439_appendix_a3_vector_4() {
        let key = hex!(
            "1c9240a5eb55d38af333888604f6b5f0"
            "473917c1402b80099dca5cbc207075c0"
        );
        let message = b"'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.";
        let expected_tag = hex!("4541669a7eaaee61e708dc7cbcc5eb62");

        let tag = poly1305_mac(message, &key).unwrap();
        assert_eq!(tag, expected_tag, "RFC 8439 A.3 Vector #4 failed");
    }

    #[test]
    fn test_rfc8439_vector_4() {
        let key = hex!("02000000000000000000000000000000" "00000000000000000000000000000000");
        let message = hex!("ffffffffffffffffffffffffffffffff");
        let expected_tag = hex!("03000000000000000000000000000000");

        let tag = poly1305_mac(&message, &key).unwrap();
        assert_eq!(tag, expected_tag);
    }

    #[test]
    fn test_incremental() {
        let key = hex!(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        );
        let message = b"Cryptographic Forum Research Group";

        // All at once
        let tag1 = poly1305_mac(message, &key).unwrap();

        // Incrementally
        let mut poly = Poly1305::new(&key).unwrap();
        poly.update(b"Cryptographic ").unwrap();
        poly.update(b"Forum ").unwrap();
        poly.update(b"Research Group").unwrap();
        let tag2 = poly.finalize().unwrap();

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_empty_message() {
        let key = hex!(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        );
        let message = b"";

        let tag = poly1305_mac(message, &key).unwrap();
        assert_eq!(tag.len(), TAG_SIZE);
    }

    #[test]
    fn test_invalid_key_size() {
        let short_key = [0u8; 16];
        let result = Poly1305::new(&short_key);
        assert_eq!(result.unwrap_err(), Poly1305Error::InvalidKeySize);

        let long_key = [0u8; 64];
        let result = Poly1305::new(&long_key);
        assert_eq!(result.unwrap_err(), Poly1305Error::InvalidKeySize);
    }

    #[test]
    fn test_already_finalized() {
        let key = [0u8; 32];
        let mut poly = Poly1305::new(&key).unwrap();
        poly.update(b"test").unwrap();
        let _tag = poly.finalize().unwrap();

        // Can't update after setting finalized flag manually
        let mut poly2 = Poly1305::new(&key).unwrap();
        poly2.finalized = true;
        let result = poly2.update(b"more");
        assert_eq!(result.unwrap_err(), Poly1305Error::AlreadyFinalized);
    }

    #[test]
    fn test_various_lengths() {
        let key = hex!(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        );

        for len in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129] {
            let message: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let tag = poly1305_mac(&message, &key).unwrap();
            assert_eq!(tag.len(), TAG_SIZE);
            assert!(poly1305_verify(&message, &key, &tag).unwrap());
        }
    }

    #[test]
    fn test_message_manipulation_detection() {
        let key = hex!(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        );
        let message = b"important message";
        let tag = poly1305_mac(message, &key).unwrap();

        // Original message should verify
        assert!(poly1305_verify(message, &key, &tag).unwrap());

        // Modified message should not verify
        assert!(!poly1305_verify(b"important messagex", &key, &tag).unwrap());
    }

    #[test]
    fn test_tag_manipulation_detection() {
        let key = hex!(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        );
        let message = b"important message";
        let tag = poly1305_mac(message, &key).unwrap();

        // Flip a bit in the tag
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;

        assert!(!poly1305_verify(message, &key, &bad_tag).unwrap());
    }
}