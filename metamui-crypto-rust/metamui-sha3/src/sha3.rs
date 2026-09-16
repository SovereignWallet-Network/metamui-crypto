// MetaMUI metamui sha3 - SHA3 implementations
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! SHA3-224, SHA3-256, SHA3-384, and SHA3-512 implementations
//! 
//! Provides NIST FIPS 202 compliant SHA3 hash functions using the Keccak sponge construction.
//! 
//! This implementation provides:
//! - SHA3-224: 224-bit output, 1152-bit rate (FIPS 204/205 pre-hash table only)
//! - SHA3-256: 256-bit output, 1088-bit rate
//! - SHA3-384: 384-bit output, 832-bit rate  
//! - SHA3-512: 512-bit output, 576-bit rate
//!
//! All functions use the SHA3 domain separator (0x06) and proper padding.

use crate::keccak::keccak_f;
use metamui_security_utils::Zeroize;

/// SHA3 Error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sha3Error {
    /// Cannot update after finalization
    AlreadyFinalized,
}

#[cfg(feature = "std")]
impl std::fmt::Display for Sha3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sha3Error::AlreadyFinalized => write!(f, "Cannot update after finalization"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Sha3Error {}

/// SHA3-224 hasher
pub struct Sha3_224 {
    state: [u64; 25],
    buffer: [u8; Self::RATE],
    buffer_len: usize,
    finalized: bool,
}

impl Sha3_224 {
    /// Rate for SHA3-224 (1152 bits = 144 bytes)
    pub const RATE: usize = 144;
    
    /// Create a new SHA3-224 hasher
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; Self::RATE],
            buffer_len: 0,
            finalized: false,
        }
    }
    
    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) -> Result<(), Sha3Error> {
        if self.finalized {
            return Err(Sha3Error::AlreadyFinalized);
        }

        let mut offset = 0;
        while offset < data.len() {
            let remaining = Self::RATE - self.buffer_len;
            let copy_len = core::cmp::min(remaining, data.len() - offset);
            
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[offset..offset + copy_len]);
            self.buffer_len += copy_len;
            offset += copy_len;
            
            if self.buffer_len == Self::RATE {
                self.absorb();
                self.buffer_len = 0;
            }
        }

        Ok(())
    }
    
    /// Finalize and return the hash
    pub fn finalize(mut self) -> [u8; 28] {
        if !self.finalized {
            // Apply SHA3 padding: append 0x06, pad with zeros, append 0x80
            self.buffer[self.buffer_len] = 0x06;
            self.buffer_len += 1;
            
            // Fill remaining buffer with zeros
            while self.buffer_len < Self::RATE {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            
            // Set the last bit for 10*1 padding
            self.buffer[Self::RATE - 1] |= 0x80;
            
            self.absorb();
            self.finalized = true;
        }
        
        // Squeeze output
        let mut output = [0u8; 28];
        for (i, byte) in output.iter_mut().enumerate() {
            let word_idx = i / 8;
            let byte_idx = i % 8;
            *byte = ((self.state[word_idx] >> (byte_idx * 8)) & 0xFF) as u8;
        }
        
        output
    }

    /// Static method to hash data with fixed output length
    pub fn hash(data: &[u8]) -> [u8; 28] {
        let mut hasher = Self::new();
        hasher.update(data).expect("Update should not fail on new hasher");
        hasher.finalize()
    }

    /// Absorb buffer data into the Keccak state
    fn absorb(&mut self) {
        // Convert buffer to 64-bit words and XOR with state (little-endian)
        for i in 0..Self::RATE / 8 {
            let mut word = 0u64;
            for j in 0..8 {
                word |= (self.buffer[i * 8 + j] as u64) << (j * 8);
            }
            self.state[i] ^= word;
        }
        
        keccak_f(&mut self.state);
    }
}

/// SHA3-256 hasher
pub struct Sha3_256 {
    state: [u64; 25],
    buffer: [u8; Self::RATE],
    buffer_len: usize,
    finalized: bool,
}

impl Sha3_256 {
    /// Rate for SHA3-256 (1088 bits = 136 bytes)
    pub const RATE: usize = 136;
    
    /// Create a new SHA3-256 hasher
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; Self::RATE],
            buffer_len: 0,
            finalized: false,
        }
    }
    
    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) -> Result<(), Sha3Error> {
        if self.finalized {
            return Err(Sha3Error::AlreadyFinalized);
        }

        let mut offset = 0;
        while offset < data.len() {
            let remaining = Self::RATE - self.buffer_len;
            let copy_len = core::cmp::min(remaining, data.len() - offset);
            
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[offset..offset + copy_len]);
            self.buffer_len += copy_len;
            offset += copy_len;
            
            if self.buffer_len == Self::RATE {
                self.absorb();
                self.buffer_len = 0;
            }
        }

        Ok(())
    }
    
    /// Finalize and return the hash
    pub fn finalize(mut self) -> [u8; 32] {
        if !self.finalized {
            // Apply SHA3 padding: append 0x06, pad with zeros, append 0x80
            self.buffer[self.buffer_len] = 0x06;
            self.buffer_len += 1;
            
            // Fill remaining buffer with zeros
            while self.buffer_len < Self::RATE {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            
            // Set the last bit for 10*1 padding
            self.buffer[Self::RATE - 1] |= 0x80;
            
            self.absorb();
            self.finalized = true;
        }
        
        // Squeeze output
        let mut output = [0u8; 32];
        for (i, byte) in output.iter_mut().enumerate() {
            let word_idx = i / 8;
            let byte_idx = i % 8;
            *byte = ((self.state[word_idx] >> (byte_idx * 8)) & 0xFF) as u8;
        }
        
        output
    }

    /// Static method to hash data with fixed output length
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data).expect("Update should not fail on new hasher");
        hasher.finalize()
    }

    /// Absorb buffer data into the Keccak state
    fn absorb(&mut self) {
        // Convert buffer to 64-bit words and XOR with state (little-endian)
        for i in 0..Self::RATE / 8 {
            let mut word = 0u64;
            for j in 0..8 {
                word |= (self.buffer[i * 8 + j] as u64) << (j * 8);
            }
            self.state[i] ^= word;
        }
        
        keccak_f(&mut self.state);
    }
}

/// SHA3-384 hasher
pub struct Sha3_384 {
    state: [u64; 25],
    buffer: [u8; Self::RATE],
    buffer_len: usize,
    finalized: bool,
}

impl Sha3_384 {
    /// Rate for SHA3-384 (832 bits = 104 bytes)
    pub const RATE: usize = 104;
    
    /// Create a new SHA3-384 hasher
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; Self::RATE],
            buffer_len: 0,
            finalized: false,
        }
    }
    
    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) -> Result<(), Sha3Error> {
        if self.finalized {
            return Err(Sha3Error::AlreadyFinalized);
        }

        let mut offset = 0;
        while offset < data.len() {
            let remaining = Self::RATE - self.buffer_len;
            let copy_len = core::cmp::min(remaining, data.len() - offset);
            
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[offset..offset + copy_len]);
            self.buffer_len += copy_len;
            offset += copy_len;
            
            if self.buffer_len == Self::RATE {
                self.absorb();
                self.buffer_len = 0;
            }
        }

        Ok(())
    }
    
    /// Finalize and return the hash
    pub fn finalize(mut self) -> [u8; 48] {
        if !self.finalized {
            // Apply SHA3 padding: append 0x06, pad with zeros, append 0x80
            self.buffer[self.buffer_len] = 0x06;
            self.buffer_len += 1;
            
            // Fill remaining buffer with zeros
            while self.buffer_len < Self::RATE {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            
            // Set the last bit for 10*1 padding
            self.buffer[Self::RATE - 1] |= 0x80;
            
            self.absorb();
            self.finalized = true;
        }
        
        // Squeeze output
        let mut output = [0u8; 48];
        for (i, byte) in output.iter_mut().enumerate() {
            let word_idx = i / 8;
            let byte_idx = i % 8;
            *byte = ((self.state[word_idx] >> (byte_idx * 8)) & 0xFF) as u8;
        }
        
        output
    }

    /// Static method to hash data with fixed output length
    pub fn hash(data: &[u8]) -> [u8; 48] {
        let mut hasher = Self::new();
        hasher.update(data).expect("Update should not fail on new hasher");
        hasher.finalize()
    }

    /// Absorb buffer data into the Keccak state
    fn absorb(&mut self) {
        // Convert buffer to 64-bit words and XOR with state (little-endian)
        for i in 0..Self::RATE / 8 {
            let mut word = 0u64;
            for j in 0..8 {
                word |= (self.buffer[i * 8 + j] as u64) << (j * 8);
            }
            self.state[i] ^= word;
        }
        
        keccak_f(&mut self.state);
    }
}

/// SHA3-512 hasher
pub struct Sha3_512 {
    state: [u64; 25],
    buffer: [u8; Self::RATE],
    buffer_len: usize,
    finalized: bool,
}

impl Sha3_512 {
    /// Rate for SHA3-512 (576 bits = 72 bytes)
    pub const RATE: usize = 72;
    
    /// Create a new SHA3-512 hasher
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; Self::RATE],
            buffer_len: 0,
            finalized: false,
        }
    }
    
    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) -> Result<(), Sha3Error> {
        if self.finalized {
            return Err(Sha3Error::AlreadyFinalized);
        }

        let mut offset = 0;
        while offset < data.len() {
            let remaining = Self::RATE - self.buffer_len;
            let copy_len = core::cmp::min(remaining, data.len() - offset);
            
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[offset..offset + copy_len]);
            self.buffer_len += copy_len;
            offset += copy_len;
            
            if self.buffer_len == Self::RATE {
                self.absorb();
                self.buffer_len = 0;
            }
        }

        Ok(())
    }
    
    /// Finalize and return the hash
    pub fn finalize(mut self) -> [u8; 64] {
        if !self.finalized {
            // Apply SHA3 padding: append 0x06, pad with zeros, append 0x80
            self.buffer[self.buffer_len] = 0x06;
            self.buffer_len += 1;
            
            // Fill remaining buffer with zeros
            while self.buffer_len < Self::RATE {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            
            // Set the last bit for 10*1 padding
            self.buffer[Self::RATE - 1] |= 0x80;
            
            self.absorb();
            self.finalized = true;
        }
        
        // Squeeze output
        let mut output = [0u8; 64];
        for (i, byte) in output.iter_mut().enumerate() {
            let word_idx = i / 8;
            let byte_idx = i % 8;
            *byte = ((self.state[word_idx] >> (byte_idx * 8)) & 0xFF) as u8;
        }
        
        output
    }

    /// Static method to hash data with fixed output length
    pub fn hash(data: &[u8]) -> [u8; 64] {
        let mut hasher = Self::new();
        hasher.update(data).expect("Update should not fail on new hasher");
        hasher.finalize()
    }

    /// Absorb buffer data into the Keccak state
    fn absorb(&mut self) {
        // Convert buffer to 64-bit words and XOR with state (little-endian)
        for i in 0..Self::RATE / 8 {
            let mut word = 0u64;
            for j in 0..8 {
                word |= (self.buffer[i * 8 + j] as u64) << (j * 8);
            }
            self.state[i] ^= word;
        }
        
        keccak_f(&mut self.state);
    }
}

impl Default for Sha3_224 {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Sha3_384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Sha3_512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for Sha3_224 {
    fn zeroize(&mut self) {
        for i in 0..self.state.len() {
            self.state[i] = 0;
        }
        for i in 0..self.buffer.len() {
            self.buffer[i] = 0;
        }
        self.buffer_len = 0;
        self.finalized = false;
    }
}

impl Drop for Sha3_224 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for Sha3_256 {
    fn zeroize(&mut self) {
        for i in 0..self.state.len() {
            self.state[i] = 0;
        }
        for i in 0..self.buffer.len() {
            self.buffer[i] = 0;
        }
        self.buffer_len = 0;
        self.finalized = false;
    }
}

impl Drop for Sha3_256 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for Sha3_384 {
    fn zeroize(&mut self) {
        for i in 0..self.state.len() {
            self.state[i] = 0;
        }
        for i in 0..self.buffer.len() {
            self.buffer[i] = 0;
        }
        self.buffer_len = 0;
        self.finalized = false;
    }
}

impl Drop for Sha3_384 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for Sha3_512 {
    fn zeroize(&mut self) {
        for i in 0..self.state.len() {
            self.state[i] = 0;
        }
        for i in 0..self.buffer.len() {
            self.buffer[i] = 0;
        }
        self.buffer_len = 0;
        self.finalized = false;
    }
}

impl Drop for Sha3_512 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex28(s: &str) -> [u8; 28] {
        let mut out = [0u8; 28];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    // FIPS 202 examples (NIST CSRC "SHA3-224 examples"), cross-checked
    // against Python's hashlib.
    #[test]
    fn sha3_224_known_answers() {
        assert_eq!(
            Sha3_224::hash(b""),
            unhex28("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7")
        );
        assert_eq!(
            Sha3_224::hash(b"abc"),
            unhex28("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")
        );
        assert_eq!(
            Sha3_224::hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            unhex28("8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33")
        );
        assert_eq!(
            Sha3_224::hash(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
            unhex28("543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc")
        );
        // Streaming across the 144-byte rate boundary equals one-shot.
        let msg = [0x5au8; 300];
        let mut streamed = Sha3_224::new();
        for chunk in msg.chunks(29) {
            streamed.update(chunk).unwrap();
        }
        assert_eq!(streamed.finalize(), Sha3_224::hash(&msg));
    }
    
    #[test]
    fn test_sha3_256_empty() {
        let hash = Sha3_256::hash(b"");
        let expected = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
        ];
        assert_eq!(hash, expected);
    }
    
    #[test]
    fn test_sha3_384_empty() {
        let hash = Sha3_384::hash(b"");
        let expected = [
            0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d,
            0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c, 0x24, 0x85,
            0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61,
            0x99, 0x5e, 0x71, 0xbb, 0xee, 0x98, 0x3a, 0x2a,
            0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47,
            0xfb, 0x6b, 0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04
        ];
        assert_eq!(hash, expected);
    }
    
    #[test]
    fn test_sha3_512_empty() {
        let hash = Sha3_512::hash(b"");
        let expected = [
            0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
            0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
            0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
            0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
            0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
            0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
            0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
            0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26
        ];
        assert_eq!(hash, expected);
    }
    
    #[test]
    fn test_sha3_256_abc() {
        let hash = Sha3_256::hash(b"abc");
        let expected = [
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
            0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
            0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
        ];
        assert_eq!(hash, expected);
    }
    
    #[test]
    fn test_sha3_384_abc() {
        let hash = Sha3_384::hash(b"abc");
        let expected = [
            0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9,
            0x26, 0x45, 0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d,
            0xf9, 0xb4, 0x73, 0xcb, 0x0f, 0xc0, 0x8c, 0x25,
            0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b, 0xe4, 0xb2,
            0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5,
            0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25
        ];
        assert_eq!(hash, expected);
    }
    
    #[test]
    fn test_sha3_512_abc() {
        let hash = Sha3_512::hash(b"abc");
        let expected = [
            0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a,
            0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
            0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d,
            0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
            0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
            0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
            0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
            0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_incremental_updates() {
        let data1 = b"Hello, ";
        let data2 = b"World!";
        let combined = b"Hello, World!";
        
        // Test SHA3-256
        let mut hasher1 = Sha3_256::new();
        hasher1.update(data1).unwrap();
        hasher1.update(data2).unwrap();
        let output1 = hasher1.finalize();
        
        let output2 = Sha3_256::hash(combined);
        assert_eq!(output1, output2);
        
        // Test SHA3-384
        let mut hasher3 = Sha3_384::new();
        hasher3.update(data1).unwrap();
        hasher3.update(data2).unwrap();
        let output3 = hasher3.finalize();
        
        let output4 = Sha3_384::hash(combined);
        assert_eq!(output3, output4);
        
        // Test SHA3-512
        let mut hasher5 = Sha3_512::new();
        hasher5.update(data1).unwrap();
        hasher5.update(data2).unwrap();
        let output5 = hasher5.finalize();
        
        let output6 = Sha3_512::hash(combined);
        assert_eq!(output5, output6);
    }

    #[test]
    fn test_large_input() {
        let large_input = vec![42u8; 10000];
        
        // Should not panic and produce consistent results
        let hash1 = Sha3_256::hash(&large_input);
        let hash2 = Sha3_256::hash(&large_input);
        assert_eq!(hash1, hash2);
        
        let hash3 = Sha3_384::hash(&large_input);
        let hash4 = Sha3_384::hash(&large_input);
        assert_eq!(hash3, hash4);
        
        let hash5 = Sha3_512::hash(&large_input);
        let hash6 = Sha3_512::hash(&large_input);
        assert_eq!(hash5, hash6);
    }

    #[test]
    fn test_error_handling() {
        let mut hasher = Sha3_256::new();
        hasher.update(b"test").unwrap();
        let _hash = hasher.finalize();
        
        // Cannot create a new hasher from the consumed one, but we can test the error case differently
        let mut hasher2 = Sha3_256::new();
        hasher2.finalized = true; // Manually set to test error
        let result = hasher2.update(b"more data");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Sha3Error::AlreadyFinalized);
    }

    #[test]
    fn test_convenience_functions() {
        let input = b"test input";
        
        let hash1 = Sha3_256::hash(input);
        let hash2 = crate::sha3_256(input);
        assert_eq!(hash1, hash2);
        
        let hash3 = Sha3_384::hash(input);
        let hash4 = crate::sha3_384(input);
        assert_eq!(hash3, hash4);
        
        let hash5 = Sha3_512::hash(input);
        let hash6 = crate::sha3_512(input);
        assert_eq!(hash5, hash6);
    }
}
// ============================================================================
// Bit-oriented input (FIPS 202 §B.2 / NIST ACVP bit-oriented AFT)
// ============================================================================
//
// FIPS 202 defines SHA-3 over bit strings of any length; the byte-oriented
// `update`/`finalize` pair above covers only multiples of 8. NIST's ACVP
// SHA3 vectors (`test-vectors/sha-3/sha3-*-acvp.json`) are almost entirely
// bit-oriented, so the crate exposes the trailing partial byte explicitly.
//
// Convention for the partial byte: FIPS 202 Appendix B.1 (`h2b`) — message
// bit `i` of the partial byte is bit `i` of the byte, i.e. the `bits` valid
// bits occupy the LOW positions and are read least-significant first. This
// is the NIST hex notation in which the 5-bit message `11001` is written
// `0x13`. Callers holding an MSB-first (top-aligned) bit string shift it
// down by `8 - bits` first.
//
// Padding (`pad10*1` after the `01` domain suffix): the partial bits, the
// suffix `01` and the leading pad `1` are packed into a 16-bit value and
// written low byte first. If the leading pad `1` landed on bit 7 of the
// block's last byte, the block is full and the closing `1` (0x80) needs a
// fresh, otherwise all-zero block; if it did not, the closing `1` shares
// that byte exactly as in the byte-aligned case.
macro_rules! impl_sha3_bit_input {
    ($ty:ident, $out:expr) => {
        impl $ty {
            /// SHA-3 domain suffix `01` followed by the leading `pad10*1` bit,
            /// LSB-first: `0b110` = 0x06 — the same byte the byte-aligned
            /// `finalize` appends.
            const SUFFIX_WITH_PAD: u16 = 0x06;
            /// Number of bits in `SUFFIX_WITH_PAD` (suffix `01` + pad `1`).
            const SUFFIX_WITH_PAD_BITS: usize = 3;

            /// Finalize with a trailing partial byte holding `bits` (0..=7)
            /// message bits in its low positions (FIPS 202 `h2b` order).
            ///
            /// `bits == 0` is identical to [`finalize`](Self::finalize).
            ///
            /// # Panics
            /// If `bits >= 8` or the hasher was already finalized.
            pub fn finalize_bits(mut self, partial: u8, bits: usize) -> [u8; $out] {
                assert!(bits < 8, "partial byte holds at most 7 bits, got {bits}");
                assert!(!self.finalized, "cannot finalize_bits an already finalized hasher");
                self.absorb_partial_and_pad(partial, bits);
                self.finalize()
            }

            /// One-shot hash of the first `bit_len` bits of `data`.
            ///
            /// Whole bytes are consumed in order; a trailing partial byte is
            /// interpreted per [`finalize_bits`](Self::finalize_bits) (valid
            /// bits in the low positions).
            ///
            /// # Panics
            /// If `data` holds fewer than `bit_len` bits.
            pub fn hash_bits(data: &[u8], bit_len: usize) -> [u8; $out] {
                assert!(
                    bit_len <= data.len() * 8,
                    "bit_len {bit_len} exceeds the {} bits supplied",
                    data.len() * 8
                );
                let full = bit_len / 8;
                let rem = bit_len % 8;
                let mut hasher = Self::new();
                hasher
                    .update(&data[..full])
                    .expect("fresh hasher cannot be finalized");
                let partial = if rem > 0 { data[full] } else { 0 };
                hasher.finalize_bits(partial, rem)
            }

            fn absorb_partial_and_pad(&mut self, partial: u8, bits: usize) {
                let mask: u16 = (1u16 << bits) - 1;
                let v: u16 = ((partial as u16) & mask) | (Self::SUFFIX_WITH_PAD << bits);
                // Bits consumed by partial ‖ suffix ‖ leading pad-1.
                let nb = bits + Self::SUFFIX_WITH_PAD_BITS;

                self.buffer[self.buffer_len] = (v & 0xFF) as u8;
                self.buffer_len += 1;
                if nb > 8 {
                    if self.buffer_len == Self::RATE {
                        self.absorb();
                        self.buffer_len = 0;
                    }
                    self.buffer[self.buffer_len] = (v >> 8) as u8;
                    self.buffer_len += 1;
                }
                // The leading pad-1 sits on bit 7 of the last written byte iff
                // nb % 8 == 0; if that byte also closed the block, the closing
                // 1 must open a new block.
                if self.buffer_len == Self::RATE && nb % 8 == 0 {
                    self.absorb();
                    self.buffer_len = 0;
                }
                while self.buffer_len < Self::RATE {
                    self.buffer[self.buffer_len] = 0;
                    self.buffer_len += 1;
                }
                self.buffer[Self::RATE - 1] |= 0x80;
                self.absorb();
                self.finalized = true;
            }
        }
    };
}

impl_sha3_bit_input!(Sha3_224, 28);
impl_sha3_bit_input!(Sha3_256, 32);
impl_sha3_bit_input!(Sha3_384, 48);
impl_sha3_bit_input!(Sha3_512, 64);
