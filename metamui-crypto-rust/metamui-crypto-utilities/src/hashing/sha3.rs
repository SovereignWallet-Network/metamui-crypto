// MetaMUI metamui crypto utilities - SHA3
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! SHA3-256, SHA3-384, and SHA3-512 implementations
//! 
//! Provides NIST FIPS 202 compliant SHA3 hash functions using the Keccak sponge construction.
//! 
//! This implementation provides:
//! - SHA3-256: 256-bit output, 1088-bit rate
//! - SHA3-384: 384-bit output, 832-bit rate  
//! - SHA3-512: 512-bit output, 576-bit rate
//!
//! All functions use the SHA3 domain separator (0x06) and proper padding.

use super::keccak::keccak_f;


/// SHA3-256 hasher
pub struct Sha3_256 {
    state: [u64; 25],
    buffer: [u8; Self::RATE],
    buffer_len: usize,
    finalized: bool,
}

impl Sha3_256 {
    /// Rate for SHA3-256 (1088 bits = 136 bytes)
    const RATE: usize = 136;
    
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
    pub fn update(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if self.finalized {
            return Err("Cannot update after finalization");
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
    const RATE: usize = 104;
    
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
    pub fn update(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if self.finalized {
            return Err("Cannot update after finalization");
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
    const RATE: usize = 72;
    
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
    pub fn update(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if self.finalized {
            return Err("Cannot update after finalization");
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

/// Convenience function for SHA3-256
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data).expect("Update should not fail on new hasher");
    hasher.finalize()
}

/// Convenience function for SHA3-384
pub fn sha3_384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha3_384::new();
    hasher.update(data).expect("Update should not fail on new hasher");
    hasher.finalize()
}

/// Convenience function for SHA3-512
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(data).expect("Update should not fail on new hasher");
    hasher.finalize()
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

/// Digest trait implementation for compatibility
pub mod digest {
    use super::*;
    
    /// Trait for cryptographic hash functions
    pub trait Digest {
        /// The output type of the hash function
        type Output;
        
        /// Create a new hasher instance
        fn new() -> Self;
        /// Update the hasher with data
        fn update(&mut self, data: &[u8]);
        /// Finalize the hash and return the result
        fn finalize(self) -> Self::Output;
    }
    
    /// Trait for hash functions with fixed output size
    pub trait FixedOutput {
        /// The size of the output
        type OutputSize;
    }
    
    /// Trait for updating hash state
    pub trait Update {
        /// Update the hasher with data
        fn update(&mut self, data: &[u8]);
    }
    
    impl Digest for Sha3_256 {
        type Output = [u8; 32];
        
        fn new() -> Self {
            Self::new()
        }
        
        fn update(&mut self, data: &[u8]) {
            self.update(data).expect("Update should not fail");
        }
        
        fn finalize(self) -> Self::Output {
            self.finalize()
        }
    }
    
    impl Digest for Sha3_384 {
        type Output = [u8; 48];
        
        fn new() -> Self {
            Self::new()
        }
        
        fn update(&mut self, data: &[u8]) {
            self.update(data).expect("Update should not fail");
        }
        
        fn finalize(self) -> Self::Output {
            self.finalize()
        }
    }
    
    impl Digest for Sha3_512 {
        type Output = [u8; 64];
        
        fn new() -> Self {
            Self::new()
        }
        
        fn update(&mut self, data: &[u8]) {
            self.update(data).expect("Update should not fail");
        }
        
        fn finalize(self) -> Self::Output {
            self.finalize()
        }
    }
    
    impl Update for Sha3_256 {
        fn update(&mut self, data: &[u8]) {
            self.update(data).expect("Update should not fail");
        }
    }
    
    impl Update for Sha3_384 {
        fn update(&mut self, data: &[u8]) {
            self.update(data).expect("Update should not fail");
        }
    }
    
    impl Update for Sha3_512 {
        fn update(&mut self, data: &[u8]) {
            self.update(data).expect("Update should not fail");
        }
    }
    
    impl FixedOutput for Sha3_256 {
        type OutputSize = [u8; 32];
    }
    
    impl FixedOutput for Sha3_384 {
        type OutputSize = [u8; 48];
    }
    
    impl FixedOutput for Sha3_512 {
        type OutputSize = [u8; 64];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sha3_256_empty() {
        let hash = sha3_256(b"");
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
        let hash = sha3_384(b"");
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
        let hash = sha3_512(b"");
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
        let hash = sha3_256(b"abc");
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
        let hash = sha3_384(b"abc");
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
        let hash = sha3_512(b"abc");
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
        
        let output2 = sha3_256(combined);
        assert_eq!(output1, output2);
        
        // Test SHA3-384
        let mut hasher3 = Sha3_384::new();
        hasher3.update(data1).unwrap();
        hasher3.update(data2).unwrap();
        let output3 = hasher3.finalize();
        
        let output4 = sha3_384(combined);
        assert_eq!(output3, output4);
        
        // Test SHA3-512
        let mut hasher5 = Sha3_512::new();
        hasher5.update(data1).unwrap();
        hasher5.update(data2).unwrap();
        let output5 = hasher5.finalize();
        
        let output6 = sha3_512(combined);
        assert_eq!(output5, output6);
    }

    #[test]
    fn test_large_input() {
        let large_input = vec![42u8; 10000];
        
        // Should not panic and produce consistent results
        let hash1 = sha3_256(&large_input);
        let hash2 = sha3_256(&large_input);
        assert_eq!(hash1, hash2);
        
        let hash3 = sha3_384(&large_input);
        let hash4 = sha3_384(&large_input);
        assert_eq!(hash3, hash4);
        
        let hash5 = sha3_512(&large_input);
        let hash6 = sha3_512(&large_input);
        assert_eq!(hash5, hash6);
    }
}