//! Keccak-256 - Ethereum-compatible hash function
//!
//! This is the original Keccak-256 algorithm, NOT SHA3-256.
//! Ethereum and other systems use this original version before NIST standardization.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, format};

#[cfg(feature = "std")]
use std::{string::String, format};

use core::convert::TryInto;

/// Keccak-256 output size in bytes
pub const HASH_SIZE: usize = 32;

/// Keccak-256 block size in bytes
pub const BLOCK_SIZE: usize = 136; // 1088 bits / 8

/// Number of rounds in Keccak-f[1600]
const ROUNDS: usize = 24;

/// Keccak round constants
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Rotation offsets for rho step
const ROTATION_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
    41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Keccak-256 hasher state
pub struct Keccak256 {
    state: [u64; 25],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Keccak256 {
    /// Create new Keccak-256 hasher
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
        }
    }

    /// Update hasher with data
    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;
        
        // Process buffered data
        if self.buffer_len > 0 {
            let to_copy = (BLOCK_SIZE - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            data = &data[to_copy..];
            
            if self.buffer_len == BLOCK_SIZE {
                let current_buffer = self.buffer;
                self.absorb_block(&current_buffer);
                self.buffer_len = 0;
            }
        }
        
        // Process full blocks
        while data.len() >= BLOCK_SIZE {
            self.absorb_block(&data[..BLOCK_SIZE]);
            data = &data[BLOCK_SIZE..];
        }
        
        // Buffer remaining bytes
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalize and return hash
    pub fn finalize(mut self) -> [u8; HASH_SIZE] {
        // Apply Keccak padding (different from SHA3!)
        // Keccak uses: 0x01 ... 0x80
        // SHA3 uses: 0x06 ... 0x80
        self.buffer[self.buffer_len] = 0x01; // This is the key difference!
        
        // Fill with zeros
        for i in self.buffer_len + 1..BLOCK_SIZE {
            self.buffer[i] = 0;
        }
        
        // Set last bit
        self.buffer[BLOCK_SIZE - 1] |= 0x80;
        
        // Absorb final block
        let final_buffer = self.buffer;
        self.absorb_block(&final_buffer);
        
        // Extract output
        let mut output = [0u8; HASH_SIZE];
        for i in 0..4 {
            output[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_le_bytes());
        }
        
        output
    }

    /// Absorb a block into the state
    fn absorb_block(&mut self, block: &[u8]) {
        // XOR block into state
        for i in 0..17 {
            self.state[i] ^= u64::from_le_bytes(
                block[i * 8..(i + 1) * 8].try_into().unwrap()
            );
        }
        
        // Apply Keccak-f[1600] permutation
        keccak_f(&mut self.state);
    }
}

/// Apply Keccak-f[1600] permutation
fn keccak_f(state: &mut [u64; 25]) {
    for round in 0..ROUNDS {
        // theta step
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        
        for x in 0..5 {
            for y in 0..5 {
                state[y * 5 + x] ^= d[x];
            }
        }
        
        // rho and pi steps
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let src_idx = y * 5 + x;
                let dst_x = y;
                let dst_y = (2 * x + 3 * y) % 5;
                let dst_idx = dst_y * 5 + dst_x;
                b[dst_idx] = state[src_idx].rotate_left(ROTATION_OFFSETS[src_idx]);
            }
        }
        
        // chi step
        for x in 0..5 {
            for y in 0..5 {
                let idx = y * 5 + x;
                state[idx] = b[idx] ^ ((!b[y * 5 + (x + 1) % 5]) & b[y * 5 + (x + 2) % 5]);
            }
        }
        
        // iota step
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

/// Compute Keccak-256 hash
pub fn keccak256(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute Keccak-256 hash and return as hex string
pub fn keccak256_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(data)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    
    #[test]
    fn test_empty() {
        let hash = keccak256(b"");
        let expected = hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        assert_eq!(hash, expected);
    }
    
    #[test]
    fn test_simple() {
        // Test vectors from Ethereum
        let hash = keccak256(b"hello");
        let expected = hex!("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8");
        assert_eq!(hash, expected);
    }
    
    #[test]
    fn test_ethereum_compatibility() {
        // Common Ethereum test case
        let hash = keccak256(b"");
        // This is different from SHA3-256 which would give:
        // a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let expected = hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        assert_eq!(hash, expected);
    }
    
    #[test]
    fn test_incremental() {
        let data = b"The quick brown fox jumps over the lazy dog";
        
        // One-shot
        let hash1 = keccak256(data);
        
        // Incremental
        let mut hasher = Keccak256::new();
        hasher.update(&data[..20]);
        hasher.update(&data[20..]);
        let hash2 = hasher.finalize();
        
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_long_message() {
        let data = [0x42u8; 1000];
        let hash = keccak256(&data);
        assert_eq!(hash.len(), HASH_SIZE);
    }
    
    #[test]
    fn test_hex_output() {
        let hash_hex = keccak256_hex(b"test");
        assert!(hash_hex.starts_with("0x"));
        assert_eq!(hash_hex.len(), 2 + HASH_SIZE * 2); // "0x" + 64 hex chars
    }
    
    #[test]
    fn test_difference_from_sha3() {
        // Keccak-256 and SHA3-256 should produce different results
        let data = b"test";
        let keccak_hash = keccak256(data);
        
        // SHA3-256 of "test" would be:
        // 36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80
        // But Keccak-256 gives:
        let expected = hex!("9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658");
        assert_eq!(keccak_hash, expected);
    }
}