//! SipHash - Fast, cryptographically secure PRF for short messages
//!
//! SipHash is a pseudorandom function optimized for short messages, commonly
//! used in hash tables for protection against hash-flooding DoS attacks.

#![cfg_attr(not(feature = "std"), no_std)]

use core::convert::TryInto;

/// Size of SipHash key in bytes
pub const KEY_SIZE: usize = 16;

/// Size of 64-bit SipHash output
pub const TAG_SIZE_64: usize = 8;

/// Size of 128-bit SipHash output  
pub const TAG_SIZE_128: usize = 16;

/// Block size in bytes
pub const BLOCK_SIZE: usize = 8;

/// SipHash parameters
#[derive(Debug, Clone, Copy)]
pub struct Parameters {
    /// Number of compression rounds
    pub c_rounds: usize,
    /// Number of finalization rounds
    pub d_rounds: usize,
}

/// Standard SipHash-2-4 parameters
pub const SIPHASH_2_4: Parameters = Parameters {
    c_rounds: 2,
    d_rounds: 4,
};

/// Fast SipHash-1-3 parameters (less secure)
pub const SIPHASH_1_3: Parameters = Parameters {
    c_rounds: 1,
    d_rounds: 3,
};

/// Extended SipHash-4-8 parameters (more secure)
pub const SIPHASH_4_8: Parameters = Parameters {
    c_rounds: 4,
    d_rounds: 8,
};

/// SipHash-64 hasher
pub struct SipHash64 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    k0: u64,
    k1: u64,
    params: Parameters,
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: usize,
}

/// SipHash-128 hasher
pub struct SipHash128 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    k0: u64,
    k1: u64,
    params: Parameters,
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: usize,
}

impl SipHash64 {
    /// Create new SipHash-64 with key and parameters
    pub fn new_with_params(key: &[u8; KEY_SIZE], params: Parameters) -> Self {
        let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
        
        let mut hasher = Self {
            v0: 0,
            v1: 0,
            v2: 0,
            v3: 0,
            k0,
            k1,
            params,
            buffer: [0; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
        };
        hasher.reset();
        hasher
    }
    
    /// Create new SipHash-64 with standard SipHash-2-4 parameters
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self::new_with_params(key, SIPHASH_2_4)
    }
    
    /// Reset hasher to initial state
    pub fn reset(&mut self) {
        self.v0 = 0x736f6d6570736575 ^ self.k0;
        self.v1 = 0x646f72616e646f6d ^ self.k1;
        self.v2 = 0x6c7967656e657261 ^ self.k0;
        self.v3 = 0x7465646279746573 ^ self.k1;
        self.buffer = [0; BLOCK_SIZE];
        self.buffer_len = 0;
        self.total_len = 0;
    }
    
    /// Update hasher with data
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len();
        let mut data = data;
        
        // Process buffered data
        if self.buffer_len > 0 {
            let to_copy = (BLOCK_SIZE - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            data = &data[to_copy..];
            
            if self.buffer_len == BLOCK_SIZE {
                let m = u64::from_le_bytes(self.buffer);
                self.process_block(m);
                self.buffer_len = 0;
            }
        }
        
        // Process full blocks
        while data.len() >= BLOCK_SIZE {
            let m = u64::from_le_bytes(data[..BLOCK_SIZE].try_into().unwrap());
            self.process_block(m);
            data = &data[BLOCK_SIZE..];
        }
        
        // Buffer remaining bytes
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }
    
    /// Process single block
    fn process_block(&mut self, m: u64) {
        self.v3 ^= m;
        for _ in 0..self.params.c_rounds {
            sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        }
        self.v0 ^= m;
    }
    
    /// Finalize and return 64-bit hash
    pub fn finalize(&self) -> u64 {
        let mut v0 = self.v0;
        let mut v1 = self.v1;
        let mut v2 = self.v2;
        let mut v3 = self.v3;
        
        // Process final block
        let mut final_block = [0u8; BLOCK_SIZE];
        final_block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        final_block[7] = self.total_len as u8;
        
        let b = u64::from_le_bytes(final_block);
        v3 ^= b;
        for _ in 0..self.params.c_rounds {
            sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^= b;
        
        // Finalization
        v2 ^= 0xff;
        for _ in 0..self.params.d_rounds {
            sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        
        v0 ^ v1 ^ v2 ^ v3
    }
}

impl SipHash128 {
    /// Create new SipHash-128 with key and parameters
    pub fn new_with_params(key: &[u8; KEY_SIZE], params: Parameters) -> Self {
        let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
        
        let mut hasher = Self {
            v0: 0,
            v1: 0,
            v2: 0,
            v3: 0,
            k0,
            k1,
            params,
            buffer: [0; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
        };
        hasher.reset();
        hasher
    }
    
    /// Create new SipHash-128 with standard SipHash-2-4 parameters
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self::new_with_params(key, SIPHASH_2_4)
    }
    
    /// Reset hasher to initial state
    pub fn reset(&mut self) {
        self.v0 = 0x736f6d6570736575 ^ self.k0;
        self.v1 = 0x646f72616e646f6d ^ self.k1 ^ 0xee;
        self.v2 = 0x6c7967656e657261 ^ self.k0;
        self.v3 = 0x7465646279746573 ^ self.k1;
        self.buffer = [0; BLOCK_SIZE];
        self.buffer_len = 0;
        self.total_len = 0;
    }
    
    /// Update hasher with data
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len();
        let mut data = data;
        
        // Process buffered data
        if self.buffer_len > 0 {
            let to_copy = (BLOCK_SIZE - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            data = &data[to_copy..];
            
            if self.buffer_len == BLOCK_SIZE {
                let m = u64::from_le_bytes(self.buffer);
                self.process_block(m);
                self.buffer_len = 0;
            }
        }
        
        // Process full blocks
        while data.len() >= BLOCK_SIZE {
            let m = u64::from_le_bytes(data[..BLOCK_SIZE].try_into().unwrap());
            self.process_block(m);
            data = &data[BLOCK_SIZE..];
        }
        
        // Buffer remaining bytes
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }
    
    /// Process single block
    fn process_block(&mut self, m: u64) {
        self.v3 ^= m;
        for _ in 0..self.params.c_rounds {
            sip_round(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        }
        self.v0 ^= m;
    }
    
    /// Finalize and return 128-bit hash
    pub fn finalize(&self) -> [u8; TAG_SIZE_128] {
        let mut v0 = self.v0;
        let mut v1 = self.v1;
        let mut v2 = self.v2;
        let mut v3 = self.v3;
        
        // Process final block
        let mut final_block = [0u8; BLOCK_SIZE];
        final_block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        final_block[7] = self.total_len as u8;
        
        let b = u64::from_le_bytes(final_block);
        v3 ^= b;
        for _ in 0..self.params.c_rounds {
            sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^= b;
        
        // First finalization for first 64 bits
        v2 ^= 0xee;
        for _ in 0..self.params.d_rounds {
            sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        let first = v0 ^ v1 ^ v2 ^ v3;
        
        // Second finalization for second 64 bits
        v1 ^= 0xdd;
        for _ in 0..self.params.d_rounds {
            sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        let second = v0 ^ v1 ^ v2 ^ v3;
        
        let mut result = [0u8; TAG_SIZE_128];
        result[0..8].copy_from_slice(&first.to_le_bytes());
        result[8..16].copy_from_slice(&second.to_le_bytes());
        result
    }
}

/// Perform one SipHash round
#[inline(always)]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// Compute 64-bit SipHash
pub fn hash64(key: &[u8; KEY_SIZE], data: &[u8]) -> u64 {
    let mut hasher = SipHash64::new(key);
    hasher.update(data);
    hasher.finalize()
}

/// Compute 128-bit SipHash
pub fn hash128(key: &[u8; KEY_SIZE], data: &[u8]) -> [u8; TAG_SIZE_128] {
    let mut hasher = SipHash128::new(key);
    hasher.update(data);
    hasher.finalize()
}

/// Generate random SipHash key
#[cfg(feature = "std")]
pub fn generate_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    getrandom::getrandom(&mut key).expect("Failed to generate random key");
    key
}

/// Generate SipHash MAC
pub fn mac(key: &[u8; KEY_SIZE], message: &[u8]) -> [u8; TAG_SIZE_64] {
    let tag = hash64(key, message);
    tag.to_le_bytes()
}

/// Verify SipHash MAC
pub fn verify(mac: &[u8], key: &[u8; KEY_SIZE], message: &[u8]) -> bool {
    if mac.len() != TAG_SIZE_64 {
        return false;
    }
    
    let expected = self::mac(key, message);
    
    // Constant-time comparison
    let mut result = 0u8;
    for i in 0..TAG_SIZE_64 {
        result |= mac[i] ^ expected[i];
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    
    #[test]
    fn test_siphash64_basic() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let data = b"test message";
        
        let hash1 = hash64(&key, data);
        let hash2 = hash64(&key, data);
        
        // Should be deterministic
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_siphash128_basic() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let data = b"test message";
        
        let hash1 = hash128(&key, data);
        let hash2 = hash128(&key, data);
        
        // Should be deterministic
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), TAG_SIZE_128);
    }
    
    #[test]
    fn test_incremental_hashing() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let data = b"The quick brown fox jumps over the lazy dog";
        
        // One-shot
        let hash1 = hash64(&key, data);
        
        // Incremental
        let mut hasher = SipHash64::new(&key);
        hasher.update(&data[..20]);
        hasher.update(&data[20..]);
        let hash2 = hasher.finalize();
        
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_different_keys() {
        let key1 = hex!("000102030405060708090a0b0c0d0e0f");
        let key2 = hex!("0f0e0d0c0b0a09080706050403020100");
        let data = b"test";
        
        let hash1 = hash64(&key1, data);
        let hash2 = hash64(&key2, data);
        
        // Different keys should produce different hashes
        assert_ne!(hash1, hash2);
    }
    
    #[test]
    fn test_mac_verify() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let message = b"authenticated message";
        
        let mac = self::mac(&key, message);
        assert!(verify(&mac, &key, message));
        
        // Wrong message
        assert!(!verify(&mac, &key, b"wrong message"));
        
        // Wrong key
        let wrong_key = hex!("0f0e0d0c0b0a09080706050403020100");
        assert!(!verify(&mac, &wrong_key, message));
    }
    
    #[test]
    fn test_empty_message() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let hash = hash64(&key, b"");
        
        // Should handle empty message
        assert_ne!(hash, 0);
    }
    
    #[test]
    fn test_parameters() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let data = b"test";
        
        let mut hasher24 = SipHash64::new_with_params(&key, SIPHASH_2_4);
        hasher24.update(data);
        let hash24 = hasher24.finalize();
        
        let mut hasher13 = SipHash64::new_with_params(&key, SIPHASH_1_3);
        hasher13.update(data);
        let hash13 = hasher13.finalize();
        
        // Different parameters should produce different hashes
        assert_ne!(hash24, hash13);
    }
}