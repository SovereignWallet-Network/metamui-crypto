//! CMAC (Cipher-based Message Authentication Code) implementation
//! 
//! This module provides a pure Rust implementation of CMAC as specified in
//! NIST SP 800-38B, using AES-256 as the underlying block cipher.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;
use alloc::vec::Vec;

use metamui_aes_256::{Aes256Core, BLOCK_SIZE};
use metamui_security_utils::zero;

/// CMAC context for incremental MAC computation
pub struct Cmac {
    cipher: Aes256Core,
    k1: [u8; BLOCK_SIZE],
    k2: [u8; BLOCK_SIZE],
    buffer: Vec<u8>,
    state: [u8; BLOCK_SIZE],
}

impl Cmac {
    /// Create a new CMAC instance with the given key
    pub fn new(key: &[u8]) -> Result<Self, CmacError> {
        if key.len() != 32 {
            return Err(CmacError::InvalidKeyLength);
        }
        
        let key_array: &[u8; 32] = key.try_into().map_err(|_| CmacError::InvalidKeyLength)?;
        let cipher = Aes256Core::new(key_array);
        
        // Generate subkeys K1 and K2
        let (k1, k2) = generate_subkeys(&cipher);
        
        Ok(Self {
            cipher,
            k1,
            k2,
            buffer: Vec::with_capacity(BLOCK_SIZE),
            state: [0u8; BLOCK_SIZE],
        })
    }
    
    /// Update the CMAC with additional data
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        
        // Process complete blocks, but always keep at least one block for finalize
        while self.buffer.len() > BLOCK_SIZE {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&self.buffer[..BLOCK_SIZE]);
            
            // XOR with state
            for i in 0..BLOCK_SIZE {
                block[i] ^= self.state[i];
            }
            
            // Encrypt
            self.state = self.cipher.encrypt_block(&block);
            
            // Remove processed block
            self.buffer.drain(..BLOCK_SIZE);
        }
    }
    
    /// Finalize the CMAC and return the tag
    pub fn finalize(self) -> [u8; BLOCK_SIZE] {
        let mut last_block = [0u8; BLOCK_SIZE];
        let last_block_len = self.buffer.len();
        
        if last_block_len == BLOCK_SIZE {
            // Complete block - XOR with K1
            last_block.copy_from_slice(&self.buffer);
            for i in 0..BLOCK_SIZE {
                last_block[i] ^= self.k1[i];
            }
        } else {
            // Incomplete block - pad and XOR with K2
            last_block[..last_block_len].copy_from_slice(&self.buffer);
            last_block[last_block_len] = 0x80;
            for i in 0..BLOCK_SIZE {
                last_block[i] ^= self.k2[i];
            }
        }
        
        // XOR with state
        for i in 0..BLOCK_SIZE {
            last_block[i] ^= self.state[i];
        }
        
        // Final encryption
        self.cipher.encrypt_block(&last_block)
    }
    
    /// Compute CMAC for the given data in one shot
    pub fn mac(key: &[u8], data: &[u8]) -> Result<[u8; BLOCK_SIZE], CmacError> {
        let mut cmac = Self::new(key)?;
        cmac.update(data);
        Ok(cmac.finalize())
    }
    
    /// Verify a CMAC tag
    pub fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool, CmacError> {
        if tag.len() != BLOCK_SIZE {
            return Ok(false);
        }
        
        let computed = Self::mac(key, data)?;
        
        // Constant-time comparison
        let mut diff = 0u8;
        for i in 0..BLOCK_SIZE {
            diff |= computed[i] ^ tag[i];
        }
        
        Ok(diff == 0)
    }
}

/// Generate CMAC subkeys K1 and K2
fn generate_subkeys(cipher: &Aes256Core) -> ([u8; BLOCK_SIZE], [u8; BLOCK_SIZE]) {
    // Step 1: L = AES(K, 0^128)
    let zero_block = [0u8; BLOCK_SIZE];
    let l = cipher.encrypt_block(&zero_block);
    
    // Step 2: K1 = L << 1
    let k1 = left_shift_one(&l);
    
    // Step 3: K2 = K1 << 1
    let k2 = left_shift_one(&k1);
    
    (k1, k2)
}

/// Left shift a block by one bit
fn left_shift_one(block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut output = [0u8; BLOCK_SIZE];
    let mut overflow = 0u8;
    
    for i in (0..BLOCK_SIZE).rev() {
        output[i] = (block[i] << 1) | overflow;
        overflow = (block[i] >> 7) & 1;
    }
    
    // If MSB of original was 1, XOR with Rb
    if (block[0] & 0x80) != 0 {
        output[BLOCK_SIZE - 1] ^= 0x87; // Rb for 128-bit blocks
    }
    
    output
}

/// CMAC errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmacError {
    /// Invalid key length (must be 32 bytes for AES-256)
    InvalidKeyLength,
}

#[cfg(feature = "std")]
impl std::error::Error for CmacError {}

impl core::fmt::Display for CmacError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeyLength => write!(f, "Invalid key length (must be 32 bytes)"),
        }
    }
}

impl Drop for Cmac {
    fn drop(&mut self) {
        zero(&mut self.k1);
        zero(&mut self.k2);
        zero(&mut self.state);
        self.buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cmac_empty() {
        // Use NIST test vector for AES-256-CMAC with empty message
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
        let data = [];
        let tag = Cmac::mac(&key, &data).unwrap();
        
        // Verify against known test vector
        let expected = hex::decode("028962f61b7bf89efc6b551f4667d983").unwrap();
        assert_eq!(&tag[..], &expected[..]);
    }
    
    /// NIST SP 800-38B D.4 Example 2 — AES-256-CMAC with 16-byte message
    #[test]
    fn test_nist_sp800_38b_example2() {
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
        let data = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let tag = Cmac::mac(&key, &data).unwrap();
        let expected = hex::decode("28a7023f452e8f82bd4bf28d8c37c35c").unwrap();
        assert_eq!(&tag[..], &expected[..], "NIST SP 800-38B D.4 Example 2 failed");
    }

    /// NIST SP 800-38B D.4 Example 4 — AES-256-CMAC with 64-byte message
    #[test]
    fn test_nist_sp800_38b_example4() {
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
        let data = hex::decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
        ).unwrap();
        let tag = Cmac::mac(&key, &data).unwrap();
        let expected = hex::decode("e1992190549f6ed5696a2c056c315410").unwrap();
        assert_eq!(&tag[..], &expected[..], "NIST SP 800-38B D.4 Example 4 failed");
    }

    #[test]
    fn test_cmac_incremental() {
        let key = [0u8; 32];
        let data = b"Hello, World!";
        
        // One-shot
        let tag1 = Cmac::mac(&key, data).unwrap();
        
        // Incremental
        let mut cmac = Cmac::new(&key).unwrap();
        cmac.update(b"Hello");
        cmac.update(b", ");
        cmac.update(b"World!");
        let tag2 = cmac.finalize();
        
        assert_eq!(tag1, tag2);
    }
    
    #[test]
    fn test_verify() {
        let key = [0x42u8; 32];
        let data = b"Test message";
        
        let tag = Cmac::mac(&key, data).unwrap();
        assert!(Cmac::verify(&key, data, &tag).unwrap());
        
        // Wrong tag
        let mut wrong_tag = tag;
        wrong_tag[0] ^= 1;
        assert!(!Cmac::verify(&key, data, &wrong_tag).unwrap());
    }
}