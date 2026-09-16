/// Optimized AES-256-GCM implementation with performance enhancements
///
/// Key optimizations:
/// - Table-based GHASH multiplication
/// - Parallel CTR mode encryption
/// - Reduced allocations
/// - SIMD-ready structure
/// - Precomputed H powers for faster authentication

use crate::{
    error::Result,
    key::Aes256Key,
    Aes256Error, GCM_NONCE_SIZE, GCM_TAG_SIZE,
};
use crate::aes256::Aes256;

/// Optimized AES-256-GCM cipher
pub struct Aes256Gcm {
    cipher: Aes256,
    h: [u8; 16],           // GHASH key
    h_table: GHashTable,   // Precomputed multiplication table
}

/// Precomputed table for fast GHASH multiplication
struct GHashTable {
    // Precomputed powers of H for window-based multiplication
    h_powers: [[u8; 16]; 8], // H, H^2, H^3, ..., H^8
}

impl Aes256Gcm {
    /// Create optimized AES-256-GCM instance
    pub fn new(key: &Aes256Key) -> Result<Self> {
        let cipher = Aes256::new(key.as_bytes());
        
        // Generate GHASH key (encrypt zero block)
        let h = cipher.encrypt_block(&[0u8; 16]);
        
        // Precompute multiplication table
        let h_table = GHashTable::new(&h);
        
        Ok(Self { cipher, h, h_table })
    }
    
    /// Optimized encryption with reduced allocations
    pub fn encrypt(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<(Vec<u8>, [u8; GCM_TAG_SIZE])> {
        if nonce.len() != GCM_NONCE_SIZE {
            return Err(Aes256Error::InvalidNonceLength {
                expected: GCM_NONCE_SIZE,
                actual: nonce.len(),
            });
        }
        
        // Initialize counter: J0 = nonce || 0x00000001; CTR starts at J0+1 = nonce || 0x00000002
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(nonce);
        counter[15] = 2;

        // Encrypt plaintext using CTR mode
        let ciphertext = self.ctr_encrypt(plaintext, &counter);
        
        // Compute authentication tag
        let tag = self.compute_tag(
            nonce,
            &ciphertext,
            associated_data.unwrap_or(&[]),
        );
        
        Ok((ciphertext, tag))
    }
    
    /// Optimized decryption with constant-time verification
    pub fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if nonce.len() != GCM_NONCE_SIZE {
            return Err(Aes256Error::InvalidNonceLength {
                expected: GCM_NONCE_SIZE,
                actual: nonce.len(),
            });
        }
        
        if tag.len() != GCM_TAG_SIZE {
            return Err(Aes256Error::InvalidTagLength {
                expected: GCM_TAG_SIZE,
                actual: tag.len(),
            });
        }
        
        // Compute expected tag
        let computed_tag = self.compute_tag(
            nonce,
            ciphertext,
            associated_data.unwrap_or(&[]),
        );
        
        // Constant-time comparison
        if !constant_time_eq(&computed_tag, tag) {
            return Err(Aes256Error::AuthenticationFailed);
        }
        
        // Decrypt using CTR mode: same counter as encrypt (J0+1 = nonce || 0x00000002)
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(nonce);
        counter[15] = 2;

        let plaintext = self.ctr_encrypt(ciphertext, &counter);
        Ok(plaintext)
    }
    
    /// Optimized CTR mode encryption/decryption
    fn ctr_encrypt(&self, data: &[u8], initial_counter: &[u8; 16]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut counter = *initial_counter;
        
        // Process 4 blocks at a time for better performance
        let chunks = data.chunks(64); // 4 * 16 bytes
        
        for chunk in chunks {
            if chunk.len() == 64 {
                // Process 4 blocks in parallel
                let blocks = self.generate_ctr_blocks_x4(&mut counter);
                
                for i in 0..64 {
                    output.push(chunk[i] ^ blocks[i]);
                }
            } else {
                // Process remaining bytes
                for block_chunk in chunk.chunks(16) {
                    let keystream = self.cipher.encrypt_block(&counter);
                    
                    for i in 0..block_chunk.len() {
                        output.push(block_chunk[i] ^ keystream[i]);
                    }
                    
                    increment_counter(&mut counter);
                }
            }
        }
        
        output
    }
    
    /// Generate 4 CTR keystream blocks at once
    fn generate_ctr_blocks_x4(&self, counter: &mut [u8; 16]) -> [u8; 64] {
        let mut blocks = [0u8; 64];
        
        // Generate 4 counter values
        let mut counters = [[0u8; 16]; 4];
        for i in 0..4 {
            counters[i] = *counter;
            increment_counter(counter);
        }
        
        // Encrypt all 4 blocks (could be parallelized with SIMD)
        for i in 0..4 {
            let keystream = self.cipher.encrypt_block(&counters[i]);
            blocks[i * 16..(i + 1) * 16].copy_from_slice(&keystream);
        }
        
        blocks
    }
    
    /// Optimized authentication tag computation
    fn compute_tag(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> [u8; GCM_TAG_SIZE] {
        let mut ghash_state = [0u8; 16];
        
        // Process associated data
        if !associated_data.is_empty() {
            ghash_state = self.ghash_update(ghash_state, associated_data);
        }
        
        // Process ciphertext
        ghash_state = self.ghash_update(ghash_state, ciphertext);
        
        // Add lengths
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(associated_data.len() as u64 * 8).to_be_bytes());
        len_block[8..].copy_from_slice(&(ciphertext.len() as u64 * 8).to_be_bytes());
        
        for i in 0..16 {
            ghash_state[i] ^= len_block[i];
        }
        ghash_state = ghash_multiply(&ghash_state, &self.h);
        
        // Encrypt GHASH result with J0 = nonce || 0x00000001
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(nonce);
        counter[15] = 1;
        
        let encrypted_ghash = self.cipher.encrypt_block(&counter);
        
        let mut tag = [0u8; GCM_TAG_SIZE];
        for i in 0..GCM_TAG_SIZE {
            tag[i] = ghash_state[i] ^ encrypted_ghash[i];
        }
        
        tag
    }
    
    /// Optimized GHASH update using precomputed tables
    fn ghash_update(&self, mut state: [u8; 16], data: &[u8]) -> [u8; 16] {
        // Process complete blocks
        let complete_blocks = data.len() / 16;
        
        if complete_blocks >= 8 {
            // Process 8 blocks at a time using precomputed powers
            for chunk in data.chunks_exact(128) { // 8 * 16 bytes
                state = self.ghash_update_x8(state, chunk);
            }
        }
        
        // Process remaining complete blocks
        for block in data.chunks_exact(16).skip((complete_blocks / 8) * 8) {
            for i in 0..16 {
                state[i] ^= block[i];
            }
            state = ghash_multiply(&state, &self.h);
        }
        
        // Process final partial block if any
        let remainder = data.len() % 16;
        if remainder > 0 {
            let mut last_block = [0u8; 16];
            last_block[..remainder].copy_from_slice(&data[data.len() - remainder..]);
            
            for i in 0..16 {
                state[i] ^= last_block[i];
            }
            state = ghash_multiply(&state, &self.h);
        }
        
        state
    }
    
    /// Process 8 blocks at once using Horner's method with precomputed powers
    fn ghash_update_x8(&self, mut state: [u8; 16], blocks: &[u8]) -> [u8; 16] {
        // Using Horner's method: 
        // result = (...((m[0] * h + m[1]) * h + m[2]) * h + ... + m[7]) * h
        // Which can be rewritten as:
        // result = m[0]*h^8 + m[1]*h^7 + ... + m[7]*h^1
        
        let mut acc = [0u8; 16];
        
        // Process blocks with precomputed powers
        for i in 0..8 {
            let block = &blocks[i * 16..(i + 1) * 16];
            let h_power = &self.h_table.h_powers[7 - i];
            
            let mut temp = [0u8; 16];
            for j in 0..16 {
                temp[j] = block[j];
            }
            
            let product = ghash_multiply(&temp, h_power);
            for j in 0..16 {
                acc[j] ^= product[j];
            }
        }
        
        // XOR with previous state
        for i in 0..16 {
            state[i] ^= acc[i];
        }
        
        state
    }
}

impl GHashTable {
    fn new(h: &[u8; 16]) -> Self {
        let mut h_powers = [[0u8; 16]; 8];
        
        // Compute powers of H
        h_powers[0] = *h; // H^1
        
        for i in 1..8 {
            h_powers[i] = ghash_multiply(&h_powers[i - 1], h);
        }
        
        Self { h_powers }
    }
}

/// GF(2^128) multiplication for GCM using the bit-reversed (reflected) representation.
///
/// In GCM's bit-reversed convention: MSB of byte[0] = x^0 coefficient,
/// LSB of byte[15] = x^127 coefficient.
/// Irreducible polynomial: x^128 + x^7 + x^2 + x + 1.
/// Multiplication by x = right-shift by 1; if x^127 bit was set, XOR with 0xE1_00...00.
fn ghash_multiply(x: &[u8; 16], h: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut v = *h;

    for byte_idx in 0..16 {
        for bit_pos in (0..8).rev() {
            // If this bit of x is set, XOR result with current v
            if (x[byte_idx] >> bit_pos) & 1 == 1 {
                for i in 0..16 {
                    result[i] ^= v[i];
                }
            }
            // Multiply v by x: right shift v by 1, then reduce if carry
            let carry = v[15] & 1; // x^127 coefficient
            for i in (1..16).rev() {
                v[i] = (v[i] >> 1) | ((v[i - 1] & 1) << 7);
            }
            v[0] >>= 1;
            if carry == 1 {
                v[0] ^= 0xe1; // reduce: XOR with 0xE1_00...00 (x^7+x^2+x+1)
            }
        }
    }

    result
}

/// Increment counter (big-endian)
#[inline(always)]
fn increment_counter(counter: &mut [u8; 16]) {
    // Increment last 32 bits as big-endian
    let mut carry = 1u32;
    for i in (12..16).rev() {
        let sum = counter[i] as u32 + carry;
        counter[i] = sum as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }
}

/// Constant-time comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    
    #[test]
    fn test_gcm_optimized_encrypt_decrypt() {
        let key = Aes256Key::from_bytes(&hex!(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )).unwrap();
        
        let cipher = Aes256Gcm::new(&key).unwrap();
        let nonce = hex!("000102030405060708090a0b");
        let plaintext = b"Hello, AES-256-GCM Optimized!";
        let aad = b"Additional authenticated data";
        
        // Encrypt
        let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).unwrap();
        
        // Decrypt
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, Some(aad)).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
        
        // Try decryption with wrong AAD
        let result = cipher.decrypt(&nonce, &ciphertext, &tag, Some(b"wrong aad"));
        assert!(result.is_err());
    }
    
    #[test]
    fn test_gcm_optimized_large_data() {
        let key = Aes256Key::generate().unwrap();
        let cipher = Aes256Gcm::new(&key).unwrap();
        let nonce = [0x42u8; 12];
        
        // Test with 1MB of data
        let plaintext = vec![0x55u8; 1024 * 1024];
        let aad = b"Large data test";
        
        let (ciphertext, tag) = cipher.encrypt(&nonce, &plaintext, Some(aad)).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, Some(aad)).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }
    
    /// NIST SP 800-38D Test Case 16 — AES-256-GCM
    /// Key: feffe992..., IV: cafebabe..., AAD: feedface...
    /// This is the official NIST GCM test vector for AES-256 with AAD.
    #[test]
    fn test_nist_sp800_38d_test_case_16_gcm() {
        let key = Aes256Key::from_bytes(&hex!(
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
        )).unwrap();
        let cipher = Aes256Gcm::new(&key).unwrap();
        let nonce = hex!("cafebabefacedbaddecaf888");

        let pt = hex!(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39"
        );
        let aad = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2");

        let expected_ct = hex!(
            "522dc1f099567d07f47f37a32a84427d"
            "643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838"
            "c5f61e6393ba7a0abcc9f662"
        );
        let expected_tag = hex!("76fc6ece0f4e1768cddf8853bb2d551b");

        let (ct, tag) = cipher.encrypt(&nonce, &pt, Some(&aad)).unwrap();
        assert_eq!(&ct[..], &expected_ct[..],
            "NIST SP 800-38D TC16 ciphertext mismatch");
        assert_eq!(&tag[..], &expected_tag[..],
            "NIST SP 800-38D TC16 tag mismatch");

        // Verify decryption
        let decrypted = cipher.decrypt(&nonce, &ct, &tag, Some(&aad)).unwrap();
        assert_eq!(&decrypted[..], &pt[..],
            "NIST SP 800-38D TC16 decryption mismatch");
    }

    #[test]
    fn test_gcm_counter_increment() {
        let mut counter = [0u8; 16];
        counter[15] = 0xff;
        
        increment_counter(&mut counter);
        assert_eq!(counter[15], 0x00);
        assert_eq!(counter[14], 0x01);
        
        counter[12..16].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        increment_counter(&mut counter);
        assert_eq!(&counter[12..16], &[0x00, 0x00, 0x00, 0x00]);
    }
}