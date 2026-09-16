//! Optimized compression for ternary signatures
//! 
//! When using the trivial s1=0, s0=c approach, we can compress efficiently
//! since c is ternary (only values -1, 0, 1).

use crate::constants::N;
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;

const SALT_LEN: usize = 40;
const HEADER: u8 = 0x3A; // New header to distinguish ternary format

/// Compress a ternary signature where s1=0 and s0 is ternary
pub fn compress_ternary(s0: &[i16], s1: &[i16], salt: &[u8; SALT_LEN]) -> Result<Vec<u8>> {
    // Verify s1 is all zeros
    if !s1.iter().all(|&x| x == 0) {
        return Err(Falcon512Error::CompressionFailed);
    }
    
    // Verify s0 is ternary
    if !s0.iter().all(|&x| x >= -1 && x <= 1) {
        return Err(Falcon512Error::CompressionFailed);
    }
    
    let mut compressed = Vec::new();
    
    // Header byte
    compressed.push(HEADER);
    
    // Salt
    compressed.extend_from_slice(salt);
    
    // Compress s0 using 2 bits per coefficient (00=0, 01=1, 11=-1)
    // 512 coefficients * 2 bits = 1024 bits = 128 bytes
    let mut buffer = 0u8;
    let mut bits_in_buffer = 0;
    
    for &coeff in s0 {
        let bits = match coeff {
            0 => 0b00,
            1 => 0b01,
            -1 => 0b11,
            _ => return Err(Falcon512Error::CompressionFailed),
        };
        
        buffer |= bits << bits_in_buffer;
        bits_in_buffer += 2;
        
        if bits_in_buffer == 8 {
            compressed.push(buffer);
            buffer = 0;
            bits_in_buffer = 0;
        }
    }
    
    // Total size: 1 (header) + 40 (salt) + 128 (s0) = 169 bytes
    Ok(compressed)
}

/// Decompress a ternary signature
pub fn decompress_ternary(compressed: &[u8]) -> Result<(Vec<i16>, Vec<i16>, [u8; SALT_LEN])> {
    if compressed.len() != 1 + SALT_LEN + 128 {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    // Check header
    if compressed[0] != HEADER {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    // Extract salt
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&compressed[1..1 + SALT_LEN]);
    
    // Decompress s0
    let mut s0 = Vec::with_capacity(N);
    let s0_data = &compressed[1 + SALT_LEN..];
    
    for byte in s0_data {
        for i in 0..4 {
            let bits = (byte >> (i * 2)) & 0b11;
            let coeff = match bits {
                0b00 => 0,
                0b01 => 1,
                0b11 => -1,
                _ => return Err(Falcon512Error::DecompressionFailed),
            };
            s0.push(coeff);
            
            if s0.len() == N {
                break;
            }
        }
    }
    
    // s1 is all zeros
    let s1 = vec![0i16; N];
    
    Ok((s0, s1, salt))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ternary_compression() {
        let mut s0 = vec![0i16; N];
        s0[0] = 1;
        s0[1] = -1;
        s0[2] = 0;
        s0[3] = 1;
        
        let s1 = vec![0i16; N];
        let salt = [42u8; SALT_LEN];
        
        let compressed = compress_ternary(&s0, &s1, &salt).unwrap();
        assert_eq!(compressed.len(), 169); // Much smaller than 2089!
        
        let (s0_dec, s1_dec, salt_dec) = decompress_ternary(&compressed).unwrap();
        assert_eq!(s0, s0_dec);
        assert_eq!(s1, s1_dec);
        assert_eq!(salt, salt_dec);
    }
}