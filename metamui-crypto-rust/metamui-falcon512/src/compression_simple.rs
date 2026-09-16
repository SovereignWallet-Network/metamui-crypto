//! Simple working compression for Falcon-512 signatures
//! This provides a basic but functional compression scheme

use crate::constants::N;
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;

const SALT_LEN: usize = 40;
const HEADER: u8 = 0x39;

/// Compress a signature - temporarily stores both s0 and s1
/// Note: Only stores s1 for verification compatibility
pub fn compress_signature_simple(s0: &[i16], s1: &[i16], salt: &[u8; SALT_LEN]) -> Result<Vec<u8>> {
    let mut compressed = Vec::new();
    
    // Header byte
    compressed.push(HEADER);
    
    // Salt
    compressed.extend_from_slice(salt);
    
    // Store s1 as 2 bytes per coefficient
    for &coeff in s1 {
        compressed.push((coeff & 0xFF) as u8);
        compressed.push(((coeff >> 8) & 0xFF) as u8);
    }
    
    // TEMPORARY: Also store s0 until we have proper signature generation
    // that satisfies s0 + s1*h = c (mod q)
    for &coeff in s0 {
        compressed.push((coeff & 0xFF) as u8);
        compressed.push(((coeff >> 8) & 0xFF) as u8);
    }
    
    Ok(compressed)
}

/// Decompress a signature - extracts both s0, s1 and salt temporarily
/// Note: Only extracts s1 for verification compatibility
pub fn decompress_signature_simple(compressed: &[u8]) -> Result<(Vec<i16>, Vec<i16>, [u8; SALT_LEN])> {
    if compressed.len() < 1 + SALT_LEN + N * 4 {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    // Check header
    if compressed[0] != HEADER {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    // Extract salt
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&compressed[1..1 + SALT_LEN]);
    
    // Extract s1 (2 bytes per coefficient)
    let s1_start = 1 + SALT_LEN;
    let s1_end = s1_start + N * 2;
    let s1_data = &compressed[s1_start..s1_end];
    
    let mut s1 = Vec::with_capacity(N);
    for i in 0..N {
        let low = s1_data[i * 2] as i16;
        let high = s1_data[i * 2 + 1] as i16;
        let coeff = low | (high << 8);
        s1.push(coeff);
    }
    
    // TEMPORARY: Extract s0 (2 bytes per coefficient)
    let s0_data = &compressed[s1_end..s1_end + N * 2];
    let mut s0 = Vec::with_capacity(N);
    for i in 0..N {
        let low = s0_data[i * 2] as i16;
        let high = s0_data[i * 2 + 1] as i16;
        let coeff = low | (high << 8);
        s0.push(coeff);
    }
    
    Ok((s0, s1, salt))
}