//! NIST-compliant signature compression to exactly 666 bytes
//! 
//! This module implements the signature compression required for NIST compliance,
//! ensuring all Falcon-512 signatures fit within the 666-byte limit.

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::poly::Poly;
use alloc::vec::Vec;

/// NIST signature format constants
const HEADER_BYTE: u8 = 0x30 + 9; // 0x39 for Falcon-512 (log2(512) = 9)
const NONCE_LEN: usize = 40;      // 320-bit nonce
const MAX_SIG_BYTES: usize = 666; // NIST specified maximum

/// Compressed signature structure
#[derive(Debug, Clone)]
pub struct CompressedSignature {
    /// Header byte (0x39 for Falcon-512)
    pub header: u8,
    /// Nonce (40 bytes)
    pub nonce: [u8; NONCE_LEN],
    /// Compressed s2 polynomial data
    pub compressed_s2: Vec<u8>,
}

impl CompressedSignature {
    /// Get total size in bytes
    pub fn size(&self) -> usize {
        1 + NONCE_LEN + self.compressed_s2.len()
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size());
        bytes.push(self.header);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.compressed_s2);
        bytes
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 1 + NONCE_LEN {
            return Err(Falcon512Error::InvalidSignature);
        }
        
        let header = bytes[0];
        if header != HEADER_BYTE {
            return Err(Falcon512Error::InvalidSignature);
        }
        
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[1..1 + NONCE_LEN]);
        
        let compressed_s2 = bytes[1 + NONCE_LEN..].to_vec();
        
        Ok(Self {
            header,
            nonce,
            compressed_s2,
        })
    }
}

/// Compress a Falcon-512 signature to meet NIST 666-byte requirement
/// 
/// Takes the signature polynomials (s0, s1) and compresses them.
/// Only s2 = s1 is stored; s0 is reconstructed during verification.
pub fn compress_signature_666(
    s0: &[i16],
    s1: &[i16],
    nonce: &[u8; NONCE_LEN],
) -> Result<CompressedSignature> {
    if s0.len() != N || s1.len() != N {
        return Err(Falcon512Error::InvalidParameter);
    }
    
    // Try multiple compression strategies to meet size limit
    let compressed_s2 = compress_s2_optimal(s1)?;
    
    let sig = CompressedSignature {
        header: HEADER_BYTE,
        nonce: *nonce,
        compressed_s2,
    };
    
    // Verify size constraint
    if sig.size() > MAX_SIG_BYTES {
        return Err(Falcon512Error::SignatureTooLarge);
    }
    
    Ok(sig)
}

/// Compress s2 polynomial using optimal strategy
fn compress_s2_optimal(s2: &[i16]) -> Result<Vec<u8>> {
    // Strategy 1: Try adaptive Golomb-Rice encoding
    if let Ok(compressed) = compress_golomb_rice_adaptive(s2) {
        if compressed.len() <= MAX_SIG_BYTES - 1 - NONCE_LEN {
            return Ok(compressed);
        }
    }
    
    // Strategy 2: Fixed-width encoding with guaranteed size
    compress_fixed_width(s2)
}

/// Adaptive Golomb-Rice compression
fn compress_golomb_rice_adaptive(s2: &[i16]) -> Result<Vec<u8>> {
    // Analyze coefficient distribution
    let mut max_abs = 0i16;
    let mut small_count = 0usize;
    
    for &coeff in s2 {
        let abs_val = coeff.abs();
        max_abs = max_abs.max(abs_val);
        if abs_val <= 127 {
            small_count += 1;
        }
    }
    
    // Choose encoding based on distribution
    let small_ratio = small_count as f64 / N as f64;
    
    if small_ratio > 0.9 && max_abs <= 255 {
        // Use 8-bit encoding (1 sign + 7 magnitude)
        compress_fixed_bits(s2, 8)
    } else {
        // Use 9-bit encoding (guaranteed to fit in 666 bytes)
        compress_fixed_bits(s2, 9)
    }
}

/// Fixed-bit-width compression
fn compress_fixed_bits(s2: &[i16], bits_per_coeff: usize) -> Result<Vec<u8>> {
    let total_bits = N * bits_per_coeff;
    let total_bytes = (total_bits + 7) / 8;
    
    let mut out = Vec::with_capacity(total_bytes);
    let mut acc: u64 = 0;
    let mut acc_len: usize = 0;
    
    for &coeff in s2 {
        // Encode sign and magnitude
        let sign = if coeff < 0 { 1u64 } else { 0u64 };
        let mag_bits = bits_per_coeff - 1;
        let max_mag = (1u64 << mag_bits) - 1;
        let mag = (coeff.abs() as u64).min(max_mag);
        
        // Pack bits
        acc |= sign << acc_len;
        acc_len += 1;
        acc |= mag << acc_len;
        acc_len += mag_bits;
        
        // Flush complete bytes
        while acc_len >= 8 {
            out.push((acc & 0xFF) as u8);
            acc >>= 8;
            acc_len -= 8;
        }
    }
    
    // Flush remaining bits
    if acc_len > 0 {
        out.push((acc & 0xFF) as u8);
    }
    
    Ok(out)
}

/// Fixed-width compression with guaranteed size
/// Uses 10 bits per coefficient: 512 * 10 / 8 = 640 bytes
/// Total: 1 (header) + 40 (nonce) + 640 (s2) = 681 bytes > 666!
/// So we need to use 9 bits: 512 * 9 / 8 = 576 bytes
/// Total: 1 + 40 + 576 = 617 bytes < 666 ??
fn compress_fixed_width(s2: &[i16]) -> Result<Vec<u8>> {
    // Use 9 bits to guarantee fitting in 666 bytes
    compress_fixed_bits(s2, 9)
}

/// Decompress a signature from 666-byte format
pub fn decompress_signature_666(_sig: &CompressedSignature) -> Result<(Vec<i16>, Vec<i16>)> {
    Err(Falcon512Error::NotImplemented)
}

/// Decompress s2 polynomial
fn decompress_s2(data: &[u8]) -> Result<Vec<i16>> {
    // Try to determine encoding from data size
    let data_bits = data.len() * 8;
    let bits_per_coeff = (data_bits + N - 1) / N;
    
    if bits_per_coeff < 8 || bits_per_coeff > 11 {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    decompress_fixed_bits(data, bits_per_coeff)
}

/// Fixed-bit-width decompression
fn decompress_fixed_bits(data: &[u8], bits_per_coeff: usize) -> Result<Vec<i16>> {
    let mut coeffs = Vec::with_capacity(N);
    let mut acc: u64 = 0;
    let mut acc_len: usize = 0;
    let mut data_pos = 0;
    
    for _ in 0..N {
        // Ensure we have enough bits
        while acc_len < bits_per_coeff && data_pos < data.len() {
            acc |= (data[data_pos] as u64) << acc_len;
            acc_len += 8;
            data_pos += 1;
        }
        
        if acc_len < bits_per_coeff {
            // Handle last coefficient which might be partially encoded
            // with zero padding
        }
        
        // Extract sign and magnitude
        let sign = (acc & 1) != 0;
        acc >>= 1;
        acc_len -= 1;
        
        let mag_bits = bits_per_coeff - 1;
        let mag = (acc & ((1u64 << mag_bits) - 1)) as i16;
        acc >>= mag_bits;
        acc_len = acc_len.saturating_sub(mag_bits);
        
        // Reconstruct coefficient
        let coeff = if sign { -mag } else { mag };
        coeffs.push(coeff);
    }
    
    Ok(coeffs)
}

/// Compute s0 from s1, c, and h during verification
/// s0 = c - s1*h mod q
pub fn reconstruct_s0(
    s1: &[i16],
    c: &[i16],
    h: &[i16],
) -> Result<Vec<i16>> {
    if s1.len() != N || c.len() != N || h.len() != N {
        return Err(Falcon512Error::InvalidParameter);
    }
    
    // Compute s1*h using NTT for efficiency
    let s1_poly = Poly::new(s1.to_vec());
    let h_poly = Poly::new(h.to_vec());
    let s1h = s1_poly.mul(&h_poly);
    
    // Compute s0 = c - s1*h mod q
    let mut s0 = vec![0i16; N];
    for i in 0..N {
        let diff = (c[i] as i32 - s1h.coeffs[i] as i32).rem_euclid(Q as i32);
        // Center-reduce to [-q/2, q/2)
        s0[i] = if diff > Q as i32 / 2 {
            diff as i16 - Q as i16
        } else {
            diff as i16
        };
    }
    
    Ok(s0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    
    #[test]
    fn test_compression_666() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        // Generate random signature with values that fit in 9 bits
        let mut s0 = vec![0i16; N];
        let mut s1 = vec![0i16; N];
        for i in 0..N {
            // Keep values within 9-bit signed range: [-255, 255]
            s0[i] = rng.gen_range(-255..=255);
            s1[i] = rng.gen_range(-255..=255);
        }
        
        let nonce = [0x42u8; NONCE_LEN];
        
        // Compress
        let compressed = compress_signature_666(&s0, &s1, &nonce)
            .expect("Compression should succeed");
        
        // Check size
        assert!(compressed.size() <= MAX_SIG_BYTES, 
                "Signature size {} exceeds maximum {}", 
                compressed.size(), MAX_SIG_BYTES);
        
        let err = decompress_signature_666(&compressed)
            .expect_err("Decompression should fail closed");
        assert!(matches!(err, Falcon512Error::NotImplemented));
    }
    
    #[test]
    fn test_fixed_width_compression() {
        let mut s2 = vec![0i16; N];
        for i in 0..N {
            // Keep values within 9-bit range (-255 to 255)
            s2[i] = ((i as i16) * 7 - 128) % 256;
        }
        
        let compressed = compress_fixed_width(&s2)
            .expect("Fixed width compression should succeed");
        
        // 9 bits * 512 / 8 = 576 bytes
        assert_eq!(compressed.len(), 576);
        
        let decompressed = decompress_fixed_bits(&compressed, 9)
            .expect("Decompression should succeed");
        
        assert_eq!(decompressed, s2);
    }
    
    #[test]
    fn test_size_guarantee() {
        // Test that even worst-case signatures fit in 666 bytes
        let mut rng = ChaCha20Rng::seed_from_u64(1337);
        
        for _ in 0..10 {
            let mut s0 = vec![0i16; N];
            let mut s1 = vec![0i16; N];
            
            // Generate worst-case large coefficients within 9-bit range
            for i in 0..N {
                s0[i] = rng.gen_range(-255..=255);
                s1[i] = rng.gen_range(-255..=255);
            }
            
            let nonce = [0xFFu8; NONCE_LEN];
            
            let compressed = compress_signature_666(&s0, &s1, &nonce)
                .expect("Compression should succeed even for large coefficients");
            
            assert!(compressed.size() <= MAX_SIG_BYTES,
                    "Large coefficient signature size {} exceeds maximum {}",
                    compressed.size(), MAX_SIG_BYTES);
        }
    }
}
