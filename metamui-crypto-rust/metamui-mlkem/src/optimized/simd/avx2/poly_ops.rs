//! AVX2-optimized polynomial operations for ML-KEM
//!
//! This module provides vectorized polynomial arithmetic operations
//! using AVX2 instructions for 8x parallel processing.

use crate::Result;
use core::arch::x86_64::*;
use super::constants::*;

/// AVX2 polynomial addition
#[target_feature(enable = "avx2")]
pub unsafe fn poly_add_avx2(r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
    // Process 16 coefficients at a time
    for i in (0..256).step_by(16) {
        let a_vec = _mm256_loadu_si256(a[i..].as_ptr() as *const __m256i);
        let b_vec = _mm256_loadu_si256(b[i..].as_ptr() as *const __m256i);
        let sum = _mm256_add_epi16(a_vec, b_vec);
        _mm256_storeu_si256(r[i..].as_mut_ptr() as *mut __m256i, sum);
    }
    Ok(())
}

/// AVX2 polynomial subtraction
#[target_feature(enable = "avx2")]
pub unsafe fn poly_sub_avx2(r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
    // Process 16 coefficients at a time
    for i in (0..256).step_by(16) {
        let a_vec = _mm256_loadu_si256(a[i..].as_ptr() as *const __m256i);
        let b_vec = _mm256_loadu_si256(b[i..].as_ptr() as *const __m256i);
        let diff = _mm256_sub_epi16(a_vec, b_vec);
        _mm256_storeu_si256(r[i..].as_mut_ptr() as *mut __m256i, diff);
    }
    Ok(())
}

/// AVX2 base multiplication (pointwise multiplication in NTT domain)
#[target_feature(enable = "avx2")]
pub unsafe fn poly_basemul_avx2(r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
    // Process pairs of coefficients for NTT domain multiplication
    // Using Karatsuba for each pair
    for i in (0..256).step_by(16) {
        let a_vec = _mm256_loadu_si256(a[i..].as_ptr() as *const __m256i);
        let b_vec = _mm256_loadu_si256(b[i..].as_ptr() as *const __m256i);
        
        // Split into even and odd coefficients
        let a_even = _mm256_and_si256(a_vec, _mm256_set_epi32(
            0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF,
            0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF
        ));
        let a_odd = _mm256_srli_epi32(a_vec, 16);
        
        let b_even = _mm256_and_si256(b_vec, _mm256_set_epi32(
            0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF,
            0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF
        ));
        let b_odd = _mm256_srli_epi32(b_vec, 16);
        
        // Multiply and reduce
        let prod_even = montgomery_mul_avx2_32(a_even, b_even);
        let prod_odd = montgomery_mul_avx2_32(a_odd, b_odd);
        
        // Combine results
        let result = _mm256_or_si256(
            _mm256_and_si256(prod_even, _mm256_set_epi32(
                0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF,
                0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF
            )),
            _mm256_slli_epi32(prod_odd, 16)
        );
        
        _mm256_storeu_si256(r[i..].as_mut_ptr() as *mut __m256i, result);
    }
    Ok(())
}

/// AVX2 Barrett reduction for polynomials
#[target_feature(enable = "avx2")]
pub unsafe fn poly_barrett_reduce_avx2(poly: &mut [i16; 256]) -> Result<()> {
    let v = vbarrett();
    let q = vq();
    
    for chunk in poly.chunks_mut(16) {
        if chunk.len() == 16 {
            let a = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
            
            // Convert to 32-bit for proper arithmetic
            let a_lo = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(a, 0));
            let a_hi = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(a, 1));
            
            // Barrett reduction: t = ((a * v) >> 26) * q
            let t_lo = _mm256_srai_epi32(_mm256_mullo_epi32(a_lo, v), 26);
            let t_hi = _mm256_srai_epi32(_mm256_mullo_epi32(a_hi, v), 26);
            
            let r_lo = _mm256_sub_epi32(a_lo, _mm256_mullo_epi32(t_lo, _mm256_set1_epi32(Q32)));
            let r_hi = _mm256_sub_epi32(a_hi, _mm256_mullo_epi32(t_hi, _mm256_set1_epi32(Q32)));
            
            // Pack back to 16-bit
            let result = _mm256_packs_epi32(r_lo, r_hi);
            _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, result);
        }
    }
    Ok(())
}

/// AVX2 Montgomery reduction for polynomials
#[target_feature(enable = "avx2")]
pub unsafe fn poly_montgomery_reduce_avx2(poly: &mut [i16; 256]) -> Result<()> {
    let qinv = vqinv();
    let q = vq();
    
    for chunk in poly.chunks_mut(16) {
        if chunk.len() == 16 {
            let a = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
            
            // Montgomery reduction
            let t = _mm256_mullo_epi16(a, qinv);
            let m = _mm256_mulhi_epi16(t, q);
            let result = _mm256_sub_epi16(a, m);
            
            _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, result);
        }
    }
    Ok(())
}

/// AVX2 polynomial compression
#[target_feature(enable = "avx2")]
pub unsafe fn poly_compress_avx2(r: &mut [u8], poly: &[i16; 256], bits: usize) -> Result<()> {
    match bits {
        4 => compress_4bit_avx2(r, poly),
        10 => compress_10bit_avx2(r, poly),
        11 => compress_11bit_avx2(r, poly),
        _ => Err(crate::Error::InvalidParameter),
    }
}

/// AVX2 polynomial decompression
#[target_feature(enable = "avx2")]
pub unsafe fn poly_decompress_avx2(poly: &mut [i16; 256], a: &[u8], bits: usize) -> Result<()> {
    match bits {
        4 => decompress_4bit_avx2(poly, a),
        10 => decompress_10bit_avx2(poly, a),
        11 => decompress_11bit_avx2(poly, a),
        _ => Err(crate::Error::InvalidParameter),
    }
}

/// Helper: AVX2 Montgomery multiplication for 32-bit values
#[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn montgomery_mul_avx2_32(a: __m256i, b: __m256i) -> __m256i {
    let prod = _mm256_mullo_epi32(a, b);
    let t = _mm256_mullo_epi32(prod, _mm256_set1_epi32(QINV as i32));
    let m = _mm256_mullo_epi32(t, _mm256_set1_epi32(Q32));
    _mm256_sub_epi32(prod, m)
}

/// Compress to 4 bits using AVX2
#[target_feature(enable = "avx2")]
unsafe fn compress_4bit_avx2(r: &mut [u8], poly: &[i16; 256]) -> Result<()> {
    // 4-bit compression: round(16*x/q) mod 16
    let mut idx = 0;
    for i in (0..256).step_by(32) {
        let coeffs1 = _mm256_loadu_si256(poly[i..].as_ptr() as *const __m256i);
        let coeffs2 = _mm256_loadu_si256(poly[i+16..].as_ptr() as *const __m256i);
        
        // Compress each coefficient to 4 bits
        let compressed1 = compress_coeff_4bit_avx2(coeffs1);
        let compressed2 = compress_coeff_4bit_avx2(coeffs2);
        
        // Pack 32 coefficients into 16 bytes
        for j in 0..8 {
            let c1 = _mm256_extract_epi16(compressed1, j*2) as u8;
            let c2 = _mm256_extract_epi16(compressed1, j*2+1) as u8;
            r[idx] = (c1 & 0x0F) | ((c2 & 0x0F) << 4);
            idx += 1;
        }
        
        for j in 0..8 {
            let c1 = _mm256_extract_epi16(compressed2, j*2) as u8;
            let c2 = _mm256_extract_epi16(compressed2, j*2+1) as u8;
            r[idx] = (c1 & 0x0F) | ((c2 & 0x0F) << 4);
            idx += 1;
        }
    }
    Ok(())
}

/// Decompress from 4 bits using AVX2
#[target_feature(enable = "avx2")]
unsafe fn decompress_4bit_avx2(poly: &mut [i16; 256], a: &[u8]) -> Result<()> {
    // 4-bit decompression: round(q*x/16)
    let mut idx = 0;
    for i in (0..256).step_by(2) {
        let byte = a[idx];
        poly[i] = decompress_coeff_4bit((byte & 0x0F) as i16);
        poly[i+1] = decompress_coeff_4bit((byte >> 4) as i16);
        idx += 1;
    }
    Ok(())
}

/// Compress to 10 bits using AVX2
#[target_feature(enable = "avx2")]
unsafe fn compress_10bit_avx2(r: &mut [u8], poly: &[i16; 256]) -> Result<()> {
    // 10-bit compression implementation
    // Pack 4 coefficients into 5 bytes
    let mut idx = 0;
    for i in (0..256).step_by(4) {
        let c0 = compress_coeff_10bit(poly[i]);
        let c1 = compress_coeff_10bit(poly[i+1]);
        let c2 = compress_coeff_10bit(poly[i+2]);
        let c3 = compress_coeff_10bit(poly[i+3]);
        
        r[idx] = c0 as u8;
        r[idx+1] = ((c0 >> 8) | (c1 << 2)) as u8;
        r[idx+2] = ((c1 >> 6) | (c2 << 4)) as u8;
        r[idx+3] = ((c2 >> 4) | (c3 << 6)) as u8;
        r[idx+4] = (c3 >> 2) as u8;
        idx += 5;
    }
    Ok(())
}

/// Decompress from 10 bits using AVX2
#[target_feature(enable = "avx2")]
unsafe fn decompress_10bit_avx2(poly: &mut [i16; 256], a: &[u8]) -> Result<()> {
    let mut idx = 0;
    for i in (0..256).step_by(4) {
        let c0 = (a[idx] as u16) | ((a[idx+1] as u16 & 0x03) << 8);
        let c1 = ((a[idx+1] as u16) >> 2) | ((a[idx+2] as u16 & 0x0F) << 6);
        let c2 = ((a[idx+2] as u16) >> 4) | ((a[idx+3] as u16 & 0x3F) << 4);
        let c3 = ((a[idx+3] as u16) >> 6) | ((a[idx+4] as u16) << 2);
        
        poly[i] = decompress_coeff_10bit(c0);
        poly[i+1] = decompress_coeff_10bit(c1);
        poly[i+2] = decompress_coeff_10bit(c2);
        poly[i+3] = decompress_coeff_10bit(c3);
        idx += 5;
    }
    Ok(())
}

/// Compress to 11 bits using AVX2
#[target_feature(enable = "avx2")]
unsafe fn compress_11bit_avx2(r: &mut [u8], poly: &[i16; 256]) -> Result<()> {
    // 11-bit compression: pack 8 coefficients into 11 bytes
    let mut idx = 0;
    for i in (0..256).step_by(8) {
        let mut coeffs = [0u16; 8];
        for j in 0..8 {
            coeffs[j] = compress_coeff_11bit(poly[i+j]);
        }
        
        r[idx] = coeffs[0] as u8;
        r[idx+1] = ((coeffs[0] >> 8) | (coeffs[1] << 3)) as u8;
        r[idx+2] = ((coeffs[1] >> 5) | (coeffs[2] << 6)) as u8;
        r[idx+3] = (coeffs[2] >> 2) as u8;
        r[idx+4] = ((coeffs[2] >> 10) | (coeffs[3] << 1)) as u8;
        r[idx+5] = ((coeffs[3] >> 7) | (coeffs[4] << 4)) as u8;
        r[idx+6] = ((coeffs[4] >> 4) | (coeffs[5] << 7)) as u8;
        r[idx+7] = (coeffs[5] >> 1) as u8;
        r[idx+8] = ((coeffs[5] >> 9) | (coeffs[6] << 2)) as u8;
        r[idx+9] = ((coeffs[6] >> 6) | (coeffs[7] << 5)) as u8;
        r[idx+10] = (coeffs[7] >> 3) as u8;
        idx += 11;
    }
    Ok(())
}

/// Decompress from 11 bits using AVX2
#[target_feature(enable = "avx2")]
unsafe fn decompress_11bit_avx2(poly: &mut [i16; 256], a: &[u8]) -> Result<()> {
    let mut idx = 0;
    for i in (0..256).step_by(8) {
        let c0 = (a[idx] as u16) | ((a[idx+1] as u16 & 0x07) << 8);
        let c1 = ((a[idx+1] as u16) >> 3) | ((a[idx+2] as u16 & 0x3F) << 5);
        let c2 = ((a[idx+2] as u16) >> 6) | ((a[idx+3] as u16) << 2) | ((a[idx+4] as u16 & 0x01) << 10);
        let c3 = ((a[idx+4] as u16) >> 1) | ((a[idx+5] as u16 & 0x0F) << 7);
        let c4 = ((a[idx+5] as u16) >> 4) | ((a[idx+6] as u16 & 0x7F) << 4);
        let c5 = ((a[idx+6] as u16) >> 7) | ((a[idx+7] as u16) << 1) | ((a[idx+8] as u16 & 0x03) << 9);
        let c6 = ((a[idx+8] as u16) >> 2) | ((a[idx+9] as u16 & 0x1F) << 6);
        let c7 = ((a[idx+9] as u16) >> 5) | ((a[idx+10] as u16) << 3);
        
        poly[i] = decompress_coeff_11bit(c0);
        poly[i+1] = decompress_coeff_11bit(c1);
        poly[i+2] = decompress_coeff_11bit(c2);
        poly[i+3] = decompress_coeff_11bit(c3);
        poly[i+4] = decompress_coeff_11bit(c4);
        poly[i+5] = decompress_coeff_11bit(c5);
        poly[i+6] = decompress_coeff_11bit(c6);
        poly[i+7] = decompress_coeff_11bit(c7);
        idx += 11;
    }
    Ok(())
}

/// Helper: Compress coefficient to 4 bits using AVX2
#[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn compress_coeff_4bit_avx2(coeffs: __m256i) -> __m256i {
    // round(16*x/q) mod 16
    let sixteen = _mm256_set1_epi16(16);
    let q_inv = _mm256_set1_epi16(20159); // Approximate 2^26/q
    
    let scaled = _mm256_mullo_epi16(coeffs, sixteen);
    let divided = _mm256_mulhi_epi16(scaled, q_inv);
    _mm256_and_si256(divided, _mm256_set1_epi16(0x0F))
}

/// Helper: Compress single coefficient to 4 bits
#[inline]
fn compress_coeff_4bit(x: i16) -> i16 {
    ((((x as i32) << 4) + Q32/2) / Q32) & 0x0F
}

/// Helper: Decompress single coefficient from 4 bits
#[inline]
fn decompress_coeff_4bit(x: i16) -> i16 {
    ((x as i32 * Q32 + 8) >> 4) as i16
}

/// Helper: Compress single coefficient to 10 bits
#[inline]
fn compress_coeff_10bit(x: i16) -> u16 {
    (((x as u32) << 10) + (Q as u32)/2) / (Q as u32) & 0x3FF
}

/// Helper: Decompress single coefficient from 10 bits
#[inline]
fn decompress_coeff_10bit(x: u16) -> i16 {
    ((x as u32 * Q as u32 + 512) >> 10) as i16
}

/// Helper: Compress single coefficient to 11 bits
#[inline]
fn compress_coeff_11bit(x: i16) -> u16 {
    (((x as u32) << 11) + (Q as u32)/2) / (Q as u32) & 0x7FF
}

/// Helper: Decompress single coefficient from 11 bits
#[inline]
fn decompress_coeff_11bit(x: u16) -> i16 {
    ((x as u32 * Q as u32 + 1024) >> 11) as i16
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_poly_add_avx2() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        
        unsafe {
            let mut a = [100i16; 256];
            let b = [200i16; 256];
            let mut r = [0i16; 256];
            
            poly_add_avx2(&mut r, &a, &b).unwrap();
            
            for i in 0..256 {
                assert_eq!(r[i], 300);
            }
        }
    }
    
    #[test]
    fn test_poly_sub_avx2() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        
        unsafe {
            let a = [500i16; 256];
            let b = [200i16; 256];
            let mut r = [0i16; 256];
            
            poly_sub_avx2(&mut r, &a, &b).unwrap();
            
            for i in 0..256 {
                assert_eq!(r[i], 300);
            }
        }
    }
    
    #[test]
    fn test_compression_roundtrip() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        
        unsafe {
            let mut poly = [0i16; 256];
            for i in 0..256 {
                poly[i] = (i as i16 * 13) % Q;
            }
            
            // Test 4-bit compression
            let mut compressed = vec![0u8; 128];
            compress_4bit_avx2(&mut compressed, &poly).unwrap();
            
            let mut decompressed = [0i16; 256];
            decompress_4bit_avx2(&mut decompressed, &compressed).unwrap();
            
            // Check approximate equality (compression is lossy)
            for i in 0..256 {
                let diff = (poly[i] - decompressed[i]).abs();
                assert!(diff < 210); // Error bound for 4-bit compression
            }
        }
    }
}