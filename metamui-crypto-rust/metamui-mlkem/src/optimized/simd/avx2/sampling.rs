//! AVX2-optimized sampling operations for ML-KEM
//!
//! This module provides vectorized CBD sampling and uniform sampling
//! using AVX2 instructions for parallel processing.

use crate::Result;
use core::arch::x86_64::*;
use sha3::{Shake128, Shake256};
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// AVX2-optimized CBD (Centered Binomial Distribution) sampling with eta=2
#[target_feature(enable = "avx2")]
pub unsafe fn cbd_eta2_avx2(poly: &mut [i16; 256], buf: &[u8]) -> Result<()> {
    // CBD with eta=2: sample from {-2, -1, 0, 1, 2}
    // Process 32 bytes at a time to generate 64 coefficients
    
    let mut idx = 0;
    for chunk in buf.chunks_exact(32) {
        if idx >= 256 {
            break;
        }
        
        // Load 32 bytes
        let data1 = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
        
        // Process pairs of bytes for CBD
        let coeffs = cbd_eta2_process_avx2(data1);
        
        // Store results
        let mut temp = [0i16; 16];
        _mm256_storeu_si256(temp.as_mut_ptr() as *mut __m256i, coeffs);
        
        for (j, &coeff) in temp.iter().enumerate() {
            if idx + j < 256 {
                poly[idx + j] = coeff;
            }
        }
        idx += 16;
    }
    
    // Handle remaining coefficients with scalar code
    while idx < 256 && idx/2 < buf.len() {
        let byte_idx = idx / 2;
        if byte_idx < buf.len() {
            let a = count_ones_2bit(buf[byte_idx] & 0x55);
            let b = count_ones_2bit((buf[byte_idx] >> 1) & 0x55);
            poly[idx] = (a as i16) - (b as i16);
            idx += 1;
            
            if idx < 256 {
                let a = count_ones_2bit((buf[byte_idx] >> 4) & 0x55);
                let b = count_ones_2bit((buf[byte_idx] >> 5) & 0x55);
                poly[idx] = (a as i16) - (b as i16);
                idx += 1;
            }
        }
    }
    
    Ok(())
}

/// Process CBD eta=2 using AVX2
#[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn cbd_eta2_process_avx2(data: __m256i) -> __m256i {
    // Extract bit pairs and compute differences
    let mask_55 = _mm256_set1_epi8(0x55);
    let mask_aa = _mm256_set1_epi8(0xAA as u8 as i8);
    
    // Get alternating bits
    let a = _mm256_and_si256(data, mask_55);
    let b = _mm256_and_si256(_mm256_srli_epi16(data, 1), mask_55);
    
    // Count bits (population count)
    let a_count = popcount_bytes_avx2(a);
    let b_count = popcount_bytes_avx2(b);
    
    // Compute a - b
    _mm256_sub_epi16(a_count, b_count)
}

/// Population count for bytes using AVX2
#[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn popcount_bytes_avx2(x: __m256i) -> __m256i {
    // Lookup table for population count of 4-bit values
    let lookup = _mm256_setr_epi8(
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4
    );
    
    let mask_0f = _mm256_set1_epi8(0x0F);
    
    // Split into 4-bit chunks
    let lo = _mm256_and_si256(x, mask_0f);
    let hi = _mm256_and_si256(_mm256_srli_epi16(x, 4), mask_0f);
    
    // Lookup population count
    let lo_count = _mm256_shuffle_epi8(lookup, lo);
    let hi_count = _mm256_shuffle_epi8(lookup, hi);
    
    // Sum the counts and convert to 16-bit
    let sum = _mm256_add_epi8(lo_count, hi_count);
    _mm256_cvtepi8_epi16(_mm256_extracti128_si256(sum, 0))
}

/// AVX2-optimized uniform sampling
#[target_feature(enable = "avx2")]
pub unsafe fn uniform_sample_avx2(poly: &mut [i16; 256], seed: &[u8], nonce: u8) -> Result<()> {
    // Use SHAKE128 for uniform sampling
    let mut hasher = Shake128::default();
    hasher.update(seed);
    hasher.update(&[nonce]);
    let mut reader = hasher.finalize_xof();
    
    let mut idx = 0;
    let mut buf = [0u8; 168]; // SHAKE128 rate
    
    while idx < 256 {
        reader.read(&mut buf);
        
        // Process buffer with AVX2
        for chunk in buf.chunks_exact(3) {
            if idx >= 256 {
                break;
            }
            
            // Sample from 3 bytes
            let d1 = chunk[0] as u16 + 256 * (chunk[1] as u16 & 0x0F);
            let d2 = (chunk[1] >> 4) as u16 + 16 * chunk[2] as u16;
            
            // Rejection sampling
            if d1 < 3329 {
                poly[idx] = d1 as i16;
                idx += 1;
            }
            if idx < 256 && d2 < 3329 {
                poly[idx] = d2 as i16;
                idx += 1;
            }
        }
    }
    
    Ok(())
}

/// Helper: Count ones in 2-bit pairs
#[inline]
fn count_ones_2bit(x: u8) -> u8 {
    let a = x & 0x55;
    let b = (x >> 1) & 0x55;
    a.count_ones() as u8
}

/// AVX2-optimized rejection sampling from uniform bytes
#[target_feature(enable = "avx2")]
pub unsafe fn rejection_sample_avx2(
    output: &mut [i16],
    input: &[u8],
    n: usize,
    q: i16
) -> usize {
    let q_vec = _mm256_set1_epi16(q);
    let mut out_idx = 0;
    let mut in_idx = 0;
    
    while out_idx < n && in_idx + 32 <= input.len() {
        // Load 32 bytes
        let data = _mm256_loadu_si256(input[in_idx..].as_ptr() as *const __m256i);
        
        // Convert to 16-bit values
        let vals_lo = _mm256_cvtepu8_epi16(_mm256_extracti128_si256(data, 0));
        let vals_hi = _mm256_cvtepu8_epi16(_mm256_extracti128_si256(data, 1));
        
        // Scale to 12-bit values (multiply by 16)
        let scaled_lo = _mm256_slli_epi16(vals_lo, 4);
        let scaled_hi = _mm256_slli_epi16(vals_hi, 4);
        
        // Add next byte bits
        if in_idx + 16 < input.len() {
            let extra = _mm_loadu_si128(input[in_idx + 16..].as_ptr() as *const __m128i);
            let extra_lo = _mm256_cvtepu8_epi16(extra);
            let extra_shifted = _mm256_srli_epi16(extra_lo, 4);
            let vals_combined = _mm256_or_si256(scaled_lo, extra_shifted);
            
            // Rejection sampling with comparison mask
            let mask = _mm256_cmpgt_epi16(q_vec, vals_combined);
            
            // Store valid samples
            let mut temp = [0i16; 16];
            _mm256_storeu_si256(temp.as_mut_ptr() as *mut __m256i, vals_combined);
            let mut mask_arr = [0i16; 16];
            _mm256_storeu_si256(mask_arr.as_mut_ptr() as *mut __m256i, mask);
            
            for i in 0..16 {
                if out_idx >= n {
                    break;
                }
                if mask_arr[i] != 0 {
                    output[out_idx] = temp[i];
                    out_idx += 1;
                }
            }
        }
        
        in_idx += 24; // 3 bytes per 2 potential samples
    }
    
    // Handle remaining with scalar code
    while out_idx < n && in_idx + 2 < input.len() {
        let val = (input[in_idx] as u16) | ((input[in_idx + 1] as u16) << 8);
        let val = val & 0x0FFF; // 12-bit value
        if val < q as u16 {
            output[out_idx] = val as i16;
            out_idx += 1;
        }
        in_idx += 3;
    }
    
    out_idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    
    #[test]
    fn test_cbd_eta2() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        
        unsafe {
            let mut rng = rand::thread_rng();
            let buf: Vec<u8> = (0..128).map(|_| rng.gen()).collect();
            let mut poly = [0i16; 256];
            
            cbd_eta2_avx2(&mut poly, &buf).unwrap();
            
            // Check that all coefficients are in range [-2, 2]
            for &coeff in &poly {
                assert!(coeff >= -2 && coeff <= 2);
            }
        }
    }
    
    #[test]
    fn test_uniform_sampling() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        
        unsafe {
            let seed = [0u8; 32];
            let mut poly = [0i16; 256];
            
            uniform_sample_avx2(&mut poly, &seed, 0).unwrap();
            
            // Check that all coefficients are in range [0, q)
            for &coeff in &poly {
                assert!(coeff >= 0 && coeff < 3329);
            }
        }
    }
    
    #[test]
    fn test_rejection_sampling() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        
        unsafe {
            let mut rng = rand::thread_rng();
            let input: Vec<u8> = (0..512).map(|_| rng.gen()).collect();
            let mut output = [0i16; 256];
            
            let count = rejection_sample_avx2(&mut output, &input, 256, 3329);
            
            // Check that we got some valid samples
            assert!(count > 0);
            assert!(count <= 256);
            
            // Check that all samples are in range
            for i in 0..count {
                assert!(output[i] >= 0 && output[i] < 3329);
            }
        }
    }
}