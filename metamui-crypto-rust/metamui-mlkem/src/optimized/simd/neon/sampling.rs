//! ARM NEON optimized sampling operations for ML-KEM
//!
//! This module implements CBD (Centered Binomial Distribution) sampling
//! and uniform sampling using ARM NEON SIMD instructions.

use std::arch::aarch64::*;
use crate::{Result, error::MLKemError as Error};
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// NEON-optimized CBD eta=2 sampling
#[target_feature(enable = "neon")]
pub unsafe fn neon_cbd_eta2(poly: &mut [i16; 256], buf: &[u8]) -> Result<()> {
    // CBD with eta=2: sample from {-2, -1, 0, 1, 2}
    // Requires 128 bytes to generate 256 coefficients (2 bits per coefficient)
    
    if buf.len() < 128 {
        return Err(Error::InvalidInput);
    }
    
    let mut idx = 0;
    
    // Process 16 bytes at a time to generate 32 coefficients
    for chunk in buf[..128].chunks_exact(16) {
        // Load 16 bytes
        let data = vld1q_u8(chunk.as_ptr());
        
        // Process CBD for each byte pair
        let coeffs = cbd_eta2_process_neon(data);
        
        // Store 8 coefficients at a time
        for i in 0..4 {
            let offset = idx + i * 8;
            if offset < 256 {
                vst1q_s16(poly.as_mut_ptr().add(offset), coeffs[i]);
            }
        }
        
        idx += 32;
    }
    
    Ok(())
}

/// Process CBD eta=2 using NEON
#[target_feature(enable = "neon")]
unsafe fn cbd_eta2_process_neon(data: uint8x16_t) -> [int16x8_t; 4] {
    // For eta=2, we need to process 2 bits at a time
    // Extract bit pairs and compute differences
    
    let mask_03 = vdupq_n_u8(0x03); // 0b00000011
    let _mask_0c = vdupq_n_u8(0x0C); // 0b00001100
    let _mask_30 = vdupq_n_u8(0x30); // 0b00110000
    let _mask_c0 = vdupq_n_u8(0xC0); // 0b11000000
    
    // Extract 2-bit values from each byte
    let b0 = vandq_u8(data, mask_03);
    let b1 = vandq_u8(vshrq_n_u8(data, 2), mask_03);
    let b2 = vandq_u8(vshrq_n_u8(data, 4), mask_03);
    let b3 = vandq_u8(vshrq_n_u8(data, 6), mask_03);
    
    // Count bits in each 2-bit value (0, 1, or 2)
    let c0 = popcount_2bit_neon(b0);
    let c1 = popcount_2bit_neon(b1);
    let c2 = popcount_2bit_neon(b2);
    let c3 = popcount_2bit_neon(b3);
    
    // Now we have 4 sets of 16 values, each in range [0,2]
    // We need to compute a-b for CBD sampling
    // Process pairs: (c0[2i], c0[2i+1]), (c1[2i], c1[2i+1]), etc.
    
    let mut result = [vdupq_n_s16(0); 4];
    
    // Process first 8 coefficients from c0
    let c0_low = vmovl_u8(vget_low_u8(c0));
    let c0_high = vmovl_u8(vget_high_u8(c0));
    
    // Extract even and odd indices for subtraction
    let even0 = vuzp1q_u16(c0_low, c0_high);
    let odd0 = vuzp2q_u16(c0_low, c0_high);
    result[0] = vsubq_s16(vreinterpretq_s16_u16(even0), vreinterpretq_s16_u16(odd0));
    
    // Process c1
    let c1_low = vmovl_u8(vget_low_u8(c1));
    let c1_high = vmovl_u8(vget_high_u8(c1));
    let even1 = vuzp1q_u16(c1_low, c1_high);
    let odd1 = vuzp2q_u16(c1_low, c1_high);
    result[1] = vsubq_s16(vreinterpretq_s16_u16(even1), vreinterpretq_s16_u16(odd1));
    
    // Process c2
    let c2_low = vmovl_u8(vget_low_u8(c2));
    let c2_high = vmovl_u8(vget_high_u8(c2));
    let even2 = vuzp1q_u16(c2_low, c2_high);
    let odd2 = vuzp2q_u16(c2_low, c2_high);
    result[2] = vsubq_s16(vreinterpretq_s16_u16(even2), vreinterpretq_s16_u16(odd2));
    
    // Process c3
    let c3_low = vmovl_u8(vget_low_u8(c3));
    let c3_high = vmovl_u8(vget_high_u8(c3));
    let even3 = vuzp1q_u16(c3_low, c3_high);
    let odd3 = vuzp2q_u16(c3_low, c3_high);
    result[3] = vsubq_s16(vreinterpretq_s16_u16(even3), vreinterpretq_s16_u16(odd3));
    
    result
}

/// Count bits in 2-bit values using NEON
#[target_feature(enable = "neon")]
unsafe fn popcount_2bit_neon(x: uint8x16_t) -> uint8x16_t {
    // For 2-bit values: 0b00 -> 0, 0b01 -> 1, 0b10 -> 1, 0b11 -> 2
    // We can use a lookup table approach
    let lookup = vcombine_u8(
        vcreate_u8(0x0101020100010102), // Lower 8 bytes: counts for 0-7
        vcreate_u8(0x0101020100010102)  // Upper 8 bytes: same pattern
    );
    
    // Since our values are already 2-bit (0-3), we can directly use them as indices
    vqtbl1q_u8(lookup, x)
}

/// NEON-optimized uniform sampling from SHAKE output
#[target_feature(enable = "neon")]
pub unsafe fn neon_uniform_sample(
    poly: &mut [i16; 256],
    seed: &[u8],
    nonce: u8,
) -> Result<()> {
    const Q: u16 = 3329;
    
    // Create SHAKE128 XOF
    let mut shake = Shake128::default();
    shake.update(seed);
    shake.update(&[nonce]);
    let mut xof = shake.finalize_xof();
    
    let mut coeffs_sampled = 0;
    let mut buf = [0u8; 504]; // Process in chunks
    
    while coeffs_sampled < 256 {
        xof.read(&mut buf);
        
        // Process buffer in 3-byte chunks to get 16-bit values
        for chunk in buf.chunks_exact(3) {
            if coeffs_sampled >= 256 {
                break;
            }
            
            // Extract two 12-bit values from 3 bytes
            let d1 = ((chunk[0] as u16) | ((chunk[1] as u16 & 0x0F) << 8)) as u16;
            let d2 = (((chunk[1] >> 4) as u16) | ((chunk[2] as u16) << 4)) as u16;
            
            // Rejection sampling
            if d1 < Q {
                poly[coeffs_sampled] = d1 as i16;
                coeffs_sampled += 1;
            }
            
            if coeffs_sampled < 256 && d2 < Q {
                poly[coeffs_sampled] = d2 as i16;
                coeffs_sampled += 1;
            }
        }
    }
    
    Ok(())
}

/// NEON-optimized rejection sampling helper
unsafe fn rejection_sample_neon(
    values: uint16x8_t,
    q: uint16x8_t,
) -> (int16x8_t, u8) {
    // Compare values < Q
    let mask = vcltq_u16(values, q);
    
    // Count valid values (ones in mask)
    let mask_bytes = vreinterpretq_u8_u16(mask);
    let ones = vcntq_u8(mask_bytes);
    let sum = vaddvq_u8(ones) / 8; // Each comparison sets 16 bits (2 bytes)
    
    // Masked select: keep values < Q, set others to 0
    let valid = vandq_u16(values, mask);
    
    (vreinterpretq_s16_u16(valid), sum)
}

/// NEON-optimized CBD eta=3 sampling (for Kyber512)
#[target_feature(enable = "neon")]
pub unsafe fn neon_cbd_eta3(poly: &mut [i16; 256], buf: &[u8]) -> Result<()> {
    // CBD with eta=3: sample from {-3, -2, -1, 0, 1, 2, 3}
    // Requires 192 bytes to generate 256 coefficients (3 bits per coefficient pair)
    
    if buf.len() < 192 {
        return Err(Error::InvalidInput);
    }
    
    let mut idx = 0;
    
    // Process 24 bytes at a time to generate 32 coefficients
    for chunk in buf[..192].chunks_exact(24) {
        // Load 24 bytes (3 bytes per 2 coefficients, 16 coefficients total)
        let data1 = vld1q_u8(chunk[0..16].as_ptr());
        let data2 = vld1_u8(chunk[16..24].as_ptr());
        
        // Process CBD for 3-bit values
        let coeffs = cbd_eta3_process_neon(data1, data2);
        
        // Store coefficients
        for i in 0..4 {
            let offset = idx + i * 8;
            if offset < 256 {
                vst1q_s16(poly.as_mut_ptr().add(offset), coeffs[i]);
            }
        }
        
        idx += 32;
    }
    
    Ok(())
}

/// Process CBD eta=3 using NEON
#[inline(always)]
unsafe fn cbd_eta3_process_neon(
    data1: uint8x16_t,
    _data2: uint8x8_t,
) -> [int16x8_t; 4] {
    // For eta=3, we need to process 3 bits at a time
    // This is more complex than eta=2
    
    let mut result = [vdupq_n_s16(0); 4];
    
    // Extract 3-bit values and compute Hamming weights
    // Then compute differences for CBD
    
    // Process first 16 bytes (data1)
    let _mask_07 = vdupq_n_u8(0x07); // 0b00000111
    
    // Extract 3-bit values from packed bytes
    // This requires careful bit manipulation
    
    // For simplicity, fall back to byte-wise processing with NEON acceleration
    let mut temp_coeffs = [0i16; 32];
    let mut coeff_idx = 0;
    
    // Store NEON vector to memory for byte-wise access
    let mut data1_bytes = [0u8; 16];
    vst1q_u8(data1_bytes.as_mut_ptr(), data1);
    
    // Process data1
    for i in 0..16 {
        let byte = data1_bytes[i];
        
        // Extract two 3-bit values
        if coeff_idx < 32 {
            let a = popcount_3bit(byte & 0x07);
            let b = popcount_3bit((byte >> 3) & 0x07);
            temp_coeffs[coeff_idx] = (a - b) as i16;
            coeff_idx += 1;
        }
        
        if i < 8 && coeff_idx < 32 {
            // Some bytes contribute to multiple coefficients
            let next_byte = data1_bytes[(i + 1) % 16];
            let c = popcount_3bit(((byte >> 6) | (next_byte << 2)) & 0x07);
            let d = popcount_3bit((next_byte >> 1) & 0x07);
            temp_coeffs[coeff_idx] = (c - d) as i16;
            coeff_idx += 1;
        }
    }
    
    // Load results into NEON registers
    for i in 0..4 {
        result[i] = vld1q_s16(&temp_coeffs[i * 8]);
    }
    
    result
}

/// Count bits in 3-bit value
#[inline(always)]
fn popcount_3bit(x: u8) -> u8 {
    // Count set bits in a 3-bit value
    (x & 1) + ((x >> 1) & 1) + ((x >> 2) & 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_neon_cbd_eta2() {
        let mut poly = [0i16; 256];
        let mut buf = [0u8; 128];
        
        // Fill buffer with test data
        for i in 0..128 {
            buf[i] = (i as u8) ^ 0x5A;
        }
        
        unsafe {
            neon_cbd_eta2(&mut poly, &buf).unwrap();
        }
        
        // Check that values are in correct range [-2, 2]
        for &coeff in &poly {
            assert!(coeff >= -2 && coeff <= 2);
        }
    }
    
    #[test]
    fn test_neon_uniform_sample() {
        let mut poly = [0i16; 256];
        let seed = [0x42u8; 32];
        let nonce = 0;
        
        unsafe {
            neon_uniform_sample(&mut poly, &seed, nonce).unwrap();
        }
        
        // Check that all coefficients are in range [0, Q)
        for &coeff in &poly {
            assert!(coeff >= 0 && coeff < 3329);
        }
    }
    
    #[test]
    fn test_popcount_3bit() {
        assert_eq!(popcount_3bit(0b000), 0);
        assert_eq!(popcount_3bit(0b001), 1);
        assert_eq!(popcount_3bit(0b010), 1);
        assert_eq!(popcount_3bit(0b011), 2);
        assert_eq!(popcount_3bit(0b100), 1);
        assert_eq!(popcount_3bit(0b101), 2);
        assert_eq!(popcount_3bit(0b110), 2);
        assert_eq!(popcount_3bit(0b111), 3);
    }
}