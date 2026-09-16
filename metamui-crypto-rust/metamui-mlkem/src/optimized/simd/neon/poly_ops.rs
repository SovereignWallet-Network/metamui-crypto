//! ARM NEON optimized polynomial operations for ML-KEM
//!
//! This module implements vectorized polynomial arithmetic operations
//! using ARM NEON SIMD instructions for parallel processing on ARM processors.

use std::arch::aarch64::*;
use crate::{Result, Error};

/// ML-KEM constants
mod constants {
    pub const Q: i16 = 3329;
    pub const QINV: i32 = 62209; // -q^(-1) mod 2^16  
    pub const BARRETT: i32 = 20159; // floor(2^26 / Q)
    pub const MONT: i16 = 2285; // 2^16 mod Q
}

/// NEON-optimized polynomial addition
#[target_feature(enable = "neon")]
pub unsafe fn neon_poly_add(r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
    // Process 8 coefficients at a time
    for i in (0..256).step_by(8) {
        let a_vec = vld1q_s16(a.as_ptr().add(i));
        let b_vec = vld1q_s16(b.as_ptr().add(i));
        let sum = vaddq_s16(a_vec, b_vec);
        vst1q_s16(r.as_mut_ptr().add(i), sum);
    }
    Ok(())
}

/// NEON-optimized polynomial subtraction
#[target_feature(enable = "neon")]
pub unsafe fn neon_poly_sub(r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
    // Process 8 coefficients at a time
    for i in (0..256).step_by(8) {
        let a_vec = vld1q_s16(a.as_ptr().add(i));
        let b_vec = vld1q_s16(b.as_ptr().add(i));
        let diff = vsubq_s16(a_vec, b_vec);
        vst1q_s16(r.as_mut_ptr().add(i), diff);
    }
    Ok(())
}

/// NEON-optimized base multiplication (pointwise multiplication in NTT domain)
#[target_feature(enable = "neon")]
pub unsafe fn neon_basemul(r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
    let q_vec = vdupq_n_s16(constants::Q);
    let qinv_vec = vdupq_n_s32(constants::QINV);
    
    // ML-KEM uses NTT with specific structure
    // Process pairs of coefficients for Karatsuba-like multiplication
    for i in (0..256).step_by(8) {
        // Load 8 coefficients from each polynomial
        let a_vec = vld1q_s16(a.as_ptr().add(i));
        let b_vec = vld1q_s16(b.as_ptr().add(i));
        
        // Perform Montgomery multiplication
        let prod = neon_montgomery_mul(a_vec, b_vec, q_vec, qinv_vec);
        
        // Store result
        vst1q_s16(r.as_mut_ptr().add(i), prod);
    }
    
    Ok(())
}

/// NEON Montgomery multiplication helper
#[inline(always)]
unsafe fn neon_montgomery_mul(a: int16x8_t, b: int16x8_t, q: int16x8_t, qinv: int32x4_t) -> int16x8_t {
    // Convert to 32-bit for multiplication
    let a_low = vmovl_s16(vget_low_s16(a));
    let a_high = vmovl_s16(vget_high_s16(a));
    let b_low = vmovl_s16(vget_low_s16(b));
    let b_high = vmovl_s16(vget_high_s16(b));
    
    // Multiply a * b
    let prod_low = vmulq_s32(a_low, b_low);
    let prod_high = vmulq_s32(a_high, b_high);
    
    // Montgomery reduction
    // t = (prod * QINV) & 0xFFFF
    let t_low = vmulq_s32(prod_low, qinv);
    let t_high = vmulq_s32(prod_high, qinv);
    
    // Mask to keep low 16 bits
    let mask = vdupq_n_s32(0xFFFF);
    let t_low_masked = vandq_s32(t_low, mask);
    let t_high_masked = vandq_s32(t_high, mask);
    
    // t * q
    let q32 = vdupq_n_s32(constants::Q as i32);
    let tq_low = vmulq_s32(t_low_masked, q32);
    let tq_high = vmulq_s32(t_high_masked, q32);
    
    // (prod - t*q) >> 16
    let res_low = vshrq_n_s32(vsubq_s32(prod_low, tq_low), 16);
    let res_high = vshrq_n_s32(vsubq_s32(prod_high, tq_high), 16);
    
    // Pack back to 16-bit
    let result = vcombine_s16(vmovn_s32(res_low), vmovn_s32(res_high));
    
    // Conditional reduction
    neon_cond_reduce(result, q)
}

/// NEON conditional reduction helper
#[inline(always)]
unsafe fn neon_cond_reduce(a: int16x8_t, q: int16x8_t) -> int16x8_t {
    // If a >= Q, subtract Q
    let mask_ge = vcgeq_s16(a, q);
    let q_masked = vandq_s16(q, vreinterpretq_s16_u16(mask_ge));
    let reduced = vsubq_s16(a, q_masked);
    
    // If a < 0, add Q
    let zero = vdupq_n_s16(0);
    let mask_lt = vcltq_s16(reduced, zero);
    let q_masked_neg = vandq_s16(q, vreinterpretq_s16_u16(mask_lt));
    vaddq_s16(reduced, q_masked_neg)
}

/// NEON-optimized Barrett reduction
#[target_feature(enable = "neon")]
pub unsafe fn neon_barrett_reduce(poly: &mut [i16; 256]) -> Result<()> {
    let barrett_vec = vdupq_n_s32(constants::BARRETT);
    let q_vec = vdupq_n_s16(constants::Q);
    
    for i in (0..256).step_by(8) {
        let a = vld1q_s16(poly.as_ptr().add(i));
        
        // Convert to 32-bit for Barrett reduction
        let a_low = vmovl_s16(vget_low_s16(a));
        let a_high = vmovl_s16(vget_high_s16(a));
        
        // t = (a * BARRETT) >> 26
        let t_low = vshrq_n_s32(vmulq_s32(a_low, barrett_vec), 26);
        let t_high = vshrq_n_s32(vmulq_s32(a_high, barrett_vec), 26);
        
        // Pack t back to 16-bit
        let t = vcombine_s16(vmovn_s32(t_low), vmovn_s32(t_high));
        
        // a - t * q
        let q32 = vdupq_n_s32(constants::Q as i32);
        let tq_low = vmulq_s32(t_low, q32);
        let tq_high = vmulq_s32(t_high, q32);
        
        let res_low = vsubq_s32(a_low, tq_low);
        let res_high = vsubq_s32(a_high, tq_high);
        
        let result = vcombine_s16(vmovn_s32(res_low), vmovn_s32(res_high));
        
        // Final conditional reduction
        let reduced = neon_cond_reduce(result, q_vec);
        vst1q_s16(poly.as_mut_ptr().add(i), reduced);
    }
    
    Ok(())
}

/// NEON-optimized Montgomery reduction
#[target_feature(enable = "neon")]
pub unsafe fn neon_montgomery_reduce(poly: &mut [i16; 256]) -> Result<()> {
    let qinv_vec = vdupq_n_s32(constants::QINV);
    let q_vec = vdupq_n_s16(constants::Q);
    let mont_vec = vdupq_n_s16(constants::MONT);
    
    for i in (0..256).step_by(8) {
        let a = vld1q_s16(poly.as_ptr().add(i));
        
        // Multiply by Montgomery constant R = 2^16 mod q
        let result = neon_montgomery_mul(a, mont_vec, q_vec, qinv_vec);
        
        vst1q_s16(poly.as_mut_ptr().add(i), result);
    }
    
    Ok(())
}

/// NEON-optimized polynomial compression
#[target_feature(enable = "neon")]
pub unsafe fn neon_poly_compress(r: &mut [u8], poly: &[i16; 256], bits: usize) -> Result<()> {
    match bits {
        4 => compress_4bit(r, poly),
        5 => compress_5bit(r, poly),
        10 => compress_10bit(r, poly),
        11 => compress_11bit(r, poly),
        _ => return Err(Error::InvalidInput),
    }
    Ok(())
}

/// Compress polynomial to 4 bits per coefficient
#[inline]
unsafe fn compress_4bit(r: &mut [u8], poly: &[i16; 256]) {
    let q_vec = vdupq_n_s32(constants::Q as i32);
    let round_vec = vdupq_n_s32((constants::Q as i32 + 1) / 2);
    
    for i in (0..256).step_by(2) {
        // Load 2 coefficients
        let a0 = poly[i] as i32;
        let a1 = poly[i + 1] as i32;
        
        // Compress: round((16 * a) / q)
        let round_val = vgetq_lane_s32(round_vec, 0);
        let q_val = vgetq_lane_s32(q_vec, 0);
        let c0 = ((16 * a0 + round_val) / q_val) & 0x0F;
        let c1 = ((16 * a1 + round_val) / q_val) & 0x0F;
        
        r[i / 2] = (c0 | (c1 << 4)) as u8;
    }
}

/// Compress polynomial to 5 bits per coefficient
#[inline]
unsafe fn compress_5bit(r: &mut [u8], poly: &[i16; 256]) {
    let q_vec = vdupq_n_s32(constants::Q as i32);
    let round_vec = vdupq_n_s32((constants::Q as i32 + 1) / 2);
    
    let mut bit_offset = 0;
    let mut byte_idx = 0;
    let mut current_byte = 0u8;
    
    for i in 0..256 {
        let a = poly[i] as i32;
        let round_val = vgetq_lane_s32(round_vec, 0);
        let q_val = vgetq_lane_s32(q_vec, 0);
        let compressed = ((32 * a + round_val) / q_val) & 0x1F;
        
        // Pack 5-bit values
        if bit_offset + 5 <= 8 {
            current_byte |= (compressed as u8) << bit_offset;
            bit_offset += 5;
            
            if bit_offset == 8 {
                r[byte_idx] = current_byte;
                byte_idx += 1;
                current_byte = 0;
                bit_offset = 0;
            }
        } else {
            // Split across byte boundary
            let bits_in_current = 8 - bit_offset;
            current_byte |= ((compressed as u8) & ((1 << bits_in_current) - 1)) << bit_offset;
            r[byte_idx] = current_byte;
            byte_idx += 1;
            
            current_byte = (compressed >> bits_in_current) as u8;
            bit_offset = 5 - bits_in_current;
        }
    }
    
    if bit_offset > 0 {
        r[byte_idx] = current_byte;
    }
}

/// Compress polynomial to 10 bits per coefficient
#[inline]
unsafe fn compress_10bit(r: &mut [u8], poly: &[i16; 256]) {
    let q = constants::Q as i32;
    let round = (q + 1) / 2;
    
    for i in (0..256).step_by(4) {
        // Process 4 coefficients -> 5 bytes
        let mut t = [0i32; 4];
        for j in 0..4 {
            t[j] = ((1024 * poly[i + j] as i32 + round) / q) & 0x3FF;
        }
        
        r[5 * i / 4] = t[0] as u8;
        r[5 * i / 4 + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
        r[5 * i / 4 + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
        r[5 * i / 4 + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
        r[5 * i / 4 + 4] = (t[3] >> 2) as u8;
    }
}

/// Compress polynomial to 11 bits per coefficient
#[inline]
unsafe fn compress_11bit(r: &mut [u8], poly: &[i16; 256]) {
    let q = constants::Q as i32;
    let round = (q + 1) / 2;
    
    for i in (0..256).step_by(8) {
        // Process 8 coefficients -> 11 bytes
        let mut t = [0i32; 8];
        for j in 0..8 {
            t[j] = ((2048 * poly[i + j] as i32 + round) / q) & 0x7FF;
        }
        
        r[11 * i / 8] = t[0] as u8;
        r[11 * i / 8 + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
        r[11 * i / 8 + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
        r[11 * i / 8 + 3] = (t[2] >> 2) as u8;
        r[11 * i / 8 + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
        r[11 * i / 8 + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
        r[11 * i / 8 + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
        r[11 * i / 8 + 7] = (t[5] >> 1) as u8;
        r[11 * i / 8 + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
        r[11 * i / 8 + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
        r[11 * i / 8 + 10] = (t[7] >> 3) as u8;
    }
}

/// NEON-optimized polynomial decompression
#[target_feature(enable = "neon")]
pub unsafe fn neon_poly_decompress(poly: &mut [i16; 256], a: &[u8], bits: usize) -> Result<()> {
    match bits {
        4 => decompress_4bit(poly, a),
        5 => decompress_5bit(poly, a),
        10 => decompress_10bit(poly, a),
        11 => decompress_11bit(poly, a),
        _ => return Err(Error::InvalidInput),
    }
    Ok(())
}

/// Decompress from 4 bits per coefficient
#[inline]
unsafe fn decompress_4bit(poly: &mut [i16; 256], a: &[u8]) {
    let q = constants::Q as i32;
    
    for i in 0..128 {
        let byte = a[i];
        let c0 = (byte & 0x0F) as i32;
        let c1 = ((byte >> 4) & 0x0F) as i32;
        
        // Decompress: round((q * c) / 16)
        poly[2 * i] = (((q * c0 + 8) >> 4) & 0xFFFF) as i16;
        poly[2 * i + 1] = (((q * c1 + 8) >> 4) & 0xFFFF) as i16;
    }
}

/// Decompress from 5 bits per coefficient
#[inline]
unsafe fn decompress_5bit(poly: &mut [i16; 256], a: &[u8]) {
    let q = constants::Q as i32;
    
    let mut bit_offset = 0;
    let mut byte_idx = 0;
    
    for i in 0..256 {
        // Extract 5 bits
        let mut compressed = 0u32;
        
        if bit_offset + 5 <= 8 {
            compressed = ((a[byte_idx] >> bit_offset) & 0x1F) as u32;
            bit_offset += 5;
            
            if bit_offset == 8 {
                byte_idx += 1;
                bit_offset = 0;
            }
        } else {
            // Split across byte boundary
            let bits_in_current = 8 - bit_offset;
            compressed = ((a[byte_idx] >> bit_offset) & ((1 << bits_in_current) - 1)) as u32;
            byte_idx += 1;
            
            compressed |= ((a[byte_idx] & ((1 << (5 - bits_in_current)) - 1)) as u32) << bits_in_current;
            bit_offset = 5 - bits_in_current;
        }
        
        // Decompress: round((q * c) / 32)
        poly[i] = (((q * compressed as i32 + 16) >> 5) & 0xFFFF) as i16;
    }
}

/// Decompress from 10 bits per coefficient
#[inline]
unsafe fn decompress_10bit(poly: &mut [i16; 256], a: &[u8]) {
    let q = constants::Q as i32;
    
    for i in (0..256).step_by(4) {
        // Extract 4 coefficients from 5 bytes
        let idx = 5 * i / 4;
        let mut t = [0i32; 4];
        
        t[0] = a[idx] as i32 | ((a[idx + 1] as i32 & 0x03) << 8);
        t[1] = ((a[idx + 1] as i32) >> 2) | ((a[idx + 2] as i32 & 0x0F) << 6);
        t[2] = ((a[idx + 2] as i32) >> 4) | ((a[idx + 3] as i32 & 0x3F) << 4);
        t[3] = ((a[idx + 3] as i32) >> 6) | ((a[idx + 4] as i32) << 2);
        
        for j in 0..4 {
            // Decompress: round((q * c) / 1024)
            poly[i + j] = (((q * (t[j] & 0x3FF) + 512) >> 10) & 0xFFFF) as i16;
        }
    }
}

/// Decompress from 11 bits per coefficient
#[inline]
unsafe fn decompress_11bit(poly: &mut [i16; 256], a: &[u8]) {
    let q = constants::Q as i32;
    
    for i in (0..256).step_by(8) {
        // Extract 8 coefficients from 11 bytes
        let idx = 11 * i / 8;
        let mut t = [0i32; 8];
        
        t[0] = a[idx] as i32 | ((a[idx + 1] as i32 & 0x07) << 8);
        t[1] = ((a[idx + 1] as i32) >> 3) | ((a[idx + 2] as i32 & 0x3F) << 5);
        t[2] = ((a[idx + 2] as i32) >> 6) | ((a[idx + 3] as i32) << 2) | ((a[idx + 4] as i32 & 0x01) << 10);
        t[3] = ((a[idx + 4] as i32) >> 1) | ((a[idx + 5] as i32 & 0x0F) << 7);
        t[4] = ((a[idx + 5] as i32) >> 4) | ((a[idx + 6] as i32 & 0x7F) << 4);
        t[5] = ((a[idx + 6] as i32) >> 7) | ((a[idx + 7] as i32) << 1) | ((a[idx + 8] as i32 & 0x03) << 9);
        t[6] = ((a[idx + 8] as i32) >> 2) | ((a[idx + 9] as i32 & 0x1F) << 6);
        t[7] = ((a[idx + 9] as i32) >> 5) | ((a[idx + 10] as i32) << 3);
        
        for j in 0..8 {
            // Decompress: round((q * c) / 2048)
            poly[i + j] = (((q * (t[j] & 0x7FF) + 1024) >> 11) & 0xFFFF) as i16;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_neon_poly_add() {
        let mut r = [0i16; 256];
        let mut a = [0i16; 256];
        let mut b = [0i16; 256];
        
        for i in 0..256 {
            a[i] = (i as i16) % constants::Q;
            b[i] = ((i + 100) as i16) % constants::Q;
        }
        
        unsafe {
            neon_poly_add(&mut r, &a, &b).unwrap();
        }
        
        for i in 0..256 {
            assert_eq!(r[i], a[i] + b[i]);
        }
    }
    
    #[test]
    fn test_neon_poly_sub() {
        let mut r = [0i16; 256];
        let mut a = [0i16; 256];
        let mut b = [0i16; 256];
        
        for i in 0..256 {
            a[i] = (i as i16) % constants::Q;
            b[i] = ((i + 50) as i16) % constants::Q;
        }
        
        unsafe {
            neon_poly_sub(&mut r, &a, &b).unwrap();
        }
        
        for i in 0..256 {
            assert_eq!(r[i], a[i] - b[i]);
        }
    }
    
    #[test]
    fn test_compress_decompress_roundtrip() {
        let mut poly = [0i16; 256];
        let mut compressed = vec![0u8; 256 * 11 / 8 + 1];
        let mut decompressed = [0i16; 256];
        
        // Initialize with valid values
        for i in 0..256 {
            poly[i] = (i as i16 * 13) % constants::Q;
        }
        
        unsafe {
            // Test 10-bit compression
            neon_poly_compress(&mut compressed, &poly, 10).unwrap();
            neon_poly_decompress(&mut decompressed, &compressed, 10).unwrap();
            
            // Check approximate recovery (compression is lossy)
            for i in 0..256 {
                let diff = (poly[i] - decompressed[i]).abs();
                assert!(diff < 10, "10-bit roundtrip failed at {}: {} vs {}", i, poly[i], decompressed[i]);
            }
        }
    }
}