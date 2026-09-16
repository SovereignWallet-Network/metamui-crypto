//! ARM NEON optimized NTT operations for ML-KEM
//!
//! This module implements Number Theoretic Transform operations
//! using ARM NEON SIMD instructions for improved performance.

use std::arch::aarch64::*;
use crate::Result;

/// NEON-optimized NTT constants
mod constants {
    
    
    /// ML-KEM modulus q = 3329
    pub const Q: i16 = 3329;
    pub const QINV: i32 = 62209; // -q^(-1) mod 2^16
    
    /// Montgomery reduction constant
    pub const MONT: i16 = 2285;
    
    /// Zeta values for NTT (first 64 values shown)
    pub const ZETAS: [i16; 128] = [
        2285, 2571, 2970, 1812, 1493, 1422, 287, 202,
        3158, 622, 1577, 182, 962, 2127, 1855, 1468,
        573, 2004, 264, 383, 2500, 1458, 1727, 3199,
        2648, 1017, 732, 608, 1787, 411, 3124, 1758,
        1223, 652, 2777, 1015, 2036, 1491, 3047, 1785,
        516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
        2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
        2931, 961, 1821, 2604, 448, 2264, 677, 2054,
        2226, 430, 555, 843, 2078, 871, 1550, 105,
        422, 587, 177, 3094, 3038, 2869, 1574, 1653,
        3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
        1739, 644, 2457, 349, 418, 329, 3173, 3254,
        817, 1097, 603, 610, 1322, 2044, 1864, 384,
        2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
        2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
        3221, 3021, 996, 991, 958, 1869, 1522, 1628,
    ];
}

/// NEON-optimized forward NTT transform
#[target_feature(enable = "neon")]
pub unsafe fn neon_ntt(poly: &mut [i16; 256]) -> Result<()> {
    let q_vec = vdupq_n_s16(constants::Q);
    let mut zeta_idx = 0;
    
    // NTT layers with decreasing stride
    let mut len = 128;
    while len >= 8 {
        for start in (0..256).step_by(2 * len) {
            let zeta = constants::ZETAS[zeta_idx];
            zeta_idx += 1;
            let zeta_vec = vdupq_n_s16(zeta);
            
            // Process 8 butterfly operations in parallel
            for j in (start..start + len).step_by(8) {
                // Load 8 elements from each half
                let a_vec = vld1q_s16(poly.as_ptr().add(j));
                let b_vec = vld1q_s16(poly.as_ptr().add(j + len));
                
                // Butterfly: t = zeta * b
                let t_vec = neon_montgomery_multiply(b_vec, zeta_vec, q_vec);
                
                // a' = a + t
                let a_new = vaddq_s16(a_vec, t_vec);
                // b' = a - t
                let b_new = vsubq_s16(a_vec, t_vec);
                
                // Store results
                vst1q_s16(poly.as_mut_ptr().add(j), a_new);
                vst1q_s16(poly.as_mut_ptr().add(j + len), b_new);
            }
        }
        len >>= 1;
    }
    
    // Handle remaining butterflies with scalar code
    while len >= 1 {
        for start in (0..256).step_by(2 * len) {
            let zeta = constants::ZETAS[zeta_idx];
            zeta_idx += 1;
            
            for j in start..start + len {
                let t = montgomery_multiply(zeta as i32, poly[j + len] as i32);
                let a = poly[j];
                poly[j] = a + t as i16;
                poly[j + len] = a - t as i16;
            }
        }
        len >>= 1;
    }
    
    Ok(())
}

/// NEON-optimized inverse NTT transform
#[target_feature(enable = "neon")]
pub unsafe fn neon_inv_ntt(poly: &mut [i16; 256]) -> Result<()> {
    let q_vec = vdupq_n_s16(constants::Q);
    let mut zeta_idx = 127;
    
    // Inverse NTT layers with increasing stride
    let mut len = 1;
    
    // Scalar layers for small strides
    while len < 8 {
        for start in (0..256).step_by(2 * len) {
            let zeta = constants::ZETAS[zeta_idx];
            zeta_idx = zeta_idx.wrapping_sub(1);
            
            for j in start..start + len {
                let a = poly[j];
                let b = poly[j + len];
                poly[j] = a + b;
                poly[j + len] = montgomery_multiply(zeta as i32, (a - b) as i32) as i16;
            }
        }
        len <<= 1;
    }
    
    // NEON layers for larger strides
    while len <= 128 {
        for start in (0..256).step_by(2 * len) {
            let zeta = constants::ZETAS[zeta_idx];
            zeta_idx = zeta_idx.wrapping_sub(1);
            let zeta_vec = vdupq_n_s16(zeta);
            
            for j in (start..start + len).step_by(8) {
                // Load 8 elements from each half
                let a_vec = vld1q_s16(poly.as_ptr().add(j));
                let b_vec = vld1q_s16(poly.as_ptr().add(j + len));
                
                // Inverse butterfly
                let sum = vaddq_s16(a_vec, b_vec);
                let diff = vsubq_s16(a_vec, b_vec);
                let prod = neon_montgomery_multiply(diff, zeta_vec, q_vec);
                
                // Store results
                vst1q_s16(poly.as_mut_ptr().add(j), sum);
                vst1q_s16(poly.as_mut_ptr().add(j + len), prod);
            }
        }
        len <<= 1;
    }
    
    // Final scaling by n^(-1) mod q
    let ninv = 3303i16; // 256^(-1) mod 3329
    let ninv_vec = vdupq_n_s16(ninv);
    
    for i in (0..256).step_by(8) {
        let vals = vld1q_s16(poly.as_ptr().add(i));
        let scaled = neon_montgomery_multiply(vals, ninv_vec, q_vec);
        vst1q_s16(poly.as_mut_ptr().add(i), scaled);
    }
    
    Ok(())
}

/// NEON Montgomery multiplication helper
#[inline(always)]
unsafe fn neon_montgomery_multiply(a: int16x8_t, b: int16x8_t, q: int16x8_t) -> int16x8_t {
    // Convert to 32-bit for multiplication
    let a_low = vmovl_s16(vget_low_s16(a));
    let a_high = vmovl_s16(vget_high_s16(a));
    let b_low = vmovl_s16(vget_low_s16(b));
    let b_high = vmovl_s16(vget_high_s16(b));
    
    // Multiply
    let prod_low = vmulq_s32(a_low, b_low);
    let prod_high = vmulq_s32(a_high, b_high);
    
    // Montgomery reduction
    let qinv = vdupq_n_s32(constants::QINV);
    let q32 = vdupq_n_s32(constants::Q as i32);
    
    // Compute t = (prod * QINV) mod 2^16
    let t_low = vmulq_s32(prod_low, qinv);
    let t_high = vmulq_s32(prod_high, qinv);
    
    // Take low 16 bits by masking
    let mask = vdupq_n_s32(0xFFFF);
    let t_low_masked = vandq_s32(t_low, mask);
    let t_high_masked = vandq_s32(t_high, mask);
    
    // Compute t*q
    let t_q_low = vmulq_s32(t_low_masked, q32);
    let t_q_high = vmulq_s32(t_high_masked, q32);
    
    // Compute (prod - t*q) >> 16
    let res_low = vshrq_n_s32(vsubq_s32(prod_low, t_q_low), 16);
    let res_high = vshrq_n_s32(vsubq_s32(prod_high, t_q_high), 16);
    
    // Pack back to 16-bit
    let result_16 = vcombine_s16(vmovn_s32(res_low), vmovn_s32(res_high));
    
    // Conditional reduction: if result >= Q, subtract Q
    let mask_ge = vcgeq_s16(result_16, q);
    let q_masked = vandq_s16(q, vreinterpretq_s16_u16(mask_ge));
    let result_reduced = vsubq_s16(result_16, q_masked);
    
    // Handle negative values: if result < 0, add Q
    let zero = vdupq_n_s16(0);
    let mask_lt = vcltq_s16(result_reduced, zero);
    let q_masked_neg = vandq_s16(q, vreinterpretq_s16_u16(mask_lt));
    vaddq_s16(result_reduced, q_masked_neg)
}

/// Scalar Montgomery multiplication (fallback for non-vectorizable parts)
#[inline(always)]
fn montgomery_multiply(a: i32, b: i32) -> i32 {
    let prod = a * b;
    // Montgomery reduction: t = (prod * QINV) mod 2^16
    let t = ((prod as i64 * constants::QINV as i64) & 0xFFFF) as i32;
    // Compute (prod - t * q) >> 16
    let mut result = (prod - t * constants::Q as i32) >> 16;
    
    // Conditional reduction to ensure result is in [0, Q)
    if result >= constants::Q as i32 {
        result -= constants::Q as i32;
    }
    if result < 0 {
        result += constants::Q as i32;
    }
    
    result
}

/// NEON-optimized butterfly operation
#[target_feature(enable = "neon")]
pub unsafe fn neon_butterfly(
    poly: &mut [i16],
    start: usize,
    len: usize,
    zeta: i16,
) -> Result<()> {
    if len >= 8 {
        let zeta_vec = vdupq_n_s16(zeta);
        let q_vec = vdupq_n_s16(constants::Q);
        
        for j in (start..start + len).step_by(8) {
            let a_vec = vld1q_s16(poly.as_ptr().add(j));
            let b_vec = vld1q_s16(poly.as_ptr().add(j + len));
            
            let t_vec = neon_montgomery_multiply(b_vec, zeta_vec, q_vec);
            
            let a_new = vaddq_s16(a_vec, t_vec);
            let b_new = vsubq_s16(a_vec, t_vec);
            
            vst1q_s16(poly.as_mut_ptr().add(j), a_new);
            vst1q_s16(poly.as_mut_ptr().add(j + len), b_new);
        }
    } else {
        // Fallback to scalar for small sizes
        for j in start..start + len {
            let t = montgomery_multiply(zeta as i32, poly[j + len] as i32);
            let a = poly[j];
            poly[j] = a + t as i16;
            poly[j + len] = a - t as i16;
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_neon_ntt_inverse() {
        let mut poly = [0i16; 256];
        for i in 0..256 {
            poly[i] = (i as i16) % constants::Q;
        }
        
        let original = poly.clone();
        
        unsafe {
            neon_ntt(&mut poly).unwrap();
            neon_inv_ntt(&mut poly).unwrap();
        }
        
        // Check if NTT followed by inverse NTT recovers original
        for i in 0..256 {
            let diff = (poly[i] - original[i]).abs();
            assert!(diff < 2, "NTT inverse failed at index {}: {} vs {}", 
                    i, poly[i], original[i]);
        }
    }
}