//! AVX2-optimized NTT and inverse NTT operations for ML-KEM
//!
//! This module provides highly optimized NTT operations using AVX2 SIMD instructions
//! for parallel butterfly computations with 8x parallelism.

use crate::Result;
use core::arch::x86_64::*;
use super::constants::*;

/// Zeta values for NTT (precomputed twiddle factors)
#[repr(align(32))]
static ZETAS: [i16; 128] = [
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

/// Inverse zeta values for inverse NTT
#[repr(align(32))]
static INV_ZETAS: [i16; 128] = [
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108,
    2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109, 874, 1335, 2111, 136, 1215,
    2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
    75, 156, 3000, 2911, 2980, 872, 2685, 1590,
    2210, 602, 1846, 777, 147, 2170, 2551, 246,
    1676, 1755, 460, 291, 235, 3152, 2742, 2907,
    3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
    1275, 2652, 1065, 2881, 725, 1508, 2368, 398,
    951, 247, 1421, 3222, 2499, 271, 90, 853,
    1860, 3203, 1162, 1618, 666, 320, 8, 2813,
    1544, 282, 1838, 1293, 2314, 552, 2677, 2106,
    1571, 205, 2918, 1542, 2721, 2597, 2312, 681,
    130, 1602, 1871, 829, 2946, 3065, 1325, 2756,
    1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
    3127, 3042, 1907, 1836, 1517, 359, 758, 1441,
];

/// AVX2 Montgomery multiplication for 16 coefficients
#[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn montgomery_mul_avx2(a: __m256i, b: __m256i) -> __m256i {
    let q = vq();
    let qinv = vqinv();
    
    // Multiply to get 32-bit results
    let lo = _mm256_mullo_epi16(a, b);
    let hi = _mm256_mulhi_epi16(a, b);
    
    // Interleave to get 32-bit products
    let prod_lo = _mm256_unpacklo_epi16(lo, hi);
    let prod_hi = _mm256_unpackhi_epi16(lo, hi);
    
    // Montgomery reduction
    let t_lo = _mm256_mullo_epi16(prod_lo, _mm256_set1_epi32(QINV as i32));
    let t_hi = _mm256_mullo_epi16(prod_hi, _mm256_set1_epi32(QINV as i32));
    
    let m_lo = _mm256_mulhi_epi16(t_lo, _mm256_set1_epi32(Q32));
    let m_hi = _mm256_mulhi_epi16(t_hi, _mm256_set1_epi32(Q32));
    
    // Pack back to 16-bit
    _mm256_packs_epi32(
        _mm256_sub_epi32(prod_lo, m_lo),
        _mm256_sub_epi32(prod_hi, m_hi)
    )
}

/// AVX2 Barrett reduction for 16 coefficients
#[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn barrett_reduce_avx2(a: __m256i) -> __m256i {
    let v = vbarrett();
    let q = vq();
    
    // Sign extend to 32-bit for proper arithmetic
    let a_lo = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(a, 0));
    let a_hi = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(a, 1));
    
    // Barrett reduction: t = ((a * v) >> 26) * q
    let t_lo = _mm256_srai_epi32(_mm256_mullo_epi32(a_lo, v), 26);
    let t_hi = _mm256_srai_epi32(_mm256_mullo_epi32(a_hi, v), 26);
    
    let r_lo = _mm256_sub_epi32(a_lo, _mm256_mullo_epi32(t_lo, _mm256_set1_epi32(Q32)));
    let r_hi = _mm256_sub_epi32(a_hi, _mm256_mullo_epi32(t_hi, _mm256_set1_epi32(Q32)));
    
    // Pack back to 16-bit
    _mm256_packs_epi32(r_lo, r_hi)
}

/// Butterfly operation for NTT
#[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn butterfly_avx2(a: &mut __m256i, b: &mut __m256i, zeta: __m256i) {
    let t = montgomery_mul_avx2(*b, zeta);
    *b = _mm256_sub_epi16(*a, t);
    *a = _mm256_add_epi16(*a, t);
}

/// Inverse butterfly operation for inverse NTT
#[inline(always)]
#[target_feature(enable = "avx2")]
unsafe fn inv_butterfly_avx2(a: &mut __m256i, b: &mut __m256i, zeta: __m256i) {
    let t = *b;
    *b = _mm256_sub_epi16(*a, t);
    *b = montgomery_mul_avx2(*b, zeta);
    *a = _mm256_add_epi16(*a, t);
}

/// AVX2-optimized NTT forward transform
#[target_feature(enable = "avx2")]
pub unsafe fn ntt_avx2(poly: &mut [i16; 256]) -> Result<()> {
    // Process 16 coefficients at a time using AVX2
    let mut k = 1;
    let mut len = 128;
    
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = _mm256_set1_epi16(ZETAS[k]);
            k += 1;
            
            // Process 16 coefficients in parallel when possible
            if len >= 16 {
                for j in (start..start + len).step_by(16) {
                    let mut a = _mm256_loadu_si256(poly[j..].as_ptr() as *const __m256i);
                    let mut b = _mm256_loadu_si256(poly[j + len..].as_ptr() as *const __m256i);
                    
                    butterfly_avx2(&mut a, &mut b, zeta);
                    
                    _mm256_storeu_si256(poly[j..].as_mut_ptr() as *mut __m256i, a);
                    _mm256_storeu_si256(poly[j + len..].as_mut_ptr() as *mut __m256i, b);
                }
            } else {
                // Fall back to smaller operations for final stages
                for j in start..start + len {
                    let t = montgomery_multiply(ZETAS[k-1] as i32, poly[j + len] as i32);
                    poly[j + len] = poly[j] - t as i16;
                    poly[j] = poly[j] + t as i16;
                }
            }
            start += 2 * len;
        }
        len >>= 1;
    }
    
    // Final reduction
    for chunk in poly.chunks_mut(16) {
        if chunk.len() == 16 {
            let a = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
            let reduced = barrett_reduce_avx2(a);
            _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, reduced);
        } else {
            // Handle remainder
            for coeff in chunk {
                *coeff = barrett_reduce(*coeff as i32) as i16;
            }
        }
    }
    
    Ok(())
}

/// AVX2-optimized inverse NTT transform
#[target_feature(enable = "avx2")]
pub unsafe fn inv_ntt_avx2(poly: &mut [i16; 256]) -> Result<()> {
    let mut k = 127;
    let mut len = 2;
    
    // Inverse NTT layers
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = _mm256_set1_epi16(INV_ZETAS[k]);
            k = k.wrapping_sub(1);
            
            // Process 16 coefficients in parallel when possible
            if len >= 16 && start + 2*len <= 256 {
                for j in (start..start + len).step_by(16).take((len.min(16) + 15) / 16) {
                    let mut a = _mm256_loadu_si256(poly[j..].as_ptr() as *const __m256i);
                    let mut b = _mm256_loadu_si256(poly[j + len..].as_ptr() as *const __m256i);
                    
                    inv_butterfly_avx2(&mut a, &mut b, zeta);
                    
                    _mm256_storeu_si256(poly[j..].as_mut_ptr() as *mut __m256i, a);
                    _mm256_storeu_si256(poly[j + len..].as_mut_ptr() as *mut __m256i, b);
                }
            } else {
                // Fall back to scalar for small/edge cases
                for j in start..start + len {
                    let t = poly[j + len];
                    poly[j + len] = poly[j] - t;
                    poly[j + len] = montgomery_multiply(INV_ZETAS[k+1] as i32, poly[j + len] as i32) as i16;
                    poly[j] = poly[j] + t;
                }
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    
    // Scale by 1/n
    let inv_n = _mm256_set1_epi16(3303); // Precomputed 1/256 mod q in Montgomery form
    for chunk in poly.chunks_mut(16) {
        if chunk.len() == 16 {
            let a = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
            let scaled = montgomery_mul_avx2(a, inv_n);
            let reduced = barrett_reduce_avx2(scaled);
            _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, reduced);
        } else {
            for coeff in chunk {
                *coeff = montgomery_multiply(3303, *coeff as i32) as i16;
                *coeff = barrett_reduce(*coeff as i32) as i16;
            }
        }
    }
    
    Ok(())
}

/// Scalar Montgomery multiplication (fallback)
#[inline]
fn montgomery_multiply(a: i32, b: i32) -> i32 {
    let t = a as i64 * b as i64;
    let m = ((t as i32).wrapping_mul(QINV as i32) & 0xFFFF) as i64;
    ((t - m * Q as i64) >> 16) as i32
}

/// Scalar Barrett reduction (fallback)  
#[inline]
fn barrett_reduce(a: i32) -> i32 {
    let t = ((a as i64 * BARRETT_V as i64) >> 26) as i32;
    a - t * Q32
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    
    #[test]
    fn test_ntt_inverse() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        
        unsafe {
            let mut rng = rand::thread_rng();
            let mut poly = [0i16; 256];
            let mut original = [0i16; 256];
            
            // Generate random polynomial
            for i in 0..256 {
                poly[i] = rng.gen_range(-Q..Q) as i16;
                original[i] = poly[i];
            }
            
            // Forward NTT
            ntt_avx2(&mut poly).unwrap();
            
            // Inverse NTT
            inv_ntt_avx2(&mut poly).unwrap();
            
            // Check if we get back the original (within modular arithmetic)
            for i in 0..256 {
                let diff = (poly[i] - original[i]).abs();
                assert!(diff == 0 || diff == Q);
            }
        }
    }
    
    #[test]
    fn test_butterfly_operations() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        
        unsafe {
            let a = _mm256_set1_epi16(100);
            let b = _mm256_set1_epi16(200);
            let zeta = _mm256_set1_epi16(ZETAS[1]);
            
            let mut a1 = a;
            let mut b1 = b;
            butterfly_avx2(&mut a1, &mut b1, zeta);
            
            // Verify butterfly preserves sum modulo q
            let sum_before = _mm256_add_epi16(a, b);
            let sum_after = _mm256_add_epi16(a1, b1);
            
            // Extract and check a few values
            let before = _mm256_extract_epi16(sum_before, 0);
            let after = _mm256_extract_epi16(sum_after, 0);
            assert_eq!(before % Q, after % Q);
        }
    }
}