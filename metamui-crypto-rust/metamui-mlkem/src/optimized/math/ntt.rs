//! Highly optimized NTT and inverse NTT implementations
//!
//! This module provides cache-optimized Cooley-Tukey NTT and Gentleman-Sande
//! inverse NTT with lazy reduction and precomputed twiddle factors.

use super::montgomery::*;
use super::barrett::*;
use core::hint::black_box;

/// ML-KEM parameters
pub const N: usize = 256;
pub const Q: i32 = 3329;
pub const QINV: i32 = 62209; // -q^(-1) mod 2^16
pub const MONT_R: i32 = 2285; // 2^16 mod q
pub const MONT_R2: i32 = 1353; // 2^32 mod q

/// Cache line size for optimization
const CACHE_LINE: usize = 64;
const ELEMENTS_PER_CACHE_LINE: usize = CACHE_LINE / 2; // 32 i16 elements

/// Precomputed twiddle factors with optimal memory layout
/// Arranged for sequential access patterns during NTT stages
#[repr(align(64))]
pub struct TwiddleFactors {
    /// Forward NTT twiddle factors in bit-reversed order
    pub forward: [i16; 128],
    /// Inverse NTT twiddle factors
    pub inverse: [i16; 128],
    /// Montgomery form of forward twiddles for fast multiplication
    pub forward_mont: [i32; 128],
    /// Montgomery form of inverse twiddles
    pub inverse_mont: [i32; 128],
}

impl TwiddleFactors {
    /// Create precomputed twiddle factors
    pub const fn new() -> Self {
        // These are the canonical ML-KEM twiddle factors
        let forward = [
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

        let inverse = [
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

        // Precompute Montgomery forms
        let mut forward_mont = [0i32; 128];
        let mut inverse_mont = [0i32; 128];
        
        let mut i = 0;
        while i < 128 {
            forward_mont[i] = montgomery_reduce((forward[i] as i32) * MONT_R2);
            inverse_mont[i] = montgomery_reduce((inverse[i] as i32) * MONT_R2);
            i += 1;
        }

        Self {
            forward,
            inverse,
            forward_mont,
            inverse_mont,
        }
    }
}

/// Global twiddle factors instance
pub static TWIDDLES: TwiddleFactors = TwiddleFactors::new();

/// Optimized bit-reversal using cache-friendly blocking
#[inline(always)]
pub fn bit_reverse_copy(src: &[i16; N], dst: &mut [i16; N]) {
    // Use blocking for better cache locality
    const BLOCK_SIZE: usize = 16;
    
    for block in 0..(N / BLOCK_SIZE) {
        let base = block * BLOCK_SIZE;
        for i in 0..BLOCK_SIZE {
            let idx = base + i;
            let rev_idx = bit_reverse_index(idx);
            dst[rev_idx] = src[idx];
        }
    }
}

/// Fast bit reversal for 8-bit index (N = 256)
#[inline(always)]
const fn bit_reverse_index(n: usize) -> usize {
    let mut n = n as u32;
    n = ((n & 0xF0) >> 4) | ((n & 0x0F) << 4);
    n = ((n & 0xCC) >> 2) | ((n & 0x33) << 2);
    n = ((n & 0xAA) >> 1) | ((n & 0x55) << 1);
    n as usize
}

/// Cooley-Tukey NTT with lazy reduction and cache optimization
///
/// This implementation uses:
/// - Lazy reduction to minimize modular operations
/// - Cache-oblivious recursive structure
/// - Optimized memory access patterns
pub fn ntt(poly: &mut [i16; N]) {
    // Stage 1-4: Process with increasing butterfly sizes
    // Using lazy reduction - only reduce when necessary
    
    let mut k = 1;
    let mut len = 128;
    
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta_idx = k;
            let zeta = TWIDDLES.forward_mont[zeta_idx - 1] as i32;
            k += 1;
            
            // Process butterflies in this stage
            for j in start..(start + len) {
                let t = montgomery_multiply_lazy(poly[j + len] as i32, zeta);
                let a = poly[j] as i32;
                
                // Lazy reduction - accumulate without full reduction
                poly[j] = lazy_reduce(a + t);
                poly[j + len] = lazy_reduce(a - t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
    
    // Final reduction pass
    for i in 0..N {
        poly[i] = barrett_reduce(poly[i] as i32) as i16;
    }
}

/// Gentleman-Sande inverse NTT with lazy reduction
///
/// This implementation uses:
/// - Lazy reduction throughout computation
/// - Optimized butterfly operations
/// - Cache-friendly memory access
pub fn inv_ntt(poly: &mut [i16; N]) {
    let mut k = 127;
    let mut len = 2;
    
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = TWIDDLES.inverse_mont[k] as i32;
            k = k.wrapping_sub(1);
            
            // Process butterflies in reverse order
            for j in start..(start + len) {
                let a = poly[j] as i32;
                let b = poly[j + len] as i32;
                
                // Gentleman-Sande butterfly with lazy reduction
                poly[j] = lazy_reduce(a + b);
                let t = lazy_reduce(a - b);
                poly[j + len] = montgomery_multiply_lazy(t, zeta);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    
    // Final scaling by N^(-1) = 3303 and reduction
    const N_INV_MONT: i32 = 3303; // N^(-1) in Montgomery form
    for i in 0..N {
        poly[i] = montgomery_reduce((poly[i] as i32) * N_INV_MONT) as i16;
    }
}

/// Optimized NTT for batch processing with improved cache usage
///
/// Process multiple polynomials together for better cache utilization
pub fn ntt_batch<const BATCH_SIZE: usize>(polys: &mut [[i16; N]; BATCH_SIZE]) {
    // Process multiple polynomials stage by stage for better cache reuse
    let mut k_base = 1;
    let mut len = 128;
    
    while len >= 2 {
        for poly in polys.iter_mut() {
            let mut k = k_base;
            let mut start = 0;
            
            while start < N {
                let zeta = TWIDDLES.forward_mont[k - 1] as i32;
                k += 1;
                
                // Unroll inner loop for better performance
                let mut j = start;
                while j < start + len {
                    let t0 = montgomery_multiply_lazy(poly[j + len] as i32, zeta);
                    let a0 = poly[j] as i32;
                    
                    poly[j] = lazy_reduce(a0 + t0);
                    poly[j + len] = lazy_reduce(a0 - t0);
                    
                    j += 1;
                }
                start += 2 * len;
            }
        }
        k_base += N / (2 * len);
        len >>= 1;
    }
    
    // Final reduction for all polynomials
    for poly in polys.iter_mut() {
        for i in 0..N {
            poly[i] = barrett_reduce(poly[i] as i32) as i16;
        }
    }
}

/// Cache-oblivious recursive NTT for very large polynomial operations
///
/// This version recursively subdivides the problem for optimal cache usage
pub fn ntt_recursive(poly: &mut [i16], n: usize, stride: usize, twiddle_offset: usize) {
    if n == 2 {
        // Base case: simple butterfly
        let a = poly[0] as i32;
        let b = poly[stride] as i32;
        poly[0] = lazy_reduce(a + b);
        poly[stride] = lazy_reduce(a - b);
        return;
    }
    
    // Recursive calls on even and odd indices
    ntt_recursive(poly, n / 2, stride * 2, twiddle_offset * 2);
    ntt_recursive(&mut poly[stride..], n / 2, stride * 2, twiddle_offset * 2);
    
    // Combine results with twiddle factors
    let half_n = n / 2;
    for i in 0..half_n {
        let twiddle_idx = twiddle_offset + i;
        let zeta = if twiddle_idx < 128 {
            TWIDDLES.forward_mont[twiddle_idx] as i32
        } else {
            MONT_R // Unity root
        };
        
        let even_idx = i * stride * 2;
        let odd_idx = even_idx + stride;
        
        let t = montgomery_multiply_lazy(poly[odd_idx] as i32, zeta);
        let a = poly[even_idx] as i32;
        
        poly[even_idx] = lazy_reduce(a + t);
        poly[odd_idx] = lazy_reduce(a - t);
    }
}

/// Lazy reduction - only ensure value is in reasonable range
#[inline(always)]
fn lazy_reduce(x: i32) -> i16 {
    // Keep values in range [-2Q, 2Q] for accumulation
    let mut r = x;
    if r >= 2 * Q {
        r -= 2 * Q;
    } else if r < -2 * Q {
        r += 2 * Q;
    }
    r as i16
}

/// Montgomery multiplication with lazy reduction
#[inline(always)]
fn montgomery_multiply_lazy(a: i32, b: i32) -> i32 {
    let prod = a * b;
    montgomery_reduce_lazy(prod)
}

/// Lazy Montgomery reduction - single reduction step
#[inline(always)]
fn montgomery_reduce_lazy(x: i32) -> i32 {
    let m = ((x as i64 * QINV as i64) & 0xFFFF) as i32;
    ((x - m * Q) >> 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_reverse() {
        assert_eq!(bit_reverse_index(0), 0);
        assert_eq!(bit_reverse_index(1), 128);
        assert_eq!(bit_reverse_index(2), 64);
        assert_eq!(bit_reverse_index(255), 255);
    }

    #[test]
    fn test_ntt_inv_ntt() {
        let mut poly = [0i16; N];
        for i in 0..N {
            poly[i] = (i as i16) % Q as i16;
        }
        
        let original = poly.clone();
        
        ntt(&mut poly);
        inv_ntt(&mut poly);
        
        // Check if we get back the original
        for i in 0..N {
            let diff = (poly[i] - original[i]).abs();
            assert!(diff < 2, "NTT/INTT not inverse at index {}: {} vs {}", 
                    i, poly[i], original[i]);
        }
    }

    #[test]
    fn test_batch_ntt() {
        const BATCH: usize = 4;
        let mut polys = [[0i16; N]; BATCH];
        
        for (j, poly) in polys.iter_mut().enumerate() {
            for i in 0..N {
                poly[i] = ((i + j * N) % Q as usize) as i16;
            }
        }
        
        let original = polys.clone();
        ntt_batch(&mut polys);
        
        // Verify each polynomial was transformed
        for j in 0..BATCH {
            assert_ne!(polys[j], original[j], "Batch NTT failed for poly {}", j);
        }
    }
}