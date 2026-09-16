//! Optimized Montgomery arithmetic for ML-KEM
//!
//! This module provides fast Montgomery multiplication and reduction
//! with optimized constants and batch operations.

use core::hint::black_box;

/// ML-KEM modulus
pub const Q: i32 = 3329;

/// Montgomery parameter R = 2^16 mod Q
pub const MONT_R: i32 = 2285;

/// R^2 mod Q for converting to Montgomery form
pub const MONT_R2: i32 = 1353;

/// -Q^(-1) mod 2^16 for Montgomery reduction
pub const QINV: i32 = 62209;

/// R^(-1) mod Q for converting from Montgomery form
pub const MONT_R_INV: i32 = 169;

/// Montgomery multiplication
///
/// Computes (a * b * R^(-1)) mod Q where inputs are in Montgomery form
#[inline(always)]
pub fn montgomery_multiply(a: i32, b: i32) -> i32 {
    montgomery_reduce(a as i64 * b as i64)
}

/// Montgomery reduction
///
/// Computes (x * R^(-1)) mod Q
#[inline(always)]
pub fn montgomery_reduce(x: i64) -> i32 {
    let m = ((x as i32) as i64 * QINV as i64) as i32;
    let t = (x - m as i64 * Q as i64) >> 16;
    t as i32
}

/// Fast Montgomery reduction for 32-bit inputs
///
/// Specialized version for when x fits in 32 bits
#[inline(always)]
pub fn montgomery_reduce_32(x: i32) -> i32 {
    let m = (x as i64 * QINV as i64) & 0xFFFF;
    ((x as i64 - m * Q as i64) >> 16) as i32
}

/// Convert to Montgomery form
#[inline(always)]
pub fn to_montgomery(x: i32) -> i32 {
    montgomery_reduce((x as i64) * (MONT_R2 as i64))
}

/// Convert from Montgomery form
#[inline(always)]
pub fn from_montgomery(x: i32) -> i32 {
    montgomery_reduce(x as i64)
}

/// Batch Montgomery multiplication
///
/// Process multiple multiplications together for better cache usage
pub fn batch_montgomery_multiply(a: &[i32], b: &[i32], result: &mut [i32]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), result.len());
    
    // Process in chunks for cache efficiency
    const CHUNK_SIZE: usize = 32;
    
    for chunk in 0..(a.len() + CHUNK_SIZE - 1) / CHUNK_SIZE {
        let start = chunk * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(a.len());
        
        // Prefetch next chunk
        if end < a.len() {
            black_box(&a[end]);
            black_box(&b[end]);
        }
        
        // Process chunk with unrolling
        let mut i = start;
        while i + 4 <= end {
            result[i] = montgomery_multiply(a[i], b[i]);
            result[i + 1] = montgomery_multiply(a[i + 1], b[i + 1]);
            result[i + 2] = montgomery_multiply(a[i + 2], b[i + 2]);
            result[i + 3] = montgomery_multiply(a[i + 3], b[i + 3]);
            i += 4;
        }
        
        // Handle remainder
        while i < end {
            result[i] = montgomery_multiply(a[i], b[i]);
            i += 1;
        }
    }
}

/// Batch Montgomery reduction
///
/// Reduce multiple values efficiently
pub fn batch_montgomery_reduce(values: &mut [i32]) {
    const CHUNK_SIZE: usize = 32;
    
    for chunk in 0..(values.len() + CHUNK_SIZE - 1) / CHUNK_SIZE {
        let start = chunk * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(values.len());
        
        // Process chunk with unrolling
        let mut i = start;
        while i + 4 <= end {
            values[i] = montgomery_reduce(values[i] as i64);
            values[i + 1] = montgomery_reduce(values[i + 1] as i64);
            values[i + 2] = montgomery_reduce(values[i + 2] as i64);
            values[i + 3] = montgomery_reduce(values[i + 3] as i64);
            i += 4;
        }
        
        // Handle remainder
        while i < end {
            values[i] = montgomery_reduce(values[i] as i64);
            i += 1;
        }
    }
}

/// Montgomery squaring (optimized)
#[inline(always)]
pub fn montgomery_square(a: i32) -> i32 {
    montgomery_reduce((a as i64) * (a as i64))
}

/// Montgomery exponentiation
pub fn montgomery_exp(base: i32, exp: u32) -> i32 {
    let mut result = MONT_R;  // 1 in Montgomery form
    let mut b = base;
    let mut e = exp;
    
    while e > 0 {
        if (e & 1) == 1 {
            result = montgomery_multiply(result, b);
        }
        b = montgomery_square(b);
        e >>= 1;
    }
    
    result
}

/// Optimized Montgomery constants for specific operations
pub mod constants {
    use super::*;
    
    /// Precomputed Montgomery form of common values
    pub const MONT_1: i32 = MONT_R;
    pub const MONT_2: i32 = (2 * MONT_R) % Q;
    pub const MONT_3: i32 = (3 * MONT_R) % Q;
    pub const MONT_4: i32 = (4 * MONT_R) % Q;
    
    /// Montgomery form of N^(-1) for ML-KEM (N = 256)
    pub const MONT_N_INV: i32 = 3303;
    
    /// Montgomery form of 2^(-1)
    pub const MONT_HALF: i32 = 1143;
}

/// SIMD-friendly Montgomery operations (for when SIMD is available)
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod simd {
    use super::*;
    
    /// Process 4 Montgomery multiplications in parallel
    #[inline(always)]
    pub fn montgomery_multiply_x4(
        a: [i32; 4],
        b: [i32; 4],
    ) -> [i32; 4] {
        [
            montgomery_multiply(a[0], b[0]),
            montgomery_multiply(a[1], b[1]),
            montgomery_multiply(a[2], b[2]),
            montgomery_multiply(a[3], b[3]),
        ]
    }
    
    /// Process 8 Montgomery reductions in parallel
    #[inline(always)]
    pub fn montgomery_reduce_x8(x: [i64; 8]) -> [i32; 8] {
        [
            montgomery_reduce(x[0]),
            montgomery_reduce(x[1]),
            montgomery_reduce(x[2]),
            montgomery_reduce(x[3]),
            montgomery_reduce(x[4]),
            montgomery_reduce(x[5]),
            montgomery_reduce(x[6]),
            montgomery_reduce(x[7]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_identity() {
        let a = 1234;
        let a_mont = to_montgomery(a);
        let result = from_montgomery(a_mont);
        assert_eq!(result, a);
    }

    #[test]
    fn test_montgomery_multiply() {
        let a = 123;
        let b = 456;
        let expected = (a * b) % Q;
        
        let a_mont = to_montgomery(a);
        let b_mont = to_montgomery(b);
        let result_mont = montgomery_multiply(a_mont, b_mont);
        let result = from_montgomery(result_mont);
        
        assert_eq!(result, expected);
    }

    #[test]
    fn test_batch_operations() {
        let a = vec![1, 2, 3, 4, 5];
        let b = vec![6, 7, 8, 9, 10];
        let mut result = vec![0; 5];
        
        let a_mont: Vec<i32> = a.iter().map(|&x| to_montgomery(x)).collect();
        let b_mont: Vec<i32> = b.iter().map(|&x| to_montgomery(x)).collect();
        
        batch_montgomery_multiply(&a_mont, &b_mont, &mut result);
        
        for i in 0..5 {
            let expected = (a[i] * b[i]) % Q;
            assert_eq!(from_montgomery(result[i]), expected);
        }
    }
}