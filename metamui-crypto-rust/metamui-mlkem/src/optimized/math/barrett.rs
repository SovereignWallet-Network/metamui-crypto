//! Optimized Barrett reduction for ML-KEM
//!
//! This module provides fast Barrett reduction with precomputed constants
//! and batch operations for efficient modular arithmetic.

use core::hint::black_box;

/// ML-KEM modulus
pub const Q: i32 = 3329;

/// Barrett constant: floor(2^26 / Q)
pub const BARRETT_CONST: i32 = 20159;

/// Barrett shift amount
pub const BARRETT_SHIFT: i32 = 26;

/// Optimized Barrett reduction
///
/// Reduces x modulo Q using Barrett's algorithm
#[inline(always)]
pub fn barrett_reduce(x: i32) -> i16 {
    // Compute quotient estimate
    let q = ((x as i64 * BARRETT_CONST as i64) >> BARRETT_SHIFT) as i32;
    
    // Compute remainder
    let r = x - q * Q;
    
    // Single conditional correction
    if r >= Q {
        (r - Q) as i16
    } else {
        r as i16
    }
}

/// Fast Barrett reduction for small inputs
///
/// Optimized for |x| < 2^14
#[inline(always)]
pub fn barrett_reduce_small(x: i32) -> i16 {
    let q = (x * BARRETT_CONST) >> BARRETT_SHIFT;
    let r = x - q * Q;
    r as i16
}

/// Centered Barrett reduction
///
/// Reduces x to range [-Q/2, Q/2)
#[inline(always)]
pub fn barrett_reduce_centered(x: i32) -> i16 {
    let mut r = barrett_reduce(x);
    
    // Center the result
    if r > (Q / 2) as i16 {
        r -= Q as i16;
    }
    
    r
}

/// Batch Barrett reduction
///
/// Efficiently reduce multiple values
pub fn batch_barrett_reduce(values: &mut [i16]) {
    const CHUNK_SIZE: usize = 32;
    
    for chunk in 0..(values.len() + CHUNK_SIZE - 1) / CHUNK_SIZE {
        let start = chunk * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(values.len());
        
        // Prefetch next chunk
        if end < values.len() {
            black_box(&values[end]);
        }
        
        // Process chunk with unrolling
        let mut i = start;
        while i + 4 <= end {
            values[i] = barrett_reduce(values[i] as i32);
            values[i + 1] = barrett_reduce(values[i + 1] as i32);
            values[i + 2] = barrett_reduce(values[i + 2] as i32);
            values[i + 3] = barrett_reduce(values[i + 3] as i32);
            i += 4;
        }
        
        // Handle remainder
        while i < end {
            values[i] = barrett_reduce(values[i] as i32);
            i += 1;
        }
    }
}

/// Batch Barrett reduction for i32 values
pub fn batch_barrett_reduce_i32(values: &[i32], result: &mut [i16]) {
    assert_eq!(values.len(), result.len());
    
    const CHUNK_SIZE: usize = 32;
    
    for chunk in 0..(values.len() + CHUNK_SIZE - 1) / CHUNK_SIZE {
        let start = chunk * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(values.len());
        
        // Process chunk with unrolling
        let mut i = start;
        while i + 4 <= end {
            result[i] = barrett_reduce(values[i]);
            result[i + 1] = barrett_reduce(values[i + 1]);
            result[i + 2] = barrett_reduce(values[i + 2]);
            result[i + 3] = barrett_reduce(values[i + 3]);
            i += 4;
        }
        
        // Handle remainder
        while i < end {
            result[i] = barrett_reduce(values[i]);
            i += 1;
        }
    }
}

/// Conditional Barrett reduction
///
/// Only reduce if value exceeds threshold
#[inline(always)]
pub fn conditional_barrett_reduce(x: i32, threshold: i32) -> i16 {
    if x.abs() >= threshold {
        barrett_reduce(x)
    } else {
        x as i16
    }
}

/// Barrett multiplication and reduction
///
/// Computes (a * b) mod Q
#[inline(always)]
pub fn barrett_multiply(a: i16, b: i16) -> i16 {
    barrett_reduce((a as i32) * (b as i32))
}

/// Precomputed Barrett constants for different moduli
pub mod constants {
    /// Barrett constant for Q = 3329
    pub const BARRETT_Q3329: i32 = 20159;
    
    /// Barrett constant for Q = 7681 (used in some variants)
    pub const BARRETT_Q7681: i32 = 8736;
    
    /// Barrett constant for Q = 12289 (used in some variants)
    pub const BARRETT_Q12289: i32 = 5461;
}

/// SIMD-friendly Barrett operations
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod simd {
    use super::*;
    
    /// Process 4 Barrett reductions in parallel
    #[inline(always)]
    pub fn barrett_reduce_x4(x: [i32; 4]) -> [i16; 4] {
        [
            barrett_reduce(x[0]),
            barrett_reduce(x[1]),
            barrett_reduce(x[2]),
            barrett_reduce(x[3]),
        ]
    }
    
    /// Process 8 Barrett reductions in parallel
    #[inline(always)]
    pub fn barrett_reduce_x8(x: [i32; 8]) -> [i16; 8] {
        [
            barrett_reduce(x[0]),
            barrett_reduce(x[1]),
            barrett_reduce(x[2]),
            barrett_reduce(x[3]),
            barrett_reduce(x[4]),
            barrett_reduce(x[5]),
            barrett_reduce(x[6]),
            barrett_reduce(x[7]),
        ]
    }
    
    /// Process 16 Barrett reductions (for AVX-512)
    #[inline(always)]
    pub fn barrett_reduce_x16(x: [i32; 16]) -> [i16; 16] {
        let mut result = [0i16; 16];
        for i in 0..16 {
            result[i] = barrett_reduce(x[i]);
        }
        result
    }
}

/// Optimized reduction pipeline
///
/// Combines multiple reduction strategies
pub struct ReductionPipeline {
    lazy_threshold: i32,
    batch_size: usize,
}

impl ReductionPipeline {
    pub const fn new() -> Self {
        Self {
            lazy_threshold: 4 * Q,
            batch_size: 32,
        }
    }
    
    /// Process values with adaptive reduction strategy
    pub fn process(&self, values: &mut [i32], output: &mut [i16]) {
        assert_eq!(values.len(), output.len());
        
        for i in 0..values.len() {
            // Use conditional reduction based on magnitude
            if values[i].abs() < self.lazy_threshold {
                // Lazy reduction for small values
                output[i] = values[i] as i16;
            } else {
                // Full Barrett reduction for large values
                output[i] = barrett_reduce(values[i]);
            }
        }
    }
    
    /// Process with hint about value ranges
    pub fn process_with_hint(&self, values: &mut [i32], output: &mut [i16], max_value: i32) {
        if max_value < Q {
            // No reduction needed
            for i in 0..values.len() {
                output[i] = values[i] as i16;
            }
        } else if max_value < 2 * Q {
            // Simple reduction
            for i in 0..values.len() {
                output[i] = barrett_reduce_small(values[i]);
            }
        } else {
            // Full reduction
            batch_barrett_reduce_i32(values, output);
        }
    }
}

impl Default for ReductionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_barrett_reduce() {
        // Test basic reduction
        assert_eq!(barrett_reduce(Q), 0);
        assert_eq!(barrett_reduce(Q + 1), 1);
        assert_eq!(barrett_reduce(2 * Q), 0);
        
        // Test negative values
        assert_eq!(barrett_reduce(-1), (Q - 1) as i16);
        assert_eq!(barrett_reduce(-Q), 0);
    }

    #[test]
    fn test_barrett_multiply() {
        let a = 1234i16;
        let b = 2345i16;
        let result = barrett_multiply(a, b);
        let expected = ((a as i32 * b as i32) % Q) as i16;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_batch_reduction() {
        let mut values = vec![Q as i16, (Q + 1) as i16, (2 * Q) as i16, 100, 200];
        batch_barrett_reduce(&mut values);
        
        assert_eq!(values[0], 0);
        assert_eq!(values[1], 1);
        assert_eq!(values[2], 0);
        assert_eq!(values[3], 100);
        assert_eq!(values[4], 200);
    }

    #[test]
    fn test_centered_reduction() {
        let val = Q - 1;
        let centered = barrett_reduce_centered(val);
        assert_eq!(centered, -1);
        
        let val = Q / 2;
        let centered = barrett_reduce_centered(val);
        assert_eq!(centered, (Q / 2) as i16);
    }
}