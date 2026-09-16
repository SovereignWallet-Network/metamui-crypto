//! Number Theoretic Transform (NTT) operations for ML-KEM
//! 
//! This implementation follows NIST FIPS 203 specification exactly,
//! using normal form arithmetic (not Montgomery form) for compatibility
//! with other language implementations.

use crate::polynomial::{Polynomial, Q};

/// FIPS 203 standard ZETAS values
/// These are bit-reversed powers of 17, matching the reference implementation
/// Note: Index 0 is unused in the NTT algorithms (they start from index 1)
pub const ZETAS: [i16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
];

/// Barrett reduction for modular arithmetic
/// Returns a mod q where q = 3329
#[inline(always)]
pub fn barrett_reduce(a: i16) -> i16 {
    const V: i16 = 20159; // floor(2^26 / q)
    
    let t = (((V as i32 * a as i32) + (1 << 25)) >> 26) as i16;
    let r = a - t * Q;
    
    // Ensure result is in [0, q)
    if r < 0 {
        r + Q
    } else if r >= Q {
        r - Q
    } else {
        r
    }
}

/// Modular multiplication using Barrett reduction
#[inline(always)]
pub fn mod_mul(a: i16, b: i16) -> i16 {
    // Use i32 to avoid overflow
    let prod = (a as i32) * (b as i32);
    // Barrett reduction
    const V: i32 = 20159; // floor(2^26 / q)
    const Q32: i32 = Q as i32;
    
    let t = ((prod as i64 * V as i64 + (1 << 25)) >> 26) as i32;
    let mut r = prod - t * Q32;
    
    // Ensure result is in [0, q)
    while r < 0 {
        r += Q32;
    }
    while r >= Q32 {
        r -= Q32;
    }
    r as i16
}

/// Add two numbers modulo q
#[inline(always)]
pub fn mod_add(a: i16, b: i16) -> i16 {
    let sum = (a as i32 + b as i32) % (Q as i32);
    if sum < 0 {
        (sum + Q as i32) as i16
    } else if sum >= Q as i32 {
        (sum - Q as i32) as i16
    } else {
        sum as i16
    }
}

/// Subtract two numbers modulo q
#[inline(always)]
pub fn mod_sub(a: i16, b: i16) -> i16 {
    let diff = (a as i32 - b as i32) % (Q as i32);
    if diff < 0 {
        (diff + Q as i32) as i16
    } else if diff >= Q as i32 {
        (diff - Q as i32) as i16
    } else {
        diff as i16
    }
}

/// Forward NTT transform (FIPS 203 Algorithm 9)
pub fn ntt(poly: &mut Polynomial) {
    let mut k = 1;  // Start from index 1 (skip ZETAS[0])
    let mut len = 128;
    
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            
            for j in start..(start + len) {
                let t = mod_mul(zeta, poly.coefficients[j + len]);
                poly.coefficients[j + len] = mod_sub(poly.coefficients[j], t);
                poly.coefficients[j] = mod_add(poly.coefficients[j], t);
            }
            
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT transform (FIPS 203 Algorithm 10)
pub fn inverse_ntt(poly: &mut Polynomial) {
    let mut k = 127;  // Start from the last ZETAS element
    let mut len = 2;
    
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k = k.saturating_sub(1);
            
            for j in start..(start + len) {
                let t = poly.coefficients[j];
                poly.coefficients[j] = mod_add(t, poly.coefficients[j + len]);
                poly.coefficients[j + len] = mod_mul(zeta, mod_sub(poly.coefficients[j + len], t));
            }
            
            start += 2 * len;
        }
        len <<= 1;
    }
    
    // Scale by 128^(-1) mod q = 3303 as per FIPS 203
    const INVN: i16 = 3303;
    for j in 0..256 {
        poly.coefficients[j] = mod_mul(poly.coefficients[j], INVN);
    }
}

/// Base multiplication in NTT domain (FIPS 203)
/// Computes multiplication of polynomials in Zq[X]/(X^2-zeta)
pub fn basemul(a: &[i16; 2], b: &[i16; 2], zeta: i16) -> [i16; 2] {
    let mut r = [0i16; 2];
    
    // r[0] = a[0]*b[0] + a[1]*b[1]*zeta
    r[0] = mod_add(
        mod_mul(a[0], b[0]),
        mod_mul(mod_mul(a[1], b[1]), zeta)
    );
    
    // r[1] = a[0]*b[1] + a[1]*b[0]
    r[1] = mod_add(
        mod_mul(a[0], b[1]),
        mod_mul(a[1], b[0])
    );
    
    r
}

// Remove Montgomery-related functions as they're no longer needed
// The following functions are deprecated and should not be used:
// - montgomery_reduce
// - fqmul
// - to_montgomery
// - from_montgomery

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polynomial::Polynomial;
    
    #[test]
    fn test_ntt_invertible() {
        // Test that NTT is invertible
        let mut poly = Polynomial::zero();
        
        // Set test values - ensure they're in valid range [0, Q)
        for i in 0..256 {
            poly.coefficients[i] = (i as i16) % 100;
        }
        
        // Save original
        let original = poly.clone();
        
        // Apply NTT
        ntt(&mut poly);
        
        // Apply inverse NTT
        inverse_ntt(&mut poly);
        
        // Check that we recover the original
        // Allow for small numerical differences due to modular arithmetic
        for i in 0..256 {
            let expected = original.coefficients[i];
            let actual = poly.coefficients[i];
            
            // Both should be in [0, Q)
            assert!(actual >= 0 && actual < Q, 
                   "Coefficient {} out of range: {}", i, actual);
            
            // Check if they're equivalent mod Q
            let diff = (actual - expected + Q) % Q;
            assert_eq!(diff, 0, 
                      "NTT not invertible at coefficient {}: expected {}, got {}", 
                      i, expected, actual);
        }
    }
    
    #[test]
    fn test_barrett_reduction() {
        // Test Barrett reduction
        let values = [0, 1, 17, 100, Q-1, Q, Q+1, 2*Q];
        
        for &val in &values {
            let reduced = barrett_reduce(val);
            assert!(reduced >= 0 && reduced < Q,
                   "Barrett reduction failed for {}: got {}", val, reduced);
            
            // Check it's equivalent to val mod Q
            let expected = ((val % Q) + Q) % Q;
            assert_eq!(reduced, expected,
                      "Barrett reduction incorrect for {}: expected {}, got {}", 
                      val, expected, reduced);
        }
    }
    
    #[test]
    fn test_simple_multiplication() {
        // Test simple polynomial multiplication
        let mut a = Polynomial::zero();
        let mut b = Polynomial::zero();
        
        // Set a = 2, b = 3 (as constant polynomials)
        a.coefficients[0] = 2;
        b.coefficients[0] = 3;
        
        // Transform to NTT domain
        ntt(&mut a);
        ntt(&mut b);
        
        // Multiply in NTT domain
        a.multiply_ntt(&b);
        
        // Transform back
        inverse_ntt(&mut a);
        
        // Should get 6 as the constant term
        assert_eq!(a.coefficients[0], 6, "Simple multiplication failed");
        
        // Other coefficients should be 0
        for i in 1..10 {
            assert_eq!(a.coefficients[i], 0, "Non-zero coefficient at position {}", i);
        }
    }
}