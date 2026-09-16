//! Modular polynomial operations for Falcon-512

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;

/// Compute h = g/f mod q in the ring Z_q[X]/(X^N + 1)
/// This computes the public key from private polynomials f and g
pub fn compute_public_key_modular(f: &[i16], g: &[i16]) -> Result<Vec<i16>> {
    let _ = (f, g);
    Err(Falcon512Error::NotImplemented)
}

/// Invert a polynomial modulo q using NTT
fn invert_polynomial_ntt(f: &[i16]) -> Result<Vec<i16>> {
    // For Falcon-512, we use NTT for fast polynomial operations
    // This requires that q = 12289 = 1 + 2^12 * 3, which supports NTT of size 512
    
    // Convert to NTT domain
    let f_ntt = forward_ntt(f);
    
    // Invert each coefficient in NTT domain
    let mut f_inv_ntt = vec![0i16; N];
    for i in 0..N {
        if f_ntt[i] == 0 {
            // Not invertible - this shouldn't happen with valid keys
            return Err(Falcon512Error::NotInvertible);
        }
        f_inv_ntt[i] = mod_inverse(f_ntt[i] as i32, Q as i32) as i16;
    }
    
    // Convert back from NTT domain
    let f_inv = inverse_ntt(&f_inv_ntt);
    
    Ok(f_inv)
}

/// Multiply two polynomials modulo q using NTT
fn multiply_polynomials_ntt(a: &[i16], b: &[i16]) -> Result<Vec<i16>> {
    // Convert to NTT domain
    let a_ntt = forward_ntt(a);
    let b_ntt = forward_ntt(b);
    
    // Pointwise multiplication in NTT domain
    let mut c_ntt = vec![0i16; N];
    for i in 0..N {
        let prod = (a_ntt[i] as i32 * b_ntt[i] as i32) % Q as i32;
        c_ntt[i] = prod as i16;
    }
    
    // Convert back from NTT domain
    let c = inverse_ntt(&c_ntt);
    
    Ok(c)
}

/// Forward NTT transform (simplified version)
fn forward_ntt(poly: &[i16]) -> Vec<i16> {
    // This is a simplified NTT - in production, use proper NTT with precomputed roots
    let result = poly.to_vec();
    
    // For now, just return the input (this makes h = g which is wrong but won't crash)
    // A proper NTT implementation would use bit-reversal and butterfly operations
    result
}

/// Inverse NTT transform (simplified version)
fn inverse_ntt(poly: &[i16]) -> Vec<i16> {
    // This is a simplified inverse NTT
    let result = poly.to_vec();
    
    // For now, just return the input
    // A proper implementation would use bit-reversal and butterfly operations
    // followed by multiplication by N^-1 mod q
    result
}

/// Compute modular inverse using extended GCD
fn mod_inverse(a: i32, m: i32) -> i32 {
    let (gcd, x, _) = extended_gcd(a, m);
    if gcd != 1 {
        // Not invertible - return 1 as fallback
        1
    } else {
        ((x % m) + m) % m
    }
}

/// Extended GCD algorithm
fn extended_gcd(a: i32, b: i32) -> (i32, i32, i32) {
    if b == 0 {
        return (a, 1, 0);
    }
    let (gcd, x1, y1) = extended_gcd(b, a % b);
    let x = y1;
    let y = x1 - (a / b) * y1;
    (gcd, x, y)
}

/// For testing: direct computation of h = g * f^-1 mod q
/// This uses a simpler approach that should work for sparse polynomials
pub fn compute_public_key_simple(f: &[i16], g: &[i16]) -> Result<Vec<i16>> {
    let _ = (f, g);
    Err(Falcon512Error::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_helpers_fail_closed() {
        let f = vec![1i16; N];
        let g = vec![2i16; N];

        assert!(matches!(
            compute_public_key_modular(&f, &g),
            Err(Falcon512Error::NotImplemented)
        ));
        assert!(matches!(
            compute_public_key_simple(&f, &g),
            Err(Falcon512Error::NotImplemented)
        ));
    }
}
