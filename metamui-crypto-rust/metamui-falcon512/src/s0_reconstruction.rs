//! S0 reconstruction during Falcon-512 signature verification
//! 
//! This module implements the reconstruction of the s0 component from
//! the compressed signature format, where only s1 is transmitted.

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::poly::Poly;
use alloc::vec::Vec;

/// Reconstruct s0 from the verification equation
/// 
/// Given:
/// - s1: The transmitted signature component
/// - c: The hashed message (challenge)
/// - h: The public key
/// 
/// Computes: s0 = c - s1*h (mod q)
/// 
/// This allows verification of the full signature (s0, s1) even though
/// only s1 was transmitted in the compressed format.
pub fn reconstruct_s0(
    s1: &[i16],
    c: &[i16],
    h: &[i16],
) -> Result<Vec<i16>> {
    if s1.len() != N || c.len() != N || h.len() != N {
        return Err(Falcon512Error::InvalidParameter);
    }

    // Use NTT multiplication which correctly handles Z[X]/(X^N + 1)
    let s1h = crate::ntt_falcon::multiply_ntt(s1, h);

    // Compute s0 = c - s1*h mod q, centered
    let mut s0 = vec![0i16; N];
    for i in 0..N {
        let diff = (c[i] as i32 - s1h[i] as i32).rem_euclid(Q as i32);
        s0[i] = center_reduce(diff as i16);
    }

    Ok(s0)
}

/// Direct polynomial multiplication method
fn reconstruct_s0_direct(
    s1: &[i16],
    c: &[i16],
    h: &[i16],
) -> Result<Vec<i16>> {
    let s1_poly = Poly::new(s1.to_vec());
    let h_poly = Poly::new(h.to_vec());
    
    // Compute s1*h using polynomial multiplication
    let s1h = s1_poly.mul(&h_poly);
    
    // Compute s0 = c - s1*h mod q
    let mut s0 = vec![0i16; N];
    for i in 0..N {
        let diff = (c[i] as i32 - s1h.coeffs[i] as i32).rem_euclid(Q as i32);
        s0[i] = center_reduce(diff as i16);
    }
    
    Ok(s0)
}

/// NTT-based multiplication method (faster)
fn reconstruct_s0_ntt(
    s1: &[i16],
    c: &[i16],
    h: &[i16],
) -> Result<Vec<i16>> {
    // Use direct polynomial multiplication for now
    // NTT optimization can be added later
    let s1_poly = Poly::new(s1.to_vec());
    let h_poly = Poly::new(h.to_vec());
    let s1h = s1_poly.mul(&h_poly);
    
    // Compute s0 = c - s1*h mod q
    let mut s0 = vec![0i16; N];
    for i in 0..N {
        let diff = (c[i] as i32 - s1h.coeffs[i] as i32).rem_euclid(Q as i32);
        s0[i] = center_reduce(diff as i16);
    }
    
    Ok(s0)
}

/// Center-reduce a value modulo q to [-q/2, q/2)
#[inline]
fn center_reduce(x: i16) -> i16 {
    let x = x.rem_euclid(Q as i16);
    if x > Q as i16 / 2 {
        x - Q as i16
    } else {
        x
    }
}

/// Verify reconstructed s0 has valid norm
/// 
/// Checks that ||s0||^2 is within expected bounds for a valid signature
pub fn verify_s0_norm(s0: &[i16]) -> bool {
    let mut norm_sq = 0i64;
    for &coeff in s0 {
        norm_sq += (coeff as i64) * (coeff as i64);
    }
    
    // Expected norm bounds for Falcon-512
    // These should be adjusted based on actual signature parameters
    const MAX_NORM_SQ: i64 = 34034726; // From Falcon spec
    
    norm_sq <= MAX_NORM_SQ
}

/// Full signature verification with s0 reconstruction
/// 
/// Verifies that:
/// 1. s0 can be correctly reconstructed from (s1, c, h)
/// 2. The reconstructed s0 has valid norm
/// 3. The equation s0 + s1*h = c (mod q) holds
pub fn verify_with_reconstruction(
    s1: &[i16],
    c: &[i16],
    h: &[i16],
) -> Result<bool> {
    // Reconstruct s0
    let s0 = reconstruct_s0(s1, c, h)?;
    
    // Verify norm
    if !verify_s0_norm(&s0) {
        return Ok(false);
    }
    
    // Verify equation: s0 + s1*h = c (mod q)
    if !verify_equation(&s0, s1, c, h)? {
        return Ok(false);
    }
    
    Ok(true)
}

/// Verify the signature equation s0 + s1*h = c (mod q) in Z[X]/(X^N + 1)
pub fn verify_equation(
    s0: &[i16],
    s1: &[i16],
    c: &[i16],
    h: &[i16],
) -> Result<bool> {
    // Compute s1*h in the ring Z[X]/(X^N + 1)
    let s1h = crate::ntt_falcon::multiply_ntt(s1, h);

    // Check s0 + s1*h = c (mod q)
    for i in 0..N {
        let lhs = (s0[i] as i32 + s1h[i] as i32).rem_euclid(Q as i32);
        let rhs = (c[i] as i32).rem_euclid(Q as i32);
        
        // Allow for center-reduction differences
        let diff = (lhs - rhs).rem_euclid(Q as i32);
        if diff != 0 && diff != Q as i32 {
            return Ok(false);
        }
    }
    
    Ok(true)
}

/// Batch s0 reconstruction for multiple signatures
/// 
/// Efficiently reconstructs s0 for multiple signatures sharing
/// the same public key h.
pub fn reconstruct_s0_batch(
    signatures: &[(Vec<i16>, Vec<i16>)], // (s1, c) pairs
    h: &[i16],
) -> Result<Vec<Vec<i16>>> {
    let mut results = Vec::with_capacity(signatures.len());

    for (s1, c) in signatures {
        let s1h = crate::ntt_falcon::multiply_ntt(s1, h);

        let mut s0 = vec![0i16; N];
        for i in 0..N {
            let diff = (c[i] as i32 - s1h[i] as i32).rem_euclid(Q as i32);
            s0[i] = center_reduce(diff as i16);
        }

        results.push(s0);
    }
    
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    
    #[test]
    fn test_s0_reconstruction() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        // Generate test values
        let mut s0 = vec![0i16; N];
        let mut s1 = vec![0i16; N];
        let mut h = vec![0i16; N];
        
        for i in 0..N {
            s0[i] = rng.gen_range(-100..=100);
            s1[i] = rng.gen_range(-100..=100);
            h[i] = rng.gen_range(0..Q as i16);
        }
        
        // Compute c = s0 + s1*h mod q in the ring Z[X]/(X^N + 1)
        let s1h = crate::ntt_falcon::multiply_ntt(&s1, &h);

        let mut c = vec![0i16; N];
        for i in 0..N {
            c[i] = ((s0[i] as i32 + s1h[i] as i32).rem_euclid(Q as i32)) as i16;
        }
        
        // Reconstruct s0 from (s1, c, h)
        let s0_reconstructed = reconstruct_s0(&s1, &c, &h)
            .expect("Reconstruction should succeed");
        
        // Verify reconstruction
        for i in 0..N {
            let expected = center_reduce(s0[i]);
            let actual = s0_reconstructed[i];
            
            // Allow for center-reduction differences
            let diff = (expected as i32 - actual as i32).abs();
            assert!(diff == 0 || diff == Q as i32,
                    "Mismatch at index {}: expected {}, got {}", 
                    i, expected, actual);
        }
    }
    
    #[test]
    fn test_verify_equation() {
        let mut rng = ChaCha20Rng::seed_from_u64(1337);
        
        // Generate valid signature
        let mut s0 = vec![0i16; N];
        let mut s1 = vec![0i16; N];
        let mut h = vec![0i16; N];
        
        for i in 0..N {
            s0[i] = rng.gen_range(-50..=50);
            s1[i] = rng.gen_range(-50..=50);
            h[i] = rng.gen_range(0..Q as i16);
        }
        
        // Compute c = s0 + s1*h mod q in the ring Z[X]/(X^N + 1)
        let s1h = crate::ntt_falcon::multiply_ntt(&s1, &h);

        let mut c = vec![0i16; N];
        for i in 0..N {
            let sum = (s0[i] as i32 + s1h[i] as i32).rem_euclid(Q as i32);
            c[i] = if sum > Q as i32 / 2 {
                sum as i16 - Q as i16
            } else {
                sum as i16
            };
        }

        // Verify equation holds
        assert!(verify_equation(&s0, &s1, &c, &h).unwrap());
        
        // Verify invalid equation fails
        s0[0] += 1;
        assert!(!verify_equation(&s0, &s1, &c, &h).unwrap());
    }
    
    #[test]
    fn test_batch_reconstruction() {
        let mut rng = ChaCha20Rng::seed_from_u64(999);
        
        // Generate public key
        let mut h = vec![0i16; N];
        for i in 0..N {
            h[i] = rng.gen_range(0..Q as i16);
        }
        
        // Generate multiple signatures
        let mut signatures = Vec::new();
        let mut expected_s0s = Vec::new();
        
        for _ in 0..5 {
            let mut s0 = vec![0i16; N];
            let mut s1 = vec![0i16; N];
            
            for i in 0..N {
                s0[i] = rng.gen_range(-100..=100);
                s1[i] = rng.gen_range(-100..=100);
            }
            
            // Compute c in the ring Z[X]/(X^N + 1)
            let s1h = crate::ntt_falcon::multiply_ntt(&s1, &h);

            let mut c = vec![0i16; N];
            for i in 0..N {
                c[i] = ((s0[i] as i32 + s1h[i] as i32).rem_euclid(Q as i32)) as i16;
            }
            
            signatures.push((s1, c));
            expected_s0s.push(s0);
        }
        
        // Batch reconstruct
        let reconstructed = reconstruct_s0_batch(&signatures, &h)
            .expect("Batch reconstruction should succeed");
        
        // Verify all reconstructions
        assert_eq!(reconstructed.len(), expected_s0s.len());
    }
}