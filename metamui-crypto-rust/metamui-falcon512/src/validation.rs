//! Comprehensive validation for Falcon-512 signatures and keys
//! 
//! This module provides thorough validation of all cryptographic
//! objects to ensure correctness and security.

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::falcon::{PrivateKey, PublicKey, KeyPair};
use crate::ntru_basis::NTRUBasis;
use alloc::vec::Vec;

/// Signature validation parameters
pub struct SignatureValidation {
    /// Maximum allowed norm squared
    pub max_norm_sq: i64,
    /// Whether to check equation exactly
    pub check_equation: bool,
    /// Whether to check coefficient bounds
    pub check_bounds: bool,
    /// Whether to verify compression
    pub check_compression: bool,
}

impl Default for SignatureValidation {
    fn default() -> Self {
        Self {
            max_norm_sq: 34034726,  // Falcon-512 bound
            check_equation: true,
            check_bounds: true,
            check_compression: true,
        }
    }
}

/// Validate a signature comprehensively
pub fn validate_signature(
    s0: &[i16],
    s1: &[i16],
    h: &[i16],
    c: &[i16],
    params: &SignatureValidation,
) -> Result<()> {
    // Check sizes
    if s0.len() != N || s1.len() != N || h.len() != N || c.len() != N {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    // Check norm bound
    if params.max_norm_sq > 0 {
        let norm_sq: i64 = s0.iter().map(|&x| x as i64 * x as i64).sum::<i64>()
            + s1.iter().map(|&x| x as i64 * x as i64).sum::<i64>();
        
        if norm_sq > params.max_norm_sq {
            #[cfg(feature = "std")]
            eprintln!("validate_signature: Norm too large: {} > {}", norm_sq, params.max_norm_sq);
            return Err(Falcon512Error::NormTooLarge);
        }
    }
    
    // Check coefficient bounds
    if params.check_bounds {
        for i in 0..N {
            // Check that coefficients are in valid range
            if s0[i].abs() > (Q / 2) as i16 || s1[i].abs() > (Q / 2) as i16 {
                #[cfg(feature = "std")]
                eprintln!("validate_signature: Coefficient out of bounds at index {}", i);
                return Err(Falcon512Error::InvalidSignature);
            }
        }
    }
    
    // Check NTRU equation: s0 + s1*h = c (mod q)
    if params.check_equation {
        let s1h = crate::ntt_falcon::multiply_ntt(s1, h);
        
        for i in 0..N {
            let lhs = (s0[i] as i32 + s1h[i] as i32).rem_euclid(Q as i32);
            let rhs = c[i] as i32;
            
            if lhs != rhs {
                #[cfg(feature = "std")]
                eprintln!("validate_signature: Equation failed at index {}: {} != {}", i, lhs, rhs);
                return Err(Falcon512Error::VerificationFailed);
            }
        }
    }
    
    Ok(())
}

/// Validate a public key
pub fn validate_public_key(public_key: &PublicKey) -> Result<()> {
    // Check size
    if public_key.h.coeffs.len() != N {
        return Err(Falcon512Error::InvalidPublicKey);
    }
    
    // Check that h is non-zero
    let all_zero = public_key.h.coeffs.iter().all(|&x| x == 0);
    if all_zero {
        return Err(Falcon512Error::InvalidPublicKey);
    }
    
    // Check coefficient bounds
    for &coeff in &public_key.h.coeffs {
        if coeff < 0 || coeff >= Q as i16 {
            return Err(Falcon512Error::InvalidPublicKey);
        }
    }
    
    // Could add more checks here, such as:
    // - h should be invertible mod q
    // - h should have certain statistical properties
    
    Ok(())
}

/// Validate a private key comprehensively
pub fn validate_private_key(private_key: &PrivateKey) -> Result<()> {
    // Compute public key from private key
    let computed_h = crate::ntt_falcon::compute_public_key_ntt(
        &private_key.f.coeffs,
        &private_key.g.coeffs,
    )?;
    
    let public_key = PublicKey {
        h: crate::poly::Poly::new(computed_h.clone()),
    };
    
    // Validate the computed public key
    validate_public_key(&public_key)?;
    
    // Check sizes
    if private_key.f.coeffs.len() != N || 
       private_key.g.coeffs.len() != N ||
       private_key.big_f.coeffs.len() != N ||
       private_key.big_g.coeffs.len() != N {
        return Err(Falcon512Error::InvalidPrivateKey);
    }
    
    // Create NTRU basis for validation
    let basis = NTRUBasis::new(
        private_key.f.coeffs.clone(),
        private_key.g.coeffs.clone(),
        private_key.big_f.coeffs.clone(),
        private_key.big_g.coeffs.clone(),
    )?;
    
    // Check NTRU equation validity
    if !basis.quality.ntru_valid {
        #[cfg(feature = "std")]
        eprintln!("validate_private_key: NTRU equation not satisfied");
        return Err(Falcon512Error::InvalidPrivateKey);
    }
    
    // Check that basis is suitable for signing
    if !basis.is_valid_for_signing() {
        #[cfg(feature = "std")]
        eprintln!("validate_private_key: Basis not suitable for signing");
        eprintln!("  Condition number: {}", basis.quality.condition_number);
        eprintln!("  GS norm: {}", basis.quality.gs_norm);
        eprintln!("  Is stable: {}", basis.quality.is_stable);
        return Err(Falcon512Error::InvalidPrivateKey);
    }
    
    // h = g/f was already computed and validated above
    
    // Check coefficient bounds for small polynomials
    for &coeff in &private_key.f.coeffs {
        if coeff.abs() > 127 {  // f, g should be small
            #[cfg(feature = "std")]
            eprintln!("validate_private_key: f coefficient too large: {}", coeff);
            return Err(Falcon512Error::InvalidPrivateKey);
        }
    }
    
    for &coeff in &private_key.g.coeffs {
        if coeff.abs() > 127 {
            #[cfg(feature = "std")]
            eprintln!("validate_private_key: g coefficient too large: {}", coeff);
            return Err(Falcon512Error::InvalidPrivateKey);
        }
    }
    
    Ok(())
}

/// Validate a complete keypair
pub fn validate_keypair(keypair: &KeyPair) -> Result<()> {
    // Validate public key
    validate_public_key(&keypair.public_key)?;
    
    // Validate private key
    validate_private_key(&keypair.private_key)?;
    
    // Check consistency: compute h from private key and compare
    let computed_h = crate::ntt_falcon::compute_public_key_ntt(
        &keypair.private_key.f.coeffs,
        &keypair.private_key.g.coeffs,
    )?;
    
    if computed_h != keypair.public_key.h.coeffs {
        return Err(Falcon512Error::InvalidKey);
    }
    
    Ok(())
}

/// Batch validation of multiple signatures
pub fn validate_signatures_batch(
    signatures: &[(Vec<i16>, Vec<i16>)],
    public_keys: &[PublicKey],
    messages: &[Vec<i16>],
    params: &SignatureValidation,
) -> Vec<bool> {
    let n = signatures.len();
    if public_keys.len() != n || messages.len() != n {
        return vec![false; n];
    }
    
    let mut results = Vec::with_capacity(n);
    
    for i in 0..n {
        let valid = validate_signature(
            &signatures[i].0,
            &signatures[i].1,
            &public_keys[i].h.coeffs,
            &messages[i],
            params,
        ).is_ok();
        
        results.push(valid);
    }
    
    results
}

/// Statistical validation of signature distribution
pub fn validate_signature_statistics(signatures: &[(Vec<i16>, Vec<i16>)]) -> bool {
    if signatures.is_empty() {
        return false;
    }

    #[cfg(feature = "std")]
    eprintln!(
        "validate_signature_statistics: statistical validation is heuristic-only and unavailable in Phase 0"
    );

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    
    #[test]
    fn test_signature_validation() {
        let s0 = vec![10i16; N];
        let s1 = vec![5i16; N];
        let h = vec![1i16; N];
        
        // Compute c = s0 + s1*h for valid equation
        let s1h = crate::ntt_falcon::multiply_ntt(&s1, &h);
        let mut c = vec![0i16; N];
        for i in 0..N {
            c[i] = (s0[i] as i32 + s1h[i] as i32).rem_euclid(Q as i32) as i16;
        }
        
        let params = SignatureValidation::default();
        
        // Should validate successfully
        validate_signature(&s0, &s1, &h, &c, &params)
            .expect("Valid signature should pass validation");
        
        // Invalid signature (wrong equation)
        c[0] = (c[0] + 1) % Q as i16;
        assert!(validate_signature(&s0, &s1, &h, &c, &params).is_err());
    }
    
    #[test]
    fn test_public_key_validation() {
        // Valid public key
        let mut pk = PublicKey {
            h: crate::poly::Poly::new(vec![1i16; N]),
        };
        
        validate_public_key(&pk).expect("Valid public key should pass");
        
        // Invalid: all zeros
        pk.h.coeffs = vec![0i16; N];
        assert!(validate_public_key(&pk).is_err());
        
        // Invalid: out of range
        pk.h.coeffs = vec![Q as i16; N];
        assert!(validate_public_key(&pk).is_err());
    }

    #[test]
    fn test_private_key_validation_accepts_generated_keypair() {
        let mut rng = ChaCha20Rng::from_seed([91u8; 32]);
        let keypair = crate::generate_keypair(&mut rng)
            .expect("generated keypair should be structurally valid");

        validate_private_key(&keypair.private_key)
            .expect("generated private key should pass validation");
    }

    #[test]
    fn test_private_key_validation_rejects_large_small_coefficients() {
        let mut rng = ChaCha20Rng::from_seed([92u8; 32]);
        let keypair = crate::generate_keypair(&mut rng)
            .expect("generated keypair should be available for mutation");

        let mut invalid_private_key = keypair.private_key.clone();
        invalid_private_key.f.coeffs[0] = 200;

        assert!(validate_private_key(&invalid_private_key).is_err());
    }

    #[test]
    fn test_signature_statistics_fail_closed() {
        assert!(!validate_signature_statistics(&[]));

        let signatures = vec![(vec![0i16; N], vec![0i16; N])];
        assert!(!validate_signature_statistics(&signatures));
    }
}
