//! Enhanced signature verification with proper equation checking
//! 
//! This module implements complete signature verification including:
//! - Signature equation verification: s0 + s1*h = c (mod q)
//! - Norm bound checking
//! - s0 reconstruction for compressed signatures

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::poly::Poly;
use crate::{PublicKey};
use alloc::vec::Vec;

/// Verify the signature equation: s0 + s1*h = c (mod q)
/// 
/// This is the core security property of Falcon signatures.
/// A signature (s0, s1) is valid for message m with public key h if:
/// - s0 + s1*h = H(m || salt) (mod q)
/// - ||(s0, s1)|| < beta (norm bound)
pub fn verify_signature_equation_complete(
    s0: &[i16],
    s1: &[i16], 
    h: &[i16],
    c: &[i16]
) -> bool {
    if s0.len() != N || s1.len() != N || h.len() != N || c.len() != N {
        return false;
    }
    
    // Compute s1*h using NTT for efficiency
    let s1_poly = Poly::new(s1.to_vec());
    let h_poly = Poly::new(h.to_vec());
    
    // Use NTT multiplication
    let s1h = crate::fft::NTT::multiply(&s1_poly, &h_poly);
    
    // Check equation: s0 + s1*h = c (mod q)
    // Both sides must be reduced to the same centered range [-q/2, q/2]
    for i in 0..N {
        let lhs = center_reduce(s0[i] as i32 + s1h.coeffs[i] as i32);
        let rhs = center_reduce(c[i] as i32);

        if lhs != rhs {
            #[cfg(feature = "std")]
            eprintln!("Equation verification failed at index {}: {} != {} (s0={}, s1h={})",
                     i, lhs, rhs, s0[i], s1h.coeffs[i]);
            return false;
        }
    }
    
    true
}

/// Reduce value to centered range [-q/2, q/2]
fn center_reduce(x: i32) -> i16 {
    let x = x.rem_euclid(Q as i32);
    if x > Q as i32 / 2 {
        (x - Q as i32) as i16
    } else {
        x as i16
    }
}

/// Verify signature norm bound
/// 
/// For Falcon-512, the norm bound is beta^2 = 34034726
pub fn verify_signature_norm(s0: &[i16], s1: &[i16]) -> bool {
    let norm_sq: i64 = s0.iter().map(|&x| x as i64 * x as i64).sum::<i64>()
        + s1.iter().map(|&x| x as i64 * x as i64).sum::<i64>();
    
    // Falcon-512 norm bound: accept ||s||^2 <= floor(beta^2) (#352)
    norm_sq <= 34034726
}

/// Reconstruct s0 from s1, h, and c
/// 
/// Given s1, public key h, and challenge c, compute:
/// s0 = c - s1*h (mod q)
pub fn reconstruct_s0(s1: &[i16], h: &[i16], c: &[i16]) -> Vec<i16> {
    let s1_poly = Poly::new(s1.to_vec());
    let h_poly = Poly::new(h.to_vec());
    
    // Compute s1*h
    let s1h = crate::fft::NTT::multiply(&s1_poly, &h_poly);
    
    // Compute s0 = c - s1*h (mod q)
    let mut s0 = vec![0i16; N];
    for i in 0..N {
        let diff = (c[i] as i32 - s1h.coeffs[i] as i32).rem_euclid(Q as i32);
        s0[i] = center_reduce(diff);
    }
    
    s0
}

/// Complete signature verification with all checks
pub fn verify_signature_complete(
    message: &[u8],
    signature: &[u8],
    public_key: &PublicKey
) -> Result<bool> {
    // Decompress signature
    let (s0, s1, salt) = decompress_signature(signature)?;
    
    // Hash message to get challenge
    let c = hash_to_challenge(message, &salt);
    
    // Check if s0 needs reconstruction (for NIST format)
    let s0 = if s0.iter().all(|&x| x == 0) {
        // s0 is all zeros, need to reconstruct from s1, h, c
        reconstruct_s0(&s1, &public_key.h.coeffs, &c)
    } else {
        s0
    };
    
    // Verify norm bound
    if !verify_signature_norm(&s0, &s1) {
        #[cfg(feature = "std")]
        eprintln!("Signature norm check failed");
        return Ok(false);
    }
    
    // Verify signature equation
    if !verify_signature_equation_complete(&s0, &s1, &public_key.h.coeffs, &c) {
        #[cfg(feature = "std")]
        eprintln!("Signature equation check failed");
        return Ok(false);
    }
    
    Ok(true)
}

/// Decompress signature based on format
fn decompress_signature(signature: &[u8]) -> Result<(Vec<i16>, Vec<i16>, [u8; 40])> {
    if signature.is_empty() {
        return Err(Falcon512Error::InvalidSignature);
    }

    match signature[0] {
        0x29 => {
            // NIST format - this requires the full signed message wrapper, not just the signature
            // The signed message format is: 2 bytes sig_len + 40 bytes nonce + message + signature
            // Check if this looks like a signed message (length > typical signature)
            if signature.len() > 666 {
                // Might be a full signed message - try to extract components
                match crate::nist_signature::extract_from_signed_message_nist(signature) {
                    Ok((nonce, _message, sig)) => {
                        let (s0, s1) = crate::nist_signature::decompress_signature_nist(&sig)?;
                        let mut salt = [0u8; 40];
                        salt.copy_from_slice(&nonce);
                        Ok((s0, s1, salt))
                    }
                    Err(_) => {
                        Err(Falcon512Error::NotImplemented)
                    }
                }
            } else {
                // Just a raw signature without salt - do not guess missing context.
                Err(Falcon512Error::NotImplemented)
            }
        }
        0x39 => {
            // Simple format - both s0 and s1 stored with salt
            crate::compression_simple::decompress_signature_simple(signature)
        }
        _ => {
            // Try other formats
            match crate::compression_proper::SignatureCompressor::decompress(signature) {
                Ok(result) => Ok(result),
                Err(Falcon512Error::NotImplemented) => Err(Falcon512Error::NotImplemented),
                Err(_) => crate::compression_simple::decompress_signature_simple(signature)
            }
        }
    }
}

/// Hash message with salt to get challenge polynomial
fn hash_to_challenge(message: &[u8], salt: &[u8; 40]) -> Vec<i16> {
    crate::nist_hash::hash_to_point_nist(salt, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};
    use rand::rngs::StdRng;
    
    #[test]
    fn test_signature_equation() {
        // Test with simple values
        let c = vec![100i16; N];
        let s0 = c.clone();
        let s1 = vec![0i16; N];
        let h = vec![1i16; N];
        
        assert!(verify_signature_equation_complete(&s0, &s1, &h, &c));
    }
    
    #[test]
    fn test_s0_reconstruction() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        // Generate random values
        let h: Vec<i16> = (0..N).map(|_| (rng.next_u32() % (Q as u32)) as i16).collect();
        let c: Vec<i16> = (0..N).map(|_| (rng.next_u32() % (Q as u32)) as i16).collect();
        let s1: Vec<i16> = (0..N).map(|_| (rng.next_u32() % 100) as i16 - 50).collect();
        
        // Reconstruct s0
        let s0 = reconstruct_s0(&s1, &h, &c);
        
        // Verify equation holds
        assert!(verify_signature_equation_complete(&s0, &s1, &h, &c));
    }
    
    #[test]
    fn test_norm_verification() {
        // Valid signature (small norm)
        let s0 = vec![10i16; N];
        let s1 = vec![10i16; N];
        assert!(verify_signature_norm(&s0, &s1));
        
        // Invalid signature (large norm)
        let s0_large = vec![1000i16; N];
        let s1_large = vec![1000i16; N];
        assert!(!verify_signature_norm(&s0_large, &s1_large));
    }

    #[test]
    fn test_rejects_raw_nist_signature_without_signed_message_wrapper() {
        let raw_signature = vec![0x29; 666];
        let err = decompress_signature(&raw_signature).unwrap_err();
        assert!(matches!(err, Falcon512Error::NotImplemented));
    }

    #[test]
    fn test_rejects_unparseable_nist_wrapped_blob_without_nonce_extraction() {
        let malformed_wrapper = vec![0x29; 667];
        let err = decompress_signature(&malformed_wrapper).unwrap_err();
        assert!(matches!(err, Falcon512Error::NotImplemented));
    }

    #[test]
    fn test_rejects_generic_666_byte_blob_instead_of_falling_back_to_simple_format() {
        let generic_blob = vec![0u8; 666];
        let err = decompress_signature(&generic_blob).unwrap_err();
        assert!(matches!(err, Falcon512Error::NotImplemented));
    }
}
