//! Compressed signing implementation for Falcon-512
//! 
//! This module provides signing with proper NIST-compliant compression
//! to ensure signatures fit within the 666-byte limit.

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::{PrivateKey, PublicKey};
use crate::shake::Shake256Context;
use crate::ffsampling_falcon::ExpandedKey;
use crate::s0_reconstruction::reconstruct_s0;
use crate::ntt_falcon;
use rand::RngCore;
use alloc::vec::Vec;

/// Maximum signature size in bytes (NIST requirement)
const MAX_SIGNATURE_BYTES: usize = 666;

/// Sign a message with compression to meet NIST size requirements
pub fn sign_compressed<R: RngCore>(
    message: &[u8],
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    // Maximum attempts for size-compliant signature
    const MAX_ATTEMPTS: usize = 256;
    
    for attempt in 0..MAX_ATTEMPTS {
        // Generate 40-byte nonce
        let mut nonce = [0u8; 40];
        rng.fill_bytes(&mut nonce);
        
        // Hash message with nonce
        let mut shake = Shake256Context::new();
        shake.update(&nonce);
        shake.update(message);
        let mut reader = shake.finalize_xof();
        let mut hashed = vec![0u8; N * 2];
        reader.read(&mut hashed);
        
        // Convert to polynomial
        let c = hash_to_poly(&hashed)?;
        
        // Create expanded key (SIMD-accelerated FFSampling)
        let sigma = 165.7366171829776; // Falcon-512 standard deviation
        let expanded = ExpandedKey::new(
            &private_key.f.coeffs,
            &private_key.g.coeffs,
            &private_key.big_f.coeffs,
            &private_key.big_g.coeffs,
            sigma,
        );

        // Sample signature
        let (s0, s1) = match expanded.sign_sample(&c, rng) {
            Ok(sig) => sig,
            Err(_) => continue, // Retry on sampling failure
        };
        
        // Check norm bound
        if !check_signature_norm(&s0, &s1) {
            continue; // Retry if norm too large
        }
        
        // Encode with the reference `comp` coder (unary + 7 low bits), the
        // same wire format as `nist_encoding::encode_signature`. The previous
        // `comp_encode_adaptive` picked a fixed bit width per signature, which
        // costs >= 705 bytes for spec-width s1 — it only ever fit under 666
        // bytes because the pre-#142 Babai-rounding signer emitted s1 ~5x
        // narrower than the spec. Retry (fresh nonce) on the rare oversize.
        let sig = crate::nist_encoding::encode_signature(&s1, &nonce, 9);
        if sig.len() <= MAX_SIGNATURE_BYTES {
            return Ok(sig);
        }
    }
    
    Err(Falcon512Error::SigningFailed)
}

/// Verify a compressed signature
pub fn verify_compressed(
    message: &[u8],
    signature: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    // Parse NIST-format signature: header(0x39) + nonce(40) + comp(s1)
    let (nonce, s1) = crate::nist_encoding::decode_signature(signature, 9)?;

    // Hash message with nonce
    let mut shake = Shake256Context::new();
    shake.update(&nonce);
    shake.update(message);
    let mut reader = shake.finalize_xof();
    let mut hashed = vec![0u8; N * 2];
    reader.read(&mut hashed);

    // Convert to polynomial
    let c = hash_to_poly(&hashed)?;
    
    // Reconstruct s0 from equation: s0 = c - s1*h (mod q)
    let s0 = reconstruct_s0(&s1, &c, &public_key.h.coeffs)?;
    
    // The norm check is what makes the signature unforgeable: s0 is computed
    // from the equation below, so the equation holds for every s1 and cannot
    // reject anything on its own. Without this check the function accepted any
    // well-formed signature for any message (#360). reconstruct_s0 centers s0.
    if !verify_signature_norm(&s0, &s1) {
        return Ok(false);
    }

    // Verify equation: s0 + s1*h = c (mod q)
    let s1h = ntt_falcon::multiply_ntt(&s1, &public_key.h.coeffs);

    for i in 0..N {
        let lhs = (s0[i] as i32 + s1h[i] as i32).rem_euclid(Q as i32);
        let rhs = (c[i] as i32).rem_euclid(Q as i32);

        if lhs != rhs {
            return Ok(false);
        }
    }
    
    Ok(true)
}

/// Convert hash output to polynomial coefficients
fn hash_to_poly(hashed: &[u8]) -> Result<Vec<i16>> {
    if hashed.len() < N * 2 {
        return Err(Falcon512Error::InvalidParameter);
    }
    
    let mut c = vec![0i16; N];
    for i in 0..N {
        let val = ((hashed[i * 2] as u16) | ((hashed[i * 2 + 1] as u16) << 8)) as u32;
        c[i] = (val % Q as u32) as i16;
        
        // Center reduce to [-q/2, q/2)
        if c[i] > Q as i16 / 2 {
            c[i] -= Q as i16;
        }
    }
    
    Ok(c)
}

/// Verifier-side norm check: Algorithm 16 accepts ||(s0, s1)||^2 <= floor(beta^2) (#352).
fn verify_signature_norm(s0: &[i16], s1: &[i16]) -> bool {
    let norm_sq: i64 = s0.iter().map(|&x| x as i64 * x as i64).sum::<i64>()
        + s1.iter().map(|&x| x as i64 * x as i64).sum::<i64>();
    norm_sq <= 34034726
}

/// Check if signature norm is within bounds
fn check_signature_norm(s0: &[i16], s1: &[i16]) -> bool {
    let norm_sq: i64 = s0.iter().map(|&x| x as i64 * x as i64).sum::<i64>()
        + s1.iter().map(|&x| x as i64 * x as i64).sum::<i64>();
    
    norm_sq < 34034726 // Falcon-512 bound
}

/// Configuration for compressed signing
#[derive(Clone, Debug)]
pub struct CompressionConfig {
    /// Maximum attempts before giving up
    pub max_attempts: usize,
    /// Target compression ratio
    pub target_ratio: f32,
    /// Enable adaptive encoding
    pub adaptive: bool,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            max_attempts: 256,
            target_ratio: 0.5, // Target 50% compression
            adaptive: true,
        }
    }
}

/// Sign with custom compression configuration
pub fn sign_compressed_with_config<R: RngCore>(
    message: &[u8],
    private_key: &PrivateKey,
    rng: &mut R,
    config: &CompressionConfig,
) -> Result<Vec<u8>> {
    // Use the standard compressed signing with config parameters
    for _ in 0..config.max_attempts {
        match sign_compressed(message, private_key, rng) {
            Ok(sig) if sig.len() <= MAX_SIGNATURE_BYTES => return Ok(sig),
            _ => continue,
        }
    }
    
    Err(Falcon512Error::CompressionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    
    #[test]
    fn test_compressed_signature_size() {
        let mut rng = StdRng::seed_from_u64(12345);
        let keypair = generate_keypair(&mut rng).unwrap();
        
        let message = b"Test message for compression";
        
        // Sign with compression
        let signature = sign_compressed(message, &keypair.private_key, &mut rng).unwrap();
        
        // Check size is within NIST limit
        assert!(signature.len() <= MAX_SIGNATURE_BYTES,
                "Compressed signature too large: {} bytes", signature.len());
        
        println!("Compressed signature size: {} bytes", signature.len());
        
        // Verify the compressed signature
        assert!(verify_compressed(message, &signature, &keypair.public_key).unwrap());
    }
    
    #[test]
    fn test_compression_success_rate() {
        let mut rng = StdRng::seed_from_u64(54321);
        let keypair = generate_keypair(&mut rng).unwrap();
        
        let message = b"Test message";
        let num_trials = 100;
        let mut successes = 0;
        let mut total_size = 0;
        
        for _ in 0..num_trials {
            if let Ok(sig) = sign_compressed(message, &keypair.private_key, &mut rng) {
                successes += 1;
                total_size += sig.len();
                
                // Verify it
                assert!(verify_compressed(message, &sig, &keypair.public_key).unwrap());
            }
        }
        
        let success_rate = successes as f64 / num_trials as f64;
        let avg_size = total_size as f64 / successes as f64;
        
        println!("Compression success rate: {:.1}%", success_rate * 100.0);
        println!("Average compressed size: {:.0} bytes", avg_size);
        
        assert!(success_rate > 0.95, "Compression success rate too low");
    }
}