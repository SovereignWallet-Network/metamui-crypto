//! Corrected signing implementation for Falcon-512
//! 
//! This module integrates all the corrected components to provide
//! a working signature generation that satisfies the NTRU equation.

use crate::constants::{N, Q, SALT_LEN};
use crate::error::{Result, Falcon512Error};
use crate::ntru_basis::NTRUBasis;
use crate::ffsampling_correct::{FFSamplerCorrect, verify_signature_equation};
use crate::falcon::{PrivateKey, PublicKey};
use alloc::vec::Vec;
use rand::RngCore;

/// Maximum attempts for signature generation
const MAX_SIGN_ATTEMPTS: usize = 100;

/// Corrected signing function that ensures equation satisfaction
pub fn sign_corrected<R: RngCore>(
    message: &[u8],
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    // Create NTRU basis from private key
    let basis = NTRUBasis::new(
        private_key.f.coeffs.clone(),
        private_key.g.coeffs.clone(),
        private_key.big_f.coeffs.clone(),
        private_key.big_g.coeffs.clone(),
    )?;
    
    // Check if basis is valid
    if !basis.is_valid_for_signing() {
        #[cfg(feature = "std")]
        eprintln!("Warning: Private key basis may not be suitable for signing");
        
        // Try to continue anyway, but with increased attempts
    }
    
    // Create the corrected sampler
    let sampler = FFSamplerCorrect::new(basis.clone())?;
    
    // Try multiple times with different salts
    for attempt in 0..MAX_SIGN_ATTEMPTS {
        #[cfg(feature = "std")]
        if attempt > 0 && attempt % 10 == 0 {
            eprintln!("sign_corrected: Attempt {} of {}", attempt + 1, MAX_SIGN_ATTEMPTS);
        }
        
        // Generate random salt
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        
        // Hash message to polynomial
        let c = hash_to_point_corrected(message, &salt);
        
        // Try to sample a valid signature
        match sampler.sample_signature(&c, rng) {
            Ok((s0, s1)) => {
                // Double-check equation satisfaction
                if !verify_signature_equation(&s0, &s1, &basis.h, &c) {
                    #[cfg(feature = "std")]
                    eprintln!("sign_corrected: Equation verification failed on attempt {}", attempt + 1);
                    continue;
                }
                
                // Check norm bounds
                let norm_sq: i64 = s0.iter().map(|&x| x as i64 * x as i64).sum::<i64>()
                    + s1.iter().map(|&x| x as i64 * x as i64).sum::<i64>();
                
                if norm_sq >= 34034726 {
                    #[cfg(feature = "std")]
                    eprintln!("sign_corrected: Norm too large ({}) on attempt {}", norm_sq, attempt + 1);
                    continue;
                }
                
                // Compress and return signature
                let compressed = compress_signature_corrected(&s0, &s1, &salt)?;
                
                #[cfg(feature = "std")]
                eprintln!("sign_corrected: SUCCESS after {} attempts", attempt + 1);
                
                return Ok(compressed);
            }
            Err(e) => {
                #[cfg(feature = "std")]
                if attempt < 5 || attempt % 10 == 0 {
                    eprintln!("sign_corrected: Sampling failed on attempt {}: {:?}", attempt + 1, e);
                }
                
                // Continue with next attempt
                continue;
            }
        }
    }
    
    Err(Falcon512Error::SigningFailed)
}

/// Hash message and salt to a polynomial
fn hash_to_point_corrected(message: &[u8], salt: &[u8]) -> Vec<i16> {
    use metamui_sha2::Sha256Hasher;
    
    let mut hasher = Sha256Hasher::new();
    hasher.update(salt);
    hasher.update(message);
    let hash = hasher.finalize();
    
    // Convert hash to polynomial coefficients
    let mut c = vec![0i16; N];
    let mut hash_bytes = hash.to_vec();
    
    // Extend hash if needed
    while hash_bytes.len() < N * 2 {
        let mut hasher = Sha256Hasher::new();
        hasher.update(&hash_bytes);
        hasher.update(&[hash_bytes.len() as u8]);
        let extended = hasher.finalize();
        hash_bytes.extend_from_slice(&extended);
    }
    
    // Convert to coefficients mod q
    for i in 0..N {
        let val = ((hash_bytes[2*i] as u16) | ((hash_bytes[2*i + 1] as u16) << 8)) as u32;
        c[i] = (val % Q as u32) as i16;
        
        // Center reduce
        if c[i] > (Q / 2) as i16 {
            c[i] -= Q as i16;
        }
    }
    
    c
}

/// Compress signature using simple encoding
fn compress_signature_corrected(s0: &[i16], s1: &[i16], salt: &[u8]) -> Result<Vec<u8>> {
    let mut compressed = Vec::new();
    
    // Add salt
    compressed.extend_from_slice(salt);
    
    // Encode s1 (s0 can be recovered from equation)
    for &coeff in s1 {
        // Simple 12-bit encoding for coefficients in [-2047, 2047]
        if coeff.abs() > 2047 {
            return Err(Falcon512Error::SignatureTooLarge);
        }
        
        let val = (coeff + 2048) as u16;
        compressed.push((val & 0xFF) as u8);
        compressed.push(((val >> 8) & 0x0F) as u8);
    }
    
    Ok(compressed)
}

/// Verify a signature using the corrected algorithm
pub fn verify_corrected(
    message: &[u8],
    signature: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    // Extract salt and s1 from signature
    if signature.len() < SALT_LEN {
        return Ok(false);
    }
    
    let salt = &signature[..SALT_LEN];
    let s1_encoded = &signature[SALT_LEN..];
    
    // Decode s1
    let mut s1 = vec![0i16; N];
    if s1_encoded.len() < N * 3 / 2 {
        return Ok(false);
    }
    
    for i in 0..N {
        let idx = i * 3 / 2;
        if i % 2 == 0 {
            let val = (s1_encoded[idx] as u16) | ((s1_encoded[idx + 1] as u16 & 0x0F) << 8);
            s1[i] = (val as i16) - 2048;
        } else {
            let val = ((s1_encoded[idx] as u16) >> 4) | ((s1_encoded[idx + 1] as u16) << 4);
            s1[i] = (val as i16) - 2048;
        }
    }
    
    // Hash message to get c
    let c = hash_to_point_corrected(message, salt);
    
    // Compute s0 from equation: s0 = c - s1*h
    let s1h = crate::ntt_falcon::multiply_ntt(&s1, &public_key.h.coeffs);
    let mut s0 = vec![0i16; N];
    
    for i in 0..N {
        let diff = (c[i] as i32 - s1h[i] as i32).rem_euclid(Q as i32);
        s0[i] = if diff > (Q / 2) as i32 {
            (diff - Q as i32) as i16
        } else {
            diff as i16
        };
    }
    
    // Check norm bound
    let norm_sq: i64 = s0.iter().map(|&x| x as i64 * x as i64).sum::<i64>()
        + s1.iter().map(|&x| x as i64 * x as i64).sum::<i64>();
    
    if norm_sq >= 34034726 {
        return Ok(false);
    }
    
    // Verify equation
    Ok(verify_signature_equation(&s0, &s1, &public_key.h.coeffs, &c))
}

/// Adaptive signing strategy that tries multiple approaches
pub fn sign_adaptive<R: RngCore>(
    message: &[u8],
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    // First try the corrected algorithm
    match sign_corrected(message, private_key, rng) {
        Ok(sig) => return Ok(sig),
        Err(Falcon512Error::SigningFailed) => {
            #[cfg(feature = "std")]
            eprintln!("sign_adaptive: corrected algorithm exhausted attempts; refusing placeholder fallback");

            return Err(Falcon512Error::NotImplemented);
        }
        Err(err) => return Err(err),
    }
}

/// Fallback signing using simpler approach
fn sign_fallback<R: RngCore>(
    _message: &[u8],
    _private_key: &PrivateKey,
    _rng: &mut R,
) -> Result<Vec<u8>> {
    Err(Falcon512Error::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    
    #[test]
    fn test_hash_to_point() {
        let message = b"test message";
        let salt = [0u8; SALT_LEN];
        
        let c = hash_to_point_corrected(message, &salt);
        
        assert_eq!(c.len(), N);
        for &coeff in &c {
            assert!(coeff.abs() <= (Q / 2) as i16);
        }
    }
    
    #[test]
    fn test_signature_compression() {
        let s0 = vec![100i16; N];
        let s1 = vec![50i16; N];
        let salt = [0u8; SALT_LEN];
        
        let compressed = compress_signature_corrected(&s0, &s1, &salt)
            .expect("Compression should succeed");
        
        assert!(compressed.len() > SALT_LEN);
        assert_eq!(&compressed[..SALT_LEN], &salt);
    }

    #[test]
    fn test_sign_fallback_fails_closed() {
        let mut rng = StdRng::seed_from_u64(42);
        let private_key = PrivateKey {
            f: crate::poly::Poly::new(vec![0i16; N]),
            g: crate::poly::Poly::new(vec![0i16; N]),
            big_f: crate::poly::Poly::new(vec![0i16; N]),
            big_g: crate::poly::Poly::new(vec![0i16; N]),
        };

        let result = sign_fallback(b"message", &private_key, &mut rng);

        assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
    }
}
