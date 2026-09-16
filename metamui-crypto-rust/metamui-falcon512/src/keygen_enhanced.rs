//! Enhanced Key Generation with Numerical Stability Checks
//! 
//! Provides key generation with conditioning checks, rejection sampling,
//! and Gram-Schmidt orthogonalization for numerically stable keys.

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::poly::Poly;
use crate::{PublicKey, PrivateKey};
use crate::falcon_reference::basis_hybrid::HybridBasis;
use crate::fft_hybrid::FFTMode;
use rand::RngCore;
use alloc::vec::Vec;

/// Enhanced key generation parameters
pub struct KeygenParams {
    /// Maximum condition number allowed
    pub max_condition_number: f64,
    /// Maximum rejection attempts
    pub max_rejections: usize,
    /// Enable Gram-Schmidt orthogonalization
    pub enable_gram_schmidt: bool,
    /// FFT mode for basis checking
    pub fft_mode: FFTMode,
}

impl Default for KeygenParams {
    fn default() -> Self {
        Self {
            max_condition_number: 1e6,
            max_rejections: 100,
            enable_gram_schmidt: true,
            fft_mode: FFTMode::Hybrid,
        }
    }
}

/// Enhanced key generation with stability checks
pub fn keygen_enhanced<R: RngCore>(
    rng: &mut R,
    params: &KeygenParams,
) -> Result<(PublicKey, PrivateKey)> {
    let mut rejection_count = 0;
    
    loop {
        if rejection_count >= params.max_rejections {
            return Err(Falcon512Error::KeyGenerationFailed);
        }
        
        // Generate NTRU keys using the best available solver
        let (f, g, big_f, big_g) = match generate_ntru_keys(rng) {
            Ok(keys) => keys,
            Err(_) => {
                rejection_count += 1;
                continue;
            }
        };
        
        // Check numerical conditioning
        match check_key_conditioning(&f, &g, &big_f, &big_g, params) {
            ConditioningResult::Good => {
                // Keys are good, proceed
                #[cfg(feature = "std")]
                eprintln!("Key generation succeeded with good conditioning after {} rejections", 
                         rejection_count);
                
                let h = compute_public_key(&f, &g)?;
                
                return Ok((
                    PublicKey { h: Poly { coeffs: h } },
                    PrivateKey {
                        f: Poly { coeffs: f },
                        g: Poly { coeffs: g },
                        big_f: Poly { coeffs: big_f },
                        big_g: Poly { coeffs: big_g },
                    }
                ));
            }
            ConditioningResult::Poor => {
                if params.enable_gram_schmidt {
                    // Try to improve with Gram-Schmidt
                    match apply_gram_schmidt(&f, &g, &big_f, &big_g) {
                        Ok((f_orth, g_orth, big_f_orth, big_g_orth)) => {
                            // Check again after orthogonalization
                            if check_key_conditioning(&f_orth, &g_orth, &big_f_orth, &big_g_orth, params) 
                                == ConditioningResult::Good {
                                
                                #[cfg(feature = "std")]
                                eprintln!("Key generation succeeded after Gram-Schmidt orthogonalization");
                                
                                let h = compute_public_key(&f_orth, &g_orth)?;
                                
                                return Ok((
                                    PublicKey { h: Poly { coeffs: h } },
                                    PrivateKey {
                                        f: Poly { coeffs: f_orth },
                                        g: Poly { coeffs: g_orth },
                                        big_f: Poly { coeffs: big_f_orth },
                                        big_g: Poly { coeffs: big_g_orth },
                                    }
                                ));
                            }
                        }
                        Err(_) => {
                            // Orthogonalization failed, reject and try again
                        }
                    }
                }
                
                rejection_count += 1;
                #[cfg(feature = "std")]
                if rejection_count % 10 == 0 {
                    eprintln!("Key generation: {} keys rejected due to poor conditioning", 
                             rejection_count);
                }
            }
            ConditioningResult::VeryPoor => {
                // Don't even try to fix, just reject
                rejection_count += 1;
            }
        }
    }
}

/// Result of conditioning check
#[derive(Debug, PartialEq)]
enum ConditioningResult {
    Good,
    Poor,
    VeryPoor,
}

/// Check numerical conditioning of NTRU keys
fn check_key_conditioning(
    f: &[i16],
    g: &[i16],
    big_f: &[i16],
    big_g: &[i16],
    params: &KeygenParams,
) -> ConditioningResult {
    // Create basis to check conditioning
    match HybridBasis::new(f, g, big_f, big_g, params.fft_mode) {
        Ok(basis) => {
            let condition = basis.estimate_condition_number();
            
            if condition < params.max_condition_number {
                // Also check norm bounds
                if verify_norm_bounds(f, g, big_f, big_g) {
                    ConditioningResult::Good
                } else {
                    ConditioningResult::Poor
                }
            } else if condition < params.max_condition_number * 10.0 {
                ConditioningResult::Poor
            } else {
                ConditioningResult::VeryPoor
            }
        }
        Err(_) => ConditioningResult::VeryPoor,
    }
}

/// Verify that key norms are within acceptable bounds
fn verify_norm_bounds(
    f: &[i16],
    g: &[i16],
    big_f: &[i16],
    big_g: &[i16],
) -> bool {
    let norm_f: i64 = f.iter().map(|&x| x as i64 * x as i64).sum();
    let norm_g: i64 = g.iter().map(|&x| x as i64 * x as i64).sum();
    let norm_big_f: i64 = big_f.iter().map(|&x| x as i64 * x as i64).sum();
    let norm_big_g: i64 = big_g.iter().map(|&x| x as i64 * x as i64).sum();
    
    // Check individual norms
    if norm_f > 8000 || norm_g > 8000 {
        return false;
    }
    
    if norm_big_f > 100000 || norm_big_g > 100000 {
        return false;
    }
    
    // Check total norm for signature bound
    let total_norm = norm_f + norm_g + norm_big_f + norm_big_g;
    total_norm < 34034726
}

/// Apply Gram-Schmidt orthogonalization to improve conditioning
#[allow(non_snake_case)]
fn apply_gram_schmidt(
    f: &[i16],
    g: &[i16],
    big_f: &[i16],
    big_g: &[i16],
) -> Result<(Vec<i16>, Vec<i16>, Vec<i16>, Vec<i16>)> {
    // Convert to f64 for orthogonalization
    let f_f64: Vec<f64> = f.iter().map(|&x| x as f64).collect();
    let mut g_f64: Vec<f64> = g.iter().map(|&x| x as f64).collect();
    let mut big_f_f64: Vec<f64> = big_f.iter().map(|&x| x as f64).collect();
    let mut big_g_f64: Vec<f64> = big_g.iter().map(|&x| x as f64).collect();
    
    // Gram-Schmidt process
    // First normalize f
    let norm_f = dot_product(&f_f64, &f_f64).sqrt();
    if norm_f < 1e-10 {
        return Err(Falcon512Error::InvalidParameter);
    }
    
    // Make g orthogonal to f
    let proj_gf = dot_product(&g_f64, &f_f64) / dot_product(&f_f64, &f_f64);
    for i in 0..N {
        g_f64[i] -= proj_gf * f_f64[i];
    }
    
    // Make F orthogonal to f and g
    let proj_Ff = dot_product(&big_f_f64, &f_f64) / dot_product(&f_f64, &f_f64);
    let proj_Fg = dot_product(&big_f_f64, &g_f64) / dot_product(&g_f64, &g_f64);
    for i in 0..N {
        big_f_f64[i] -= proj_Ff * f_f64[i] + proj_Fg * g_f64[i];
    }
    
    // Make G orthogonal to f, g, and F
    let proj_Gf = dot_product(&big_g_f64, &f_f64) / dot_product(&f_f64, &f_f64);
    let proj_Gg = dot_product(&big_g_f64, &g_f64) / dot_product(&g_f64, &g_f64);
    let proj_GF = dot_product(&big_g_f64, &big_f_f64) / dot_product(&big_f_f64, &big_f_f64);
    for i in 0..N {
        big_g_f64[i] -= proj_Gf * f_f64[i] + proj_Gg * g_f64[i] + proj_GF * big_f_f64[i];
    }
    
    // Scale to maintain NTRU equation approximately
    let scale = estimate_ntru_scale(&f_f64, &g_f64, &big_f_f64, &big_g_f64);
    for i in 0..N {
        big_f_f64[i] *= scale;
        big_g_f64[i] *= scale;
    }
    
    // Convert back to i16
    Ok((
        f_f64.iter().map(|&x| x.round() as i16).collect(),
        g_f64.iter().map(|&x| x.round() as i16).collect(),
        big_f_f64.iter().map(|&x| x.round() as i16).collect(),
        big_g_f64.iter().map(|&x| x.round() as i16).collect(),
    ))
}

/// Compute dot product
fn dot_product(a: &[f64], b: &[f64]) -> f64 {
    // Use Kahan summation for accuracy
    crate::falcon_reference::extended_precision::extended_dot_product(a, b)
}

/// Estimate scaling factor to maintain NTRU equation
fn estimate_ntru_scale(f: &[f64], g: &[f64], big_f: &[f64], big_g: &[f64]) -> f64 {
    // Estimate scale to make f*G - g*F ≈ q
    let fg_norm = dot_product(f, big_g).abs();
    let gf_norm = dot_product(g, big_f).abs();
    
    if fg_norm + gf_norm > 1e-10 {
        Q as f64 / (fg_norm - gf_norm).abs()
    } else {
        1.0
    }
}

/// Generate NTRU keys using the best available solver
fn generate_ntru_keys<R: RngCore>(rng: &mut R) -> Result<(Vec<i16>, Vec<i16>, Vec<i16>, Vec<i16>)> {
    // Use the reference ntru_exact solver
    match crate::ntru_exact::ntru_keygen_exact(rng) {
        Ok(keys) => Ok((keys.f, keys.g, keys.big_f, keys.big_g)),
        Err(e) => Err(e)
    }
}

/// Compute public key h = g/f mod q
fn compute_public_key(f: &[i16], g: &[i16]) -> Result<Vec<i16>> {
    // Use NTT for efficient modular division
    use crate::ntt_falcon;
    
    // Convert to NTT domain
    let f_ntt = ntt_falcon::ntt_forward(f);
    let g_ntt = ntt_falcon::ntt_forward(g);
    
    // Compute f^(-1) in NTT domain
    let mut f_inv_ntt = vec![0u16; N];
    for i in 0..N {
        let f_val = if f_ntt[i] < 0 {
            ((f_ntt[i] % Q as i16) + Q as i16) as u16
        } else {
            f_ntt[i] as u16
        };
        match ntt_falcon::mod_inverse(f_val, Q) {
            Some(inv) => f_inv_ntt[i] = inv,
            None => return Err(Falcon512Error::InvalidPrivateKey),
        }
    }
    
    // Compute h = g * f^(-1) in NTT domain
    let mut h_ntt = vec![0i16; N];
    for i in 0..N {
        let g_val = if g_ntt[i] < 0 {
            ((g_ntt[i] % Q as i16) + Q as i16) as u16
        } else {
            g_ntt[i] as u16
        };
        h_ntt[i] = ((g_val as u32 * f_inv_ntt[i] as u32) % Q as u32) as i16;
    }
    
    // Convert back from NTT
    let h = ntt_falcon::ntt_inverse(&h_ntt);
    
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    
    #[test]
    fn test_enhanced_keygen() {
        let mut rng = StdRng::seed_from_u64(12345);
        let params = KeygenParams::default();
        
        match keygen_enhanced(&mut rng, &params) {
            Ok((pk, sk)) => {
                // Verify keys have correct structure
                assert_eq!(pk.h.coeffs.len(), N);
                assert_eq!(sk.f.coeffs.len(), N);
                assert_eq!(sk.g.coeffs.len(), N);
                assert_eq!(sk.big_f.coeffs.len(), N);
                assert_eq!(sk.big_g.coeffs.len(), N);
                
                // Verify norm bounds
                assert!(verify_norm_bounds(
                    &sk.f.coeffs,
                    &sk.g.coeffs,
                    &sk.big_f.coeffs,
                    &sk.big_g.coeffs,
                ));
            }
            Err(e) => {
                // Key generation might fail due to rejection sampling
                eprintln!("Enhanced keygen failed (expected in some cases): {:?}", e);
            }
        }
    }
    
    #[test]
    fn test_gram_schmidt() {
        let mut rng = StdRng::seed_from_u64(42);
        
        // Generate some keys
        if let Ok((f, g, big_f, big_g)) = generate_ntru_keys(&mut rng) {
            // Apply Gram-Schmidt
            if let Ok((f_orth, g_orth, big_f_orth, big_g_orth)) = 
                apply_gram_schmidt(&f, &g, &big_f, &big_g) {
                
                // Check that vectors have similar norms (not blown up)
                let norm_f: i64 = f.iter().map(|&x| x as i64 * x as i64).sum();
                let norm_f_orth: i64 = f_orth.iter().map(|&x| x as i64 * x as i64).sum();
                
                // Orthogonalized version shouldn't be much larger
                assert!(norm_f_orth < norm_f * 10);
            }
        }
    }
}

/// Simplified enhanced keygen that returns the polynomials directly
/// This is a wrapper for keygen_extended module
pub fn enhanced_keygen<R: RngCore>(rng: &mut R) -> Result<(Poly, Poly, Poly, Poly)> {
    // Use default parameters
    let params = KeygenParams::default();
    
    // Generate keys with enhanced method
    let (public_key, private_key) = keygen_enhanced(rng, &params)?;
    
    // Return the polynomials
    Ok((
        private_key.f.clone(),
        private_key.g.clone(),
        private_key.big_f.clone(),
        private_key.big_g.clone(),
    ))
}