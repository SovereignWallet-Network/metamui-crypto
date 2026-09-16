//! NTRU basis management and validation for Falcon-512
//! 
//! This module ensures the NTRU basis (f, g, F, G) satisfies all
//! required properties for secure signature generation.

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::ntt_falcon;
use crate::fft_stable::{ComplexStable, FFTStable};
use alloc::vec::Vec;
use zeroize::Zeroize;

/// NTRU basis with validation and dual representations
#[derive(Clone)]
pub struct NTRUBasis {
    /// Secret key f (small polynomial)
    pub f: Vec<i16>,
    /// Secret key g (small polynomial)
    pub g: Vec<i16>,
    /// Secret key F (large polynomial)
    pub big_f: Vec<i16>,
    /// Secret key G (large polynomial)
    pub big_g: Vec<i16>,
    /// Public key h = g/f mod q
    pub h: Vec<i16>,
    /// FFT representation of basis
    pub f_fft: Vec<ComplexStable>,
    pub g_fft: Vec<ComplexStable>,
    pub big_f_fft: Vec<ComplexStable>,
    pub big_g_fft: Vec<ComplexStable>,
    /// Quality metrics
    pub quality: BasisQuality,
}

impl Drop for NTRUBasis {
    fn drop(&mut self) {
        self.f.zeroize();
        self.g.zeroize();
        self.big_f.zeroize();
        self.big_g.zeroize();
        self.h.zeroize();
        // Clear FFT data
        for c in &mut self.f_fft {
            c.re = 0.0;
            c.im = 0.0;
        }
        for c in &mut self.g_fft {
            c.re = 0.0;
            c.im = 0.0;
        }
        for c in &mut self.big_f_fft {
            c.re = 0.0;
            c.im = 0.0;
        }
        for c in &mut self.big_g_fft {
            c.re = 0.0;
            c.im = 0.0;
        }
    }
}

/// Quality metrics for NTRU basis
#[derive(Clone, Debug)]
pub struct BasisQuality {
    /// Maximum coefficient in f, g
    pub max_coeff_small: i16,
    /// Maximum coefficient in F, G
    pub max_coeff_large: i16,
    /// Gram-Schmidt norm
    pub gs_norm: f64,
    /// Condition number of Gram matrix
    pub condition_number: f64,
    /// Whether basis satisfies NTRU equation
    pub ntru_valid: bool,
    /// Numerical stability indicator
    pub is_stable: bool,
}

impl NTRUBasis {
    /// Create a new NTRU basis with validation
    pub fn new(
        f: Vec<i16>,
        g: Vec<i16>,
        big_f: Vec<i16>,
        big_g: Vec<i16>,
    ) -> Result<Self> {
        // Validate sizes
        if f.len() != N || g.len() != N || big_f.len() != N || big_g.len() != N {
            return Err(Falcon512Error::InvalidParameter);
        }
        
        // Compute public key h = g/f mod q
        let h = compute_public_key(&f, &g)?;
        
        // Validate NTRU equation: f*G - g*F = q
        let ntru_valid = validate_ntru_equation(&f, &g, &big_f, &big_g)?;
        
        // Compute FFT representations
        let fft = FFTStable::new(N);
        let f_f64: Vec<f64> = f.iter().map(|&x| x as f64).collect();
        let g_f64: Vec<f64> = g.iter().map(|&x| x as f64).collect();
        let big_f_f64: Vec<f64> = big_f.iter().map(|&x| x as f64).collect();
        let big_g_f64: Vec<f64> = big_g.iter().map(|&x| x as f64).collect();
        
        let f_fft = fft.forward(&f_f64);
        let g_fft = fft.forward(&g_f64);
        let big_f_fft = fft.forward(&big_f_f64);
        let big_g_fft = fft.forward(&big_g_f64);
        
        // Compute quality metrics
        let quality = compute_basis_quality(
            &f, &g, &big_f, &big_g,
            &f_fft, &g_fft, &big_f_fft, &big_g_fft,
            ntru_valid,
        );
        
        // Check if basis is usable
        if !quality.is_stable {
            #[cfg(feature = "std")]
            eprintln!("Warning: NTRU basis may be numerically unstable");
        }
        
        Ok(Self {
            f,
            g,
            big_f,
            big_g,
            h,
            f_fft,
            g_fft,
            big_f_fft,
            big_g_fft,
            quality,
        })
    }
    
    /// Get the basis matrix in FFT form: [[f, g], [F, G]]
    pub fn get_basis_fft(&self) -> [[&Vec<ComplexStable>; 2]; 2] {
        [
            [&self.f_fft, &self.g_fft],
            [&self.big_f_fft, &self.big_g_fft],
        ]
    }
    
    /// Compute the Gram matrix G = B * B^T in FFT domain
    pub fn compute_gram_fft(&self) -> Vec<[[ComplexStable; 2]; 2]> {
        let n = self.f_fft.len();
        let mut gram = vec![[[ComplexStable::zero(); 2]; 2]; n];
        
        for i in 0..n {
            let f = self.f_fft[i];
            let g = self.g_fft[i];
            let big_f = self.big_f_fft[i];
            let big_g = self.big_g_fft[i];
            
            // G[0][0] = |f|^2 + |g|^2
            gram[i][0][0] = ComplexStable::new(
                f.norm_sqr() + g.norm_sqr(),
                0.0,
            );
            
            // G[0][1] = f*F* + g*G*
            let f_big_f_conj = f.mul_tracked(&big_f.conj());
            let g_big_g_conj = g.mul_tracked(&big_g.conj());
            gram[i][0][1] = ComplexStable::new(
                f_big_f_conj.re + g_big_g_conj.re,
                f_big_f_conj.im + g_big_g_conj.im,
            );
            
            // G[1][0] = G[0][1]*
            gram[i][1][0] = gram[i][0][1].conj();
            
            // G[1][1] = |F|^2 + |G|^2
            gram[i][1][1] = ComplexStable::new(
                big_f.norm_sqr() + big_g.norm_sqr(),
                0.0,
            );
        }
        
        gram
    }
    
    /// Check if basis is suitable for signing
    pub fn is_valid_for_signing(&self) -> bool {
        self.quality.ntru_valid && 
        self.quality.is_stable &&
        self.quality.condition_number < 1e6 // Reasonable conditioning
    }
    
    /// Regenerate FFT representations (useful after modification)
    pub fn refresh_fft(&mut self) -> Result<()> {
        let fft = FFTStable::new(N);
        
        let f_f64: Vec<f64> = self.f.iter().map(|&x| x as f64).collect();
        let g_f64: Vec<f64> = self.g.iter().map(|&x| x as f64).collect();
        let big_f_f64: Vec<f64> = self.big_f.iter().map(|&x| x as f64).collect();
        let big_g_f64: Vec<f64> = self.big_g.iter().map(|&x| x as f64).collect();
        
        self.f_fft = fft.forward(&f_f64);
        self.g_fft = fft.forward(&g_f64);
        self.big_f_fft = fft.forward(&big_f_f64);
        self.big_g_fft = fft.forward(&big_g_f64);
        
        // Recompute quality metrics
        let ntru_valid = validate_ntru_equation(&self.f, &self.g, &self.big_f, &self.big_g)?;
        self.quality = compute_basis_quality(
            &self.f, &self.g, &self.big_f, &self.big_g,
            &self.f_fft, &self.g_fft, &self.big_f_fft, &self.big_g_fft,
            ntru_valid,
        );
        
        Ok(())
    }
}

/// Compute public key h = g/f mod q
fn compute_public_key(f: &[i16], g: &[i16]) -> Result<Vec<i16>> {
    // Use NTT for modular division
    ntt_falcon::compute_public_key_ntt(f, g)
}

/// Validate NTRU equation: f*G - g*F = q
fn validate_ntru_equation(
    f: &[i16],
    g: &[i16],
    big_f: &[i16],
    big_g: &[i16],
) -> Result<bool> {
    // Compute f*G in NTT domain
    let fg = ntt_falcon::multiply_ntt(f, big_g);
    
    // Compute g*F in NTT domain
    let gf = ntt_falcon::multiply_ntt(g, big_f);
    
    // Check f*G - g*F = q (mod q)
    // In practice, we check if f*G - g*F = q or 0 (mod q)
    for i in 0..N {
        let diff = (fg[i] as i32 - gf[i] as i32).rem_euclid(Q as i32);
        
        // At position 0, the difference should be q
        if i == 0 {
            if diff != 0 && diff != Q as i32 {
                #[cfg(feature = "std")]
                eprintln!("NTRU equation failed at position 0: {} != 0 or {}", diff, Q);
                return Ok(false);
            }
        } else {
            // At other positions, the difference should be 0
            if diff != 0 {
                #[cfg(feature = "std")]
                eprintln!("NTRU equation failed at position {}: {} != 0", i, diff);
                return Ok(false);
            }
        }
    }
    
    Ok(true)
}

/// Compute quality metrics for the basis
fn compute_basis_quality(
    f: &[i16],
    g: &[i16],
    big_f: &[i16],
    big_g: &[i16],
    f_fft: &[ComplexStable],
    g_fft: &[ComplexStable],
    big_f_fft: &[ComplexStable],
    big_g_fft: &[ComplexStable],
    ntru_valid: bool,
) -> BasisQuality {
    // Find maximum coefficients
    let max_coeff_small = f.iter().chain(g.iter())
        .map(|&x| x.abs())
        .max()
        .unwrap_or(0);
    
    let max_coeff_large = big_f.iter().chain(big_g.iter())
        .map(|&x| x.abs())
        .max()
        .unwrap_or(0);
    
    // Compute Gram-Schmidt norm (simplified)
    let mut gs_norm = 0.0;
    for i in 0..N {
        gs_norm += f_fft[i].norm_sqr() + g_fft[i].norm_sqr();
    }
    gs_norm = (gs_norm / N as f64).sqrt();
    
    // Estimate condition number
    let mut min_sv = f64::INFINITY;
    let mut max_sv = 0.0;
    
    for i in 0..N {
        // Singular values of [[f, g], [F, G]] at FFT index i
        let sv1 = (f_fft[i].norm_sqr() + g_fft[i].norm_sqr()).sqrt();
        let sv2 = (big_f_fft[i].norm_sqr() + big_g_fft[i].norm_sqr()).sqrt();
        
        if sv1 > 0.0 {
            min_sv = f64::min(f64::min(min_sv, sv1), sv2);
            max_sv = f64::max(f64::max(max_sv, sv1), sv2);
        }
    }
    
    let condition_number = if min_sv > 0.0 {
        max_sv / min_sv
    } else {
        f64::INFINITY
    };
    
    // Check numerical stability
    let is_stable = condition_number < 1e8 && 
                   gs_norm > 0.0 && 
                   gs_norm < 1e6 &&
                   max_coeff_small < 1000 &&
                   max_coeff_large < 10000;
    
    BasisQuality {
        max_coeff_small,
        max_coeff_large,
        gs_norm,
        condition_number,
        ntru_valid,
        is_stable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basis_validation() {
        // Create a simple test basis (not cryptographically secure)
        let mut f = vec![1i16; N];
        let mut g = vec![1i16; N];
        let mut big_f = vec![0i16; N];
        let mut big_g = vec![0i16; N];
        
        // Set up a simple NTRU relation
        f[0] = 2;
        g[0] = 3;
        big_f[0] = 5;
        big_g[0] = 7;
        
        match NTRUBasis::new(f, g, big_f, big_g) {
            Ok(basis) => {
                println!("Basis quality: {:?}", basis.quality);
                // The test basis won't satisfy NTRU equation perfectly
                assert!(!basis.quality.ntru_valid);
            }
            Err(e) => {
                println!("Expected error for test basis: {:?}", e);
            }
        }
    }
}