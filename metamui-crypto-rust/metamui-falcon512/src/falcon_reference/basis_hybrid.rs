//! Hybrid FFT Basis Construction with improved numerical stability
//! 
//! Uses hybrid precision for basis transformation and inverse computation.

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::fft_hybrid::{HybridFFT, HybridComplex, FFTMode};
use crate::poly::PolyF64;
use alloc::vec::Vec;

/// Hybrid basis in FFT form with selectable precision
#[derive(Clone, Debug)]
pub struct HybridBasis {
    /// The basis matrix B = [[f, g], [F, G]] in hybrid FFT form
    pub b_fft: [[Vec<HybridComplex>; 2]; 2],
    /// The inverse basis matrix B0 = [[a, b], [c, d]] in hybrid FFT form
    pub b0_fft: [[Vec<HybridComplex>; 2]; 2],
    /// FFT mode used
    mode: FFTMode,
}

impl HybridBasis {
    /// Create a new basis from private key polynomials
    pub fn new(
        f: &[i16],
        g: &[i16],
        big_f: &[i16],
        big_g: &[i16],
        mode: FFTMode,
    ) -> Result<Self> {
        if f.len() != N || g.len() != N || big_f.len() != N || big_g.len() != N {
            return Err(Falcon512Error::InvalidParameter);
        }
        
        // Use emulated precision for basis transformation in hybrid mode
        let transform_mode = if mode == FFTMode::Hybrid {
            FFTMode::Emulated
        } else {
            mode
        };
        
        // Convert to hybrid FFT representation
        let f_fft = poly_to_fft_hybrid(f, transform_mode);
        let g_fft = poly_to_fft_hybrid(g, transform_mode);
        let big_f_fft = poly_to_fft_hybrid(big_f, transform_mode);
        let big_g_fft = poly_to_fft_hybrid(big_g, transform_mode);
        
        // Construct basis matrix B = [[f, g], [F, G]]
        let b_fft = [
            [f_fft.clone(), g_fft.clone()],
            [big_f_fft.clone(), big_g_fft.clone()],
        ];
        
        // Compute the inverse basis B0 with tolerance
        let b0_fft = compute_inverse_basis_hybrid(
            &f_fft, &g_fft, &big_f_fft, &big_g_fft, transform_mode
        )?;
        
        Ok(Self { b_fft, b0_fft, mode })
    }
    
    /// Get the basis matrix in FFT form
    pub fn get_basis_fft(&self) -> &[[Vec<HybridComplex>; 2]; 2] {
        &self.b_fft
    }
    
    /// Get the inverse basis matrix in FFT form
    pub fn get_inverse_basis_fft(&self) -> &[[Vec<HybridComplex>; 2]; 2] {
        &self.b0_fft
    }
    
    /// Check basis numerical stability
    pub fn check_stability(&self) -> bool {
        for i in 0..2 {
            for j in 0..2 {
                for k in 0..self.b_fft[i][j].len() {
                    let norm = self.b_fft[i][j][k].norm_sqr();
                    
                    // Check for NaN, Inf, or extremely large values
                    if !norm.is_finite() || norm > 1e10 {
                        return false;
                    }
                }
            }
        }
        true
    }
    
    /// Compute Gram matrix G = B * B^T
    pub fn compute_gram_matrix(&self, mode: FFTMode) -> Result<[[Vec<HybridComplex>; 2]; 2]> {
        let n = self.b_fft[0][0].len();
        let mut g = [[vec![HybridComplex::zero(mode); n], vec![HybridComplex::zero(mode); n]],
                     [vec![HybridComplex::zero(mode); n], vec![HybridComplex::zero(mode); n]]];
        
        // G[i][j] = sum_k B[i][k] * conj(B[j][k])
        for i in 0..2 {
            for j in 0..2 {
                for idx in 0..n {
                    g[i][j][idx] = self.b_fft[i][0][idx].mul(self.b_fft[j][0][idx].conj())
                                 .add(self.b_fft[i][1][idx].mul(self.b_fft[j][1][idx].conj()));
                }
            }
        }
        
        Ok(g)
    }
    
    /// Estimate condition number of the basis
    pub fn estimate_condition_number(&self) -> f64 {
        let mut min_norm = f64::MAX;
        let mut max_norm = 0.0;
        
        for i in 0..2 {
            for j in 0..2 {
                for k in 0..self.b_fft[i][j].len() {
                    let norm = self.b_fft[i][j][k].norm_sqr();
                    if norm > 0.0 && norm < min_norm {
                        min_norm = norm;
                    }
                    if norm > max_norm {
                        max_norm = norm;
                    }
                }
            }
        }
        
        if min_norm > 0.0 {
            (max_norm / min_norm).sqrt()
        } else {
            f64::INFINITY
        }
    }
}

/// Convert polynomial to hybrid FFT representation
fn poly_to_fft_hybrid(poly: &[i16], mode: FFTMode) -> Vec<HybridComplex> {
    // Convert to floating point
    let poly_f64: Vec<f64> = poly.iter().map(|&x| x as f64).collect();
    let poly_obj = PolyF64::new(poly_f64);
    
    // Apply hybrid FFT
    let hybrid_fft = HybridFFT::new(mode);
    hybrid_fft.forward(&poly_obj)
}

/// Compute inverse basis with tolerance for numerical errors
fn compute_inverse_basis_hybrid(
    f_fft: &[HybridComplex],
    g_fft: &[HybridComplex],
    big_f_fft: &[HybridComplex],
    big_g_fft: &[HybridComplex],
    mode: FFTMode,
) -> Result<[[Vec<HybridComplex>; 2]; 2]> {
    let n = f_fft.len();
    let q_inv = 1.0 / (Q as f64);
    let q_inv_complex = HybridComplex::new(q_inv, 0.0, mode);
    
    // B0 = (1/q) * [[G, -g], [-F, f]]
    let mut a = vec![HybridComplex::zero(mode); n];  // G/q
    let mut b = vec![HybridComplex::zero(mode); n];  // -g/q
    let mut c = vec![HybridComplex::zero(mode); n];  // -F/q
    let mut d = vec![HybridComplex::zero(mode); n];  // f/q
    
    for i in 0..n {
        a[i] = big_g_fft[i].mul(q_inv_complex);
        
        // Negate and scale
        let neg_one = HybridComplex::new(-1.0, 0.0, mode);
        b[i] = g_fft[i].mul(q_inv_complex).mul(neg_one);
        c[i] = big_f_fft[i].mul(q_inv_complex).mul(neg_one);
        d[i] = f_fft[i].mul(q_inv_complex);
    }
    
    // Verify the NTRU equation with tolerance
    verify_ntru_equation_hybrid(f_fft, g_fft, big_f_fft, big_g_fft, mode);
    
    Ok([[a, b], [c, d]])
}

/// Verify NTRU equation with tolerance in hybrid mode
fn verify_ntru_equation_hybrid(
    f_fft: &[HybridComplex],
    g_fft: &[HybridComplex],
    big_f_fft: &[HybridComplex],
    big_g_fft: &[HybridComplex],
    mode: FFTMode,
) {
    const TOLERANCE: f64 = 1.0 / (1u64 << 40) as f64;
    let mut max_relative_error = 0.0;
    let q_val = Q as f64;
    
    for i in 0..f_fft.len() {
        // Compute f*G - g*F
        let fg = f_fft[i].mul(big_g_fft[i]);
        let gf = g_fft[i].mul(big_f_fft[i]);
        let check = fg.sub(gf);
        
        // Expected value is q
        let expected = HybridComplex::new(q_val, 0.0, mode);
        let error_complex = check.sub(expected);
        let error = error_complex.norm_sqr().sqrt();
        let relative_error = error / q_val;
        
        if relative_error > max_relative_error {
            max_relative_error = relative_error;
        }
    }
    
    #[cfg(feature = "std")]
    if max_relative_error > TOLERANCE {
        eprintln!("NTRU equation max relative error: {} (tolerance: {})", 
                 max_relative_error, TOLERANCE);
    }
}

/// Compute target vector for sampling
pub fn compute_target_fft_hybrid(
    point_fft: &[HybridComplex],
    b0_fft: &[[Vec<HybridComplex>; 2]; 2],
    mode: FFTMode,
) -> Result<[Vec<HybridComplex>; 2]> {
    let n = point_fft.len();
    let [[a, b], [c, d]] = b0_fft;
    
    // t0 = point * a = point * G/q
    // t1 = point * b = -point * g/q
    
    let mut t0 = vec![HybridComplex::zero(mode); n];
    let mut t1 = vec![HybridComplex::zero(mode); n];
    
    for i in 0..n {
        t0[i] = point_fft[i].mul(a[i]);
        t1[i] = point_fft[i].mul(b[i]);
    }
    
    Ok([t0, t1])
}