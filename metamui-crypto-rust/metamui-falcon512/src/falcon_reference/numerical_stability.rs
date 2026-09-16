//! Numerical stability improvements for FFT-based sampling
//! 
//! Addresses precision issues when working in FFT domain

use crate::fft::FFTComplex;
use alloc::vec::Vec;

/// Stabilize FFT coefficients to prevent numerical drift
pub fn stabilize_fft_coefficients(coeffs: &mut [FFTComplex]) {
    for c in coeffs.iter_mut() {
        // Clamp very small values to zero to prevent accumulation of errors
        if c.re.abs() < 1e-12 {
            c.re = 0.0;
        }
        if c.im.abs() < 1e-12 {
            c.im = 0.0;
        }
        
        // Prevent NaN or Inf
        if !c.re.is_finite() {
            c.re = 0.0;
        }
        if !c.im.is_finite() {
            c.im = 0.0;
        }
    }
}

/// Apply numerical damping to reduce oscillations
pub fn apply_damping(coeffs: &mut [FFTComplex], damping_factor: f64) {
    for c in coeffs.iter_mut() {
        c.re *= damping_factor;
        c.im *= damping_factor;
    }
}

/// Check if Gram matrix is well-conditioned
pub fn check_gram_matrix_conditioning(g: &[[Vec<FFTComplex>; 2]; 2]) -> bool {
    // Check diagonal dominance
    for i in 0..g[0][0].len() {
        let diag_sum = g[0][0][i].norm_sqr() + g[1][1][i].norm_sqr();
        let off_diag = g[0][1][i].norm_sqr() + g[1][0][i].norm_sqr();
        
        // Matrix should be diagonally dominant
        if diag_sum < 2.0 * off_diag {
            return false;
        }
        
        // Check for near-zero diagonal elements
        if g[0][0][i].norm_sqr() < 1e-10 || g[1][1][i].norm_sqr() < 1e-10 {
            return false;
        }
    }
    
    true
}

/// Regularize Gram matrix to improve conditioning
pub fn regularize_gram_matrix(g: &mut [[Vec<FFTComplex>; 2]; 2], epsilon: f64) {
    let n = g[0][0].len();
    
    // Add small positive value to diagonal for regularization
    for i in 0..n {
        g[0][0][i].re += epsilon;
        g[1][1][i].re += epsilon;
    }
}

/// Adaptive sigma selection based on numerical stability
pub fn compute_adaptive_sigma(basis_norm: f64, target_norm: f64) -> f64 {
    // Adjust sigma based on the ratio of basis norm to target norm
    let base_sigma = 165.7;
    let norm_ratio = basis_norm / target_norm;
    
    if norm_ratio > 100.0 {
        // Very poor conditioning, use larger sigma
        base_sigma * 1.5
    } else if norm_ratio > 10.0 {
        // Poor conditioning, slightly increase sigma
        base_sigma * 1.2
    } else {
        // Good conditioning, use standard sigma
        base_sigma
    }
}

/// Check if FFT basis is numerically stable
pub fn check_basis_stability(b_fft: &[[Vec<FFTComplex>; 2]; 2]) -> bool {
    for i in 0..2 {
        for j in 0..2 {
            for k in 0..b_fft[i][j].len() {
                let c = &b_fft[i][j][k];
                
                // Check for NaN or Inf
                if !c.re.is_finite() || !c.im.is_finite() {
                    return false;
                }
                
                // Check for extremely large values that indicate instability
                if c.norm_sqr() > 1e10 {
                    return false;
                }
            }
        }
    }
    
    true
}

/// Round FFT coefficients to reduce precision errors
pub fn round_fft_coefficients(coeffs: &mut [FFTComplex], precision: f64) {
    for c in coeffs.iter_mut() {
        c.re = (c.re / precision).round() * precision;
        c.im = (c.im / precision).round() * precision;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stabilize_coefficients() {
        let mut coeffs = vec![
            FFTComplex::new(1e-15, 1e-14),
            FFTComplex::new(1.0, 2.0),
            FFTComplex::new(f64::NAN, f64::INFINITY),
        ];
        
        stabilize_fft_coefficients(&mut coeffs);
        
        assert_eq!(coeffs[0].re, 0.0);
        assert_eq!(coeffs[0].im, 0.0);
        assert_eq!(coeffs[1].re, 1.0);
        assert_eq!(coeffs[1].im, 2.0);
        assert_eq!(coeffs[2].re, 0.0);
        assert_eq!(coeffs[2].im, 0.0);
    }
    
    #[test]
    fn test_gram_matrix_conditioning() {
        // Well-conditioned matrix (identity-like)
        let g_good = [
            [vec![FFTComplex::new(1.0, 0.0)], vec![FFTComplex::new(0.1, 0.0)]],
            [vec![FFTComplex::new(0.1, 0.0)], vec![FFTComplex::new(1.0, 0.0)]],
        ];
        
        assert!(check_gram_matrix_conditioning(&g_good));
        
        // Poorly conditioned matrix
        let g_bad = [
            [vec![FFTComplex::new(0.0001, 0.0)], vec![FFTComplex::new(1.0, 0.0)]],
            [vec![FFTComplex::new(1.0, 0.0)], vec![FFTComplex::new(0.0001, 0.0)]],
        ];
        
        assert!(!check_gram_matrix_conditioning(&g_bad));
    }
}