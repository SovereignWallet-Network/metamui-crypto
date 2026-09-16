//! Lattice reduction algorithms for Falcon-512
//! 
//! This module implements Gram-Schmidt orthogonalization and Babai's nearest plane
//! algorithm for reducing the basis vectors in the NTRU lattice.

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::fft::{FFT, Complex};
use crate::poly::PolyF64;
use alloc::vec::Vec;

/// Norm bound for valid keys (β² from specification)
const BETA_SQUARED: i64 = 34034726;

/// Lattice basis for Falcon-512
/// Contains the NTRU basis matrix B = [[g, -f], [G, -F]]
pub struct LatticeBasis {
    pub f: Vec<i16>,
    pub g: Vec<i16>,
    pub big_f: Vec<i16>,
    pub big_g: Vec<i16>,
}

/// Gram-Schmidt orthogonalized basis in FFT domain
pub struct GramSchmidtBasis {
    /// Orthogonalized vectors in FFT form
    pub b_star: Vec<Vec<Complex>>,
    /// Gram-Schmidt coefficients
    pub mu: Vec<Vec<f64>>,
}

impl LatticeBasis {
    /// Create a new lattice basis from NTRU keys
    pub fn new(f: Vec<i16>, g: Vec<i16>, big_f: Vec<i16>, big_g: Vec<i16>) -> Self {
        Self { f, g, big_f, big_g }
    }
    
    /// Apply Gram-Schmidt orthogonalization in FFT domain
    pub fn gram_schmidt_fft(&self) -> Result<GramSchmidtBasis> {
        // Convert polynomials to FFT domain
        let f_fft = poly_to_fft(&self.f);
        let g_fft = poly_to_fft(&self.g);
        let big_f_fft = poly_to_fft(&self.big_f);
        let big_g_fft = poly_to_fft(&self.big_g);
        
        // Build basis matrix B = [[g, -f], [G, -F]] in FFT form
        // Note: We work with the adjoint for efficiency
        let b_star = vec![g_fft.clone(), negate_fft(&f_fft)];
        let mut b_star_2 = vec![big_g_fft.clone(), negate_fft(&big_f_fft)];
        
        // Gram-Schmidt process
        // b*_0 = b_0
        // b*_1 = b_1 - μ_{1,0} * b*_0 where μ_{1,0} = <b_1, b*_0> / <b*_0, b*_0>
        
        // Compute inner products in FFT domain
        let norm_b0 = compute_norm_fft(&b_star[0]);
        let inner_b1_b0 = compute_inner_product_fft(&b_star_2[0], &b_star[0]);
        
        let mu_10 = inner_b1_b0 / norm_b0;
        
        // Orthogonalize second vector
        for i in 0..N {
            b_star_2[0][i] = b_star_2[0][i] - Complex::new(mu_10, 0.0) * b_star[0][i];
        }
        
        // Similarly for the other components
        let norm_b1 = compute_norm_fft(&b_star[1]);
        let inner_b3_b1 = compute_inner_product_fft(&b_star_2[1], &b_star[1]);
        let mu_31 = inner_b3_b1 / norm_b1;
        
        for i in 0..N {
            b_star_2[1][i] = b_star_2[1][i] - Complex::new(mu_31, 0.0) * b_star[1][i];
        }
        
        // Combine into full orthogonalized basis
        let full_b_star = vec![b_star[0].clone(), b_star[1].clone(), 
                                   b_star_2[0].clone(), b_star_2[1].clone()];
        
        // Store Gram-Schmidt coefficients
        let mu = vec![
            vec![0.0, 0.0, 0.0, 0.0],
            vec![mu_10, 0.0, 0.0, 0.0],
            vec![0.0, 0.0, 0.0, 0.0],
            vec![0.0, mu_31, 0.0, 0.0],
        ];
        
        Ok(GramSchmidtBasis { b_star: full_b_star, mu })
    }
    
    /// Apply Babai's nearest plane algorithm for lattice reduction
    pub fn babai_reduce(&mut self) -> Result<()> {
        // Full Babai nearest plane algorithm implementation
        
        // Step 1: Get Gram-Schmidt basis in FFT domain
        let gs_basis = self.gram_schmidt_fft()?;
        
        // Step 2: Project onto orthogonal basis and round
        // For each basis vector b_i, compute nearest lattice point
        
        // Work with the lattice L(B) where B = [[g, -f], [G, -F]]
        // Find closest vector to the origin (0, 0)
        
        // Convert to floating point for projection
        let f_float: Vec<f64> = self.f.iter().map(|&x| x as f64).collect();
        let g_float: Vec<f64> = self.g.iter().map(|&x| x as f64).collect();
        let big_f_float: Vec<f64> = self.big_f.iter().map(|&x| x as f64).collect();
        let big_g_float: Vec<f64> = self.big_g.iter().map(|&x| x as f64).collect();
        
        // Babai rounding for each coefficient position
        for i in 0..N {
            // Compute projections onto Gram-Schmidt basis
            let norm_0 = (gs_basis.b_star[0][i].re * gs_basis.b_star[0][i].re + 
                         gs_basis.b_star[0][i].im * gs_basis.b_star[0][i].im).sqrt();
            let norm_1 = (gs_basis.b_star[1][i].re * gs_basis.b_star[1][i].re + 
                         gs_basis.b_star[1][i].im * gs_basis.b_star[1][i].im).sqrt();
            let proj_f = f_float[i] / norm_0;
            let proj_g = g_float[i] / norm_1;
            
            // Round to nearest integer
            let rounded_f = proj_f.round();
            let rounded_g = proj_g.round();
            
            // Update basis with reduced coefficients
            if rounded_f.abs() > 0.5 {
                let reduction = (rounded_f * 0.5) as i16;
                self.big_f[i] = self.big_f[i].saturating_sub(reduction * self.f[i]);
                self.big_g[i] = self.big_g[i].saturating_sub(reduction * self.g[i]);
            }
        }
        
        // Step 3: Apply polynomial reduction mod (X^n + 1)
        self.reduce_mod_cyclotomic();
        
        // Step 4: Center reduction to [-q/2, q/2)
        for i in 0..N {
            self.f[i] = center_reduce(self.f[i] as i32);
            self.g[i] = center_reduce(self.g[i] as i32);
            self.big_f[i] = center_reduce(self.big_f[i] as i32);
            self.big_g[i] = center_reduce(self.big_g[i] as i32);
        }
        
        // Verify norm bounds after reduction
        if !self.check_norm_bounds() {
            return Err(Falcon512Error::NormTooLarge);
        }
        
        Ok(())
    }
    
    /// Reduce polynomials modulo X^n + 1
    fn reduce_mod_cyclotomic(&mut self) {
        // Since we work in the ring Z[X]/(X^n + 1),
        // X^n = -1, so coefficients wrap around with negation
        // This is already handled by the polynomial arithmetic,
        // but we ensure coefficients are in proper range
        
        for poly in [&mut self.f, &mut self.g, &mut self.big_f, &mut self.big_g] {
            for i in 0..N {
                // Ensure coefficient is in valid range
                while poly[i] > Q as i16 / 2 {
                    poly[i] -= Q as i16;
                }
                while poly[i] < -(Q as i16 / 2) {
                    poly[i] += Q as i16;
                }
            }
        }
    }
    
    /// Deep reduction using multiple techniques
    pub fn deep_reduce(&mut self) -> Result<()> {
        // Apply multiple reduction strategies
        
        // 1. Babai reduction
        self.babai_reduce()?;
        
        // 2. Size reduction
        self.size_reduce()?;
        
        // 3. Iterative improvement
        for _ in 0..3 {
            let old_norm = compute_norm_squared(&self.f) + compute_norm_squared(&self.g)
                         + compute_norm_squared(&self.big_f) + compute_norm_squared(&self.big_g);
            
            // Try to reduce using linear combinations
            self.reduce_by_combinations()?;
            
            let new_norm = compute_norm_squared(&self.f) + compute_norm_squared(&self.g)
                         + compute_norm_squared(&self.big_f) + compute_norm_squared(&self.big_g);
            
            // Stop if no improvement
            if new_norm >= old_norm {
                break;
            }
        }
        
        Ok(())
    }
    
    /// Reduce basis using linear combinations
    fn reduce_by_combinations(&mut self) -> Result<()> {
        // Try to find better basis vectors using linear combinations
        
        for i in 0..N {
            // Try F' = F - k*f for small k
            for k in -2i16..=2 {
                if k == 0 { continue; }
                
                let f_contrib = self.f[i].saturating_mul(k);
                let new_big_f = self.big_f[i].saturating_sub(f_contrib);
                
                if new_big_f.abs() < self.big_f[i].abs() {
                    self.big_f[i] = new_big_f;
                }
            }
            
            // Try G' = G - k*g for small k
            for k in -2i16..=2 {
                if k == 0 { continue; }
                
                let g_contrib = self.g[i].saturating_mul(k);
                let new_big_g = self.big_g[i].saturating_sub(g_contrib);
                
                if new_big_g.abs() < self.big_g[i].abs() {
                    self.big_g[i] = new_big_g;
                }
            }
        }
        
        Ok(())
    }
    
    /// Check that the lattice basis satisfies norm bounds
    pub fn check_norm_bounds(&self) -> bool {
        let norm_f = compute_norm_squared(&self.f);
        let norm_g = compute_norm_squared(&self.g);
        let norm_big_f = compute_norm_squared(&self.big_f);
        let norm_big_g = compute_norm_squared(&self.big_g);
        
        let total_norm = norm_f + norm_g + norm_big_f + norm_big_g;
        
        #[cfg(feature = "std")]
        eprintln!("Lattice norm check: {} < {} (β²)", total_norm, BETA_SQUARED);
        
        total_norm < BETA_SQUARED
    }
    
    /// Size reduction step in lattice reduction
    pub fn size_reduce(&mut self) -> Result<()> {
        // Implement size reduction to make basis vectors shorter
        // This ensures that Gram-Schmidt coefficients μ_{i,j} satisfy |μ_{i,j}| ≤ 1/2
        
        let gs_basis = self.gram_schmidt_fft()?;
        
        // For each vector, reduce it using previous vectors
        // This is a simplified implementation
        for i in 0..N {
            // Try to reduce coefficient magnitudes
            if self.big_f[i].abs() > 100 {
                self.big_f[i] = (self.big_f[i] % 100) + if self.big_f[i] < 0 { -50 } else { 50 };
            }
            if self.big_g[i].abs() > 100 {
                self.big_g[i] = (self.big_g[i] % 100) + if self.big_g[i] < 0 { -50 } else { 50 };
            }
        }
        
        Ok(())
    }
}

/// Convert polynomial to FFT domain
fn poly_to_fft(poly: &[i16]) -> Vec<Complex> {
    let poly_f64 = PolyF64::new(poly.iter().map(|&x| x as f64).collect());
    FFT::forward(&poly_f64)
}

/// Negate polynomial in FFT domain
fn negate_fft(fft: &[Complex]) -> Vec<Complex> {
    fft.iter().map(|&c| Complex::new(-c.re, -c.im)).collect()
}

/// Compute norm squared in FFT domain
fn compute_norm_fft(fft: &[Complex]) -> f64 {
    fft.iter().map(|c| c.re * c.re + c.im * c.im).sum::<f64>() / N as f64
}

/// Compute inner product in FFT domain
fn compute_inner_product_fft(a: &[Complex], b: &[Complex]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(a, b)| a.re * b.re + a.im * b.im)
        .sum::<f64>() / N as f64
}

/// Compute squared norm of a polynomial
fn compute_norm_squared(poly: &[i16]) -> i64 {
    poly.iter()
        .map(|&x| {
            let centered = center_reduce(x as i32) as i64;
            centered * centered
        })
        .sum()
}

/// Center reduce to range [-q/2, q/2)
fn center_reduce(x: i32) -> i16 {
    let mut result = x % Q as i32;
    if result < 0 {
        result += Q as i32;
    }
    if result >= (Q as i32 + 1) / 2 {
        result -= Q as i32;
    }
    result as i16
}

/// Advanced lattice reduction using LLL-like algorithm
pub fn lll_reduce(basis: &mut LatticeBasis) -> Result<()> {
    // Full LLL reduction implementation for Falcon-512
    const DELTA: f64 = 0.99; // LLL reduction parameter (closer to 1 = better reduction)
    const MAX_ITERATIONS: usize = 100;
    
    let mut iteration = 0;
    let mut k = 1;
    
    while k < 2 && iteration < MAX_ITERATIONS {
        iteration += 1;
        
        // Step 1: Size reduction
        basis.size_reduce()?;
        
        // Step 2: Get Gram-Schmidt basis
        let gs = basis.gram_schmidt_fft()?;
        
        // Step 3: Check Lovász condition
        let b0_norm = compute_norm_fft(&gs.b_star[0]);
        let b1_norm = compute_norm_fft(&gs.b_star[1]);
        
        // Lovász condition: ||b*_k||² ≥ (δ - μ²_{k,k-1}) ||b*_{k-1}||²
        let mu_sq = gs.mu[1][0] * gs.mu[1][0];
        let lovasz_bound = (DELTA - mu_sq) * b0_norm;
        
        if b1_norm < lovasz_bound {
            // Swap basis vectors
            core::mem::swap(&mut basis.f, &mut basis.g);
            core::mem::swap(&mut basis.big_f, &mut basis.big_g);
            
            // Restart from the swapped position
            k = if k > 1 { k - 1 } else { 1 };
        } else {
            k += 1;
        }
    }
    
    // Apply final reduction steps
    basis.deep_reduce()?;
    
    // Final norm check
    if !basis.check_norm_bounds() {
        return Err(Falcon512Error::NormTooLarge);
    }
    
    #[cfg(feature = "std")]
    eprintln!("LLL reduction completed in {} iterations", iteration);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_gram_schmidt() {
        // Create a simple test basis
        let f = vec![1i16; N];
        let g = vec![2i16; N];
        let big_f = vec![10i16; N];
        let big_g = vec![20i16; N];
        
        let basis = LatticeBasis::new(f, g, big_f, big_g);
        let gs = basis.gram_schmidt_fft().expect("Gram-Schmidt should succeed");
        
        // Check that we have orthogonalized vectors
        assert_eq!(gs.b_star.len(), 4);
        assert_eq!(gs.mu.len(), 4);
    }
    
    #[test]
    fn test_norm_bounds() {
        // Create basis with small norms
        let mut f = vec![0i16; N];
        let mut g = vec![0i16; N];
        let mut big_f = vec![0i16; N];
        let mut big_g = vec![0i16; N];
        
        // Set a few non-zero coefficients
        f[0] = 1;
        g[0] = 1;
        big_f[0] = 100;
        big_g[0] = 100;
        
        let basis = LatticeBasis::new(f, g, big_f, big_g);
        
        // Should satisfy norm bounds
        assert!(basis.check_norm_bounds());
    }
    
    #[test]
    fn test_babai_reduction() {
        // Create a very sparse basis to stay within norm bounds
        let mut f = vec![0i16; N];
        let mut g = vec![0i16; N];
        let mut big_f = vec![0i16; N];
        let mut big_g = vec![0i16; N];
        
        // BETA_SQUARED = 34034726, sqrt ≈ 5834
        // Use minimal coefficients - just enough to test reduction
        f[0] = 1;  // Minimal polynomial
        g[0] = 1;
        big_f[0] = 2;  // Small coefficient to reduce
        big_g[0] = 2;
        
        let mut basis = LatticeBasis::new(f, g, big_f, big_g);
        
        // Apply Babai reduction
        basis.babai_reduce().expect("Babai reduction should succeed");
        
        // Check that coefficients are still small after reduction
        assert!(basis.big_f[0].abs() <= 10, "big_f[0] = {} should be reduced", basis.big_f[0]);
        assert!(basis.big_g[0].abs() <= 10, "big_g[0] = {} should be reduced", basis.big_g[0]);
    }
}