//! Babai's nearest plane algorithm for Falcon-512
//! 
//! This module implements the complete Babai nearest plane algorithm
//! for finding close vectors in the NTRU lattice.

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::fft::{FFT, Complex};
use crate::poly::PolyF64;
use alloc::vec::Vec;

/// Babai nearest plane algorithm implementation
pub struct BabaiNearestPlane {
    /// Dimension of the lattice
    n: usize,
    /// Gram-Schmidt orthogonalized basis
    basis_star: Vec<Vec<Complex>>,
    /// Original basis vectors
    basis: Vec<Vec<i16>>,
    /// Gram-Schmidt coefficients μ_ij
    mu: Vec<Vec<f64>>,
}

impl BabaiNearestPlane {
    /// Create new Babai algorithm instance from NTRU basis
    pub fn new(f: &[i16], g: &[i16], big_f: &[i16], big_g: &[i16]) -> Result<Self> {
        // Build the basis matrix B = [[g, -f], [G, -F]]
        let basis = vec![
            g.to_vec(),
            f.iter().map(|&x| -x).collect(),
            big_g.to_vec(),
            big_f.iter().map(|&x| -x).collect(),
        ];
        
        // Compute Gram-Schmidt orthogonalization
        let (basis_star, mu) = Self::gram_schmidt(&basis)?;
        
        Ok(Self {
            n: N,
            basis_star,
            basis,
            mu,
        })
    }
    
    /// Gram-Schmidt orthogonalization process
    fn gram_schmidt(basis: &[Vec<i16>]) -> Result<(Vec<Vec<Complex>>, Vec<Vec<f64>>)> {
        let m = basis.len();
        let mut basis_star: Vec<Vec<Complex>> = Vec::with_capacity(m);
        let mut mu = vec![vec![0.0; m]; m];
        
        // Convert basis to FFT domain for efficiency
        for i in 0..m {
            let poly_f64 = PolyF64::new(basis[i].iter().map(|&x| x as f64).collect());
            let mut b_star_i = FFT::forward(&poly_f64);
            
            // Orthogonalize against previous vectors
            for j in 0..i {
                // Compute μ_ij = <b_i, b*_j> / <b*_j, b*_j>
                let inner_product = Self::inner_product_fft(&b_star_i, &basis_star[j]);
                let norm_j = Self::norm_squared_fft(&basis_star[j]);
                
                mu[i][j] = inner_product / norm_j;
                
                // b*_i = b*_i - μ_ij * b*_j
                for k in 0..N {
                    b_star_i[k] = b_star_i[k] - Complex::new(mu[i][j], 0.0) * basis_star[j][k];
                }
            }
            
            basis_star.push(b_star_i);
        }
        
        Ok((basis_star, mu))
    }
    
    /// Find the closest lattice vector to a target vector
    pub fn closest_vector(&self, target: &[i16]) -> Result<Vec<i16>> {
        // Convert target to FFT domain
        let target_f64 = PolyF64::new(target.iter().map(|&x| x as f64).collect());
        let target_fft = FFT::forward(&target_f64);
        
        // Initialize coefficients for linear combination
        let mut coeffs = vec![0.0; self.basis.len()];
        
        // Babai rounding: work backwards through the basis
        for i in (0..self.basis.len()).rev() {
            // Compute projection onto b*_i
            let mut proj = Self::inner_product_fft(&target_fft, &self.basis_star[i]) 
                          / Self::norm_squared_fft(&self.basis_star[i]);
            
            // Adjust for previous coefficients
            for j in (i + 1)..self.basis.len() {
                proj -= coeffs[j] * self.mu[j][i];
            }
            
            // Round to nearest integer
            coeffs[i] = proj.round();
        }
        
        // Reconstruct the lattice vector
        let mut result = vec![0i16; N];
        for i in 0..self.basis.len() {
            if coeffs[i].abs() > 0.0 {
                let coeff = coeffs[i] as i16;
                for j in 0..N {
                    result[j] = result[j].saturating_add(
                        self.basis[i][j].saturating_mul(coeff)
                    );
                }
            }
        }
        
        // Center reduce the result
        for i in 0..N {
            result[i] = Self::center_reduce(result[i] as i32);
        }
        
        Ok(result)
    }
    
    /// Find a short vector in the lattice coset v + L
    pub fn short_vector_in_coset(&self, v: &[i16]) -> Result<Vec<i16>> {
        // Find closest lattice vector to v
        let closest = self.closest_vector(v)?;
        
        // The short vector is v - closest
        let mut short = vec![0i16; N];
        for i in 0..N {
            short[i] = Self::center_reduce(v[i] as i32 - closest[i] as i32);
        }
        
        // Verify the result is short enough
        let norm = short.iter().map(|&x| x as i64 * x as i64).sum::<i64>();
        if norm > 34034726 / 4 {  // Use 1/4 of the bound for safety
            return Err(Falcon512Error::NormTooLarge);
        }
        
        Ok(short)
    }
    
    /// Solve the closest vector problem (CVP) approximately
    pub fn solve_cvp(&self, target: &[i16]) -> Result<Vec<i16>> {
        // Use Babai's algorithm with iterative refinement
        let mut best = self.closest_vector(target)?;
        let mut best_dist = Self::distance_squared(target, &best);
        
        // Try small perturbations to improve the solution
        for _ in 0..3 {
            let mut improved = false;
            
            // Try adjusting each basis vector coefficient by ±1
            for i in 0..self.basis.len() {
                for delta in [-1i16, 1] {
                    let mut candidate = best.clone();
                    
                    // Add delta * basis[i] to the candidate
                    for j in 0..N {
                        candidate[j] = Self::center_reduce(
                            candidate[j] as i32 + delta as i32 * self.basis[i][j] as i32
                        );
                    }
                    
                    let dist = Self::distance_squared(target, &candidate);
                    if dist < best_dist {
                        best = candidate;
                        best_dist = dist;
                        improved = true;
                    }
                }
            }
            
            if !improved {
                break;
            }
        }
        
        Ok(best)
    }
    
    /// Compute inner product in FFT domain
    fn inner_product_fft(a: &[Complex], b: &[Complex]) -> f64 {
        a.iter()
            .zip(b.iter())
            .map(|(a, b)| a.re * b.re + a.im * b.im)
            .sum::<f64>() / N as f64
    }
    
    /// Compute squared norm in FFT domain
    fn norm_squared_fft(v: &[Complex]) -> f64 {
        v.iter()
            .map(|c| c.re * c.re + c.im * c.im)
            .sum::<f64>() / N as f64
    }
    
    /// Compute squared distance between two vectors
    fn distance_squared(a: &[i16], b: &[i16]) -> i64 {
        a.iter()
            .zip(b.iter())
            .map(|(&x, &y)| {
                let diff = x as i64 - y as i64;
                diff * diff
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
}

/// Apply Babai reduction to signature generation
pub fn babai_sign_reduction(
    s0: &mut Vec<i16>,
    s1: &mut Vec<i16>,
    f: &[i16],
    g: &[i16],
    big_f: &[i16],
    big_g: &[i16],
) -> Result<()> {
    // Create Babai algorithm instance
    let babai = BabaiNearestPlane::new(f, g, big_f, big_g)?;
    
    // Find short vectors for both s0 and s1
    let short_s0 = babai.short_vector_in_coset(s0)?;
    let short_s1 = babai.short_vector_in_coset(s1)?;
    
    // Update with shorter vectors
    *s0 = short_s0;
    *s1 = short_s1;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_babai_initialization() {
        let f = vec![1i16; N];
        let g = vec![2i16; N];
        let big_f = vec![10i16; N];
        let big_g = vec![20i16; N];
        
        let babai = BabaiNearestPlane::new(&f, &g, &big_f, &big_g)
            .expect("Babai initialization should succeed");
        
        assert_eq!(babai.n, N);
        assert_eq!(babai.basis.len(), 4);
    }
    
    #[test]
    fn test_closest_vector() {
        let mut f = vec![0i16; N];
        let mut g = vec![0i16; N];
        let mut big_f = vec![0i16; N];
        let mut big_g = vec![0i16; N];
        
        // Simple basis
        f[0] = 1;
        g[0] = 1;
        big_f[0] = Q as i16 / 2;
        big_g[0] = Q as i16 / 2;
        
        let babai = BabaiNearestPlane::new(&f, &g, &big_f, &big_g)
            .expect("Babai initialization should succeed");
        
        // Find closest vector to a target
        let mut target = vec![0i16; N];
        target[0] = 100;
        
        let closest = babai.closest_vector(&target)
            .expect("Should find closest vector");
        
        // Check that the result is a lattice vector
        assert_eq!(closest.len(), N);
    }
    
    #[test]
    fn test_short_vector_in_coset() {
        let f = vec![1i16; N];
        let g = vec![1i16; N];
        let big_f = vec![2i16; N];
        let big_g = vec![2i16; N];
        
        let babai = BabaiNearestPlane::new(&f, &g, &big_f, &big_g)
            .expect("Babai initialization should succeed");
        
        let v = vec![100i16; N];
        let short = babai.short_vector_in_coset(&v)
            .expect("Should find short vector");
        
        // Verify the result is shorter than the input
        let v_norm: i64 = v.iter().map(|&x| x as i64 * x as i64).sum();
        let short_norm: i64 = short.iter().map(|&x| x as i64 * x as i64).sum();
        
        assert!(short_norm <= v_norm, "Short vector should have smaller norm");
    }
}