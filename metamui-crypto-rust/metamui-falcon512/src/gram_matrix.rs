//! Gram matrix computation and conditioning for Falcon-512
//! 
//! This module provides numerically stable computation of Gram matrices
//! with conditioning analysis and regularization.

use crate::fft_stable::ComplexStable;
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;

/// Gram matrix in FFT domain with conditioning information
pub struct GramMatrixFFT {
    /// The Gram matrix G = B * B^T at each FFT index
    /// Indexed as matrix[fft_index][row][col]
    pub matrix: Vec<[[ComplexStable; 2]; 2]>,
    /// Condition number at each FFT index
    pub condition_numbers: Vec<f64>,
    /// Overall condition estimate
    pub overall_condition: f64,
    /// Whether regularization was applied
    pub regularized: bool,
}

impl GramMatrixFFT {
    /// Compute Gram matrix from basis in FFT domain
    pub fn from_basis_fft(
        f_fft: &[ComplexStable],
        g_fft: &[ComplexStable],
        big_f_fft: &[ComplexStable],
        big_g_fft: &[ComplexStable],
    ) -> Result<Self> {
        let n = f_fft.len();
        if g_fft.len() != n || big_f_fft.len() != n || big_g_fft.len() != n {
            return Err(Falcon512Error::InvalidParameter);
        }
        
        let mut matrix = vec![[[ComplexStable::zero(); 2]; 2]; n];
        let mut condition_numbers = vec![0.0; n];
        
        // Compute G = B * B^T at each FFT index
        for i in 0..n {
            let f = f_fft[i];
            let g = g_fft[i];
            let big_f = big_f_fft[i];
            let big_g = big_g_fft[i];
            
            // G[0][0] = |f|^2 + |g|^2
            matrix[i][0][0] = ComplexStable::new(
                f.norm_sqr() + g.norm_sqr(),
                0.0,
            );
            
            // G[0][1] = f*F* + g*G*
            let f_big_f_conj = f.mul_tracked(&big_f.conj());
            let g_big_g_conj = g.mul_tracked(&big_g.conj());
            matrix[i][0][1] = ComplexStable {
                re: f_big_f_conj.re + g_big_g_conj.re,
                im: f_big_f_conj.im + g_big_g_conj.im,
                precision_bits: f_big_f_conj.precision_bits.min(g_big_g_conj.precision_bits),
            };
            
            // G[1][0] = G[0][1]* (Hermitian matrix)
            matrix[i][1][0] = matrix[i][0][1].conj();
            
            // G[1][1] = |F|^2 + |G|^2
            matrix[i][1][1] = ComplexStable::new(
                big_f.norm_sqr() + big_g.norm_sqr(),
                0.0,
            );
            
            // Compute condition number for this 2x2 matrix
            condition_numbers[i] = compute_2x2_condition(&matrix[i]);
        }
        
        // Compute overall condition estimate
        let overall_condition = condition_numbers.iter()
            .copied()
            .fold(0.0, f64::max);
        
        Ok(Self {
            matrix,
            condition_numbers,
            overall_condition,
            regularized: false,
        })
    }
    
    /// Apply Tikhonov regularization to improve conditioning
    pub fn regularize(&mut self, epsilon: f64) {
        for i in 0..self.matrix.len() {
            // Add epsilon to diagonal elements
            self.matrix[i][0][0].re += epsilon;
            self.matrix[i][1][1].re += epsilon;
            
            // Recompute condition number
            self.condition_numbers[i] = compute_2x2_condition(&self.matrix[i]);
        }
        
        // Update overall condition
        self.overall_condition = self.condition_numbers.iter()
            .copied()
            .fold(0.0, f64::max);
        
        self.regularized = true;
        
        #[cfg(feature = "std")]
        eprintln!("Gram matrix regularized with epsilon={}, new condition number: {}", 
                 epsilon, self.overall_condition);
    }
    
    /// Check if the Gram matrix is well-conditioned
    pub fn is_well_conditioned(&self) -> bool {
        self.overall_condition < 1e6 && 
        self.condition_numbers.iter().all(|&c| c < 1e7)
    }
    
    /// Get LDL decomposition at FFT index
    pub fn get_ldl_at(&self, index: usize) -> Result<LDLDecomposition> {
        if index >= self.matrix.len() {
            return Err(Falcon512Error::InvalidParameter);
        }
        
        let g = &self.matrix[index];
        
        // LDL decomposition of 2x2 Hermitian matrix
        // G = L * D * L^H where L is lower triangular with 1s on diagonal
        
        // D[0][0] = G[0][0]
        let d00 = g[0][0].re;
        
        if d00 <= 0.0 {
            #[cfg(feature = "std")]
            eprintln!("Warning: Non-positive diagonal element in Gram matrix at index {}", index);
            return Err(Falcon512Error::InvalidBasis);
        }
        
        // L[1][0] = G[1][0] / D[0][0]
        let l10 = ComplexStable {
            re: g[1][0].re / d00,
            im: g[1][0].im / d00,
            precision_bits: g[1][0].precision_bits.saturating_sub(1),
        };
        
        // D[1][1] = G[1][1] - L[1][0] * D[0][0] * L[1][0]*
        let l10_norm_sqr = l10.norm_sqr();
        let d11 = g[1][1].re - l10_norm_sqr * d00;
        
        if d11 <= 0.0 {
            #[cfg(feature = "std")]
            eprintln!("Warning: Non-positive Schur complement in Gram matrix at index {}", index);
            return Err(Falcon512Error::InvalidBasis);
        }
        
        Ok(LDLDecomposition {
            d00,
            d11,
            l10,
            condition: (d00.max(d11)) / (d00.min(d11)),
        })
    }
    
    /// Apply spectral normalization to control eigenvalues
    pub fn spectral_normalize(&mut self, max_eigenvalue: f64) {
        for i in 0..self.matrix.len() {
            let g = &self.matrix[i];
            
            // Compute eigenvalues of 2x2 matrix
            let trace = g[0][0].re + g[1][1].re;
            let det = g[0][0].re * g[1][1].re - g[0][1].norm_sqr();
            
            // Eigenvalues are roots of: λ^2 - trace*λ + det = 0
            let discriminant = trace * trace - 4.0 * det;
            if discriminant >= 0.0 {
                let sqrt_disc = discriminant.sqrt();
                let lambda1 = (trace + sqrt_disc) / 2.0;
                let lambda2 = (trace - sqrt_disc) / 2.0;
                
                let max_lambda = f64::max(lambda1, lambda2);
                
                if max_lambda > max_eigenvalue {
                    // Scale matrix to reduce largest eigenvalue
                    let scale = max_eigenvalue / max_lambda;
                    self.matrix[i][0][0].re *= scale;
                    self.matrix[i][0][1].re *= scale;
                    self.matrix[i][0][1].im *= scale;
                    self.matrix[i][1][0].re *= scale;
                    self.matrix[i][1][0].im *= scale;
                    self.matrix[i][1][1].re *= scale;
                }
            }
        }
    }
}

/// LDL decomposition of a 2x2 Hermitian matrix
pub struct LDLDecomposition {
    /// Diagonal element D[0][0]
    pub d00: f64,
    /// Diagonal element D[1][1]
    pub d11: f64,
    /// Off-diagonal element L[1][0]
    pub l10: ComplexStable,
    /// Condition number of this decomposition
    pub condition: f64,
}

/// Compute condition number of a 2x2 Hermitian matrix
fn compute_2x2_condition(g: &[[ComplexStable; 2]; 2]) -> f64 {
    // For 2x2 Hermitian matrix, eigenvalues can be computed exactly
    let a = g[0][0].re;
    let b_norm_sqr = g[0][1].norm_sqr();
    let c = g[1][1].re;
    
    // Eigenvalues of [[a, b], [b*, c]]
    let trace = a + c;
    let det = a * c - b_norm_sqr;
    
    if det <= 0.0 {
        // Matrix is not positive definite
        return f64::INFINITY;
    }
    
    let discriminant = trace * trace - 4.0 * det;
    if discriminant < 0.0 {
        // Should not happen for Hermitian matrix
        return f64::INFINITY;
    }
    
    let sqrt_disc = discriminant.sqrt();
    let lambda_max = (trace + sqrt_disc) / 2.0;
    let lambda_min = (trace - sqrt_disc) / 2.0;
    
    if lambda_min <= 0.0 {
        return f64::INFINITY;
    }
    
    lambda_max / lambda_min
}

/// Adaptive regularization based on condition number
pub fn adaptive_regularization(gram: &mut GramMatrixFFT) -> Result<()> {
    let mut epsilon = 1e-12;
    let max_iterations = 10;
    let target_condition = 1e6;
    
    for iteration in 0..max_iterations {
        if gram.overall_condition < target_condition {
            #[cfg(feature = "std")]
            eprintln!("Gram matrix conditioning acceptable after {} iterations", iteration);
            return Ok(());
        }
        
        // Apply regularization
        gram.regularize(epsilon);
        
        // Increase epsilon for next iteration
        epsilon *= 10.0;
    }
    
    if gram.overall_condition > target_condition {
        #[cfg(feature = "std")]
        eprintln!("Warning: Could not achieve target conditioning (current: {})", 
                 gram.overall_condition);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fft_stable::FFTStable;

    #[test]
    fn test_gram_matrix_computation() {
        let n = 8;
        let fft = FFTStable::new(n);

        // Use orthogonal constant polynomials to ensure positive-definite Gram matrix.
        // B = [[g, -f], [G, -F]] must have linearly independent rows at each FFT index.
        // Constant polynomials have identical FFT values at all indices, ensuring
        // the 2×2 Gram matrix is well-conditioned everywhere.
        let f = vec![3.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        let g = vec![1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        let big_f = vec![1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        let big_g = vec![3.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];

        let f_fft = fft.forward(&f);
        let g_fft = fft.forward(&g);
        let big_f_fft = fft.forward(&big_f);
        let big_g_fft = fft.forward(&big_g);

        let gram = GramMatrixFFT::from_basis_fft(&f_fft, &g_fft, &big_f_fft, &big_g_fft)
            .expect("Failed to compute Gram matrix");

        println!("Overall condition number: {}", gram.overall_condition);
        assert!(gram.overall_condition < f64::INFINITY);
    }

    #[test]
    fn test_regularization() {
        let n = 8;
        let fft = FFTStable::new(n);

        // Create a poorly-conditioned but positive-definite basis.
        // Use orthogonal directions: f large, g small, F in "g direction", G in "f direction".
        // This gives g01 ≈ 0 (cross-terms cancel) but large ratio g11/g00.
        //   g00 = 100² + 1² = 10001, g01 = 100*0 + 1*0 = 0, g11 = 0² + 100² + 0² + 1² ≈ 10001
        // Use non-proportional directions to avoid det=0.
        let f = vec![100.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        let g = vec![1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        let big_f = vec![0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];  // non-constant → different FFT
        let big_g = vec![0.0, 100.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];

        let f_fft = fft.forward(&f);
        let g_fft = fft.forward(&g);
        let big_f_fft = fft.forward(&big_f);
        let big_g_fft = fft.forward(&big_g);

        let mut gram = GramMatrixFFT::from_basis_fft(&f_fft, &g_fft, &big_f_fft, &big_g_fft)
            .expect("Failed to compute Gram matrix");

        let original_condition = gram.overall_condition;
        println!("Condition before regularization: {}", original_condition);
        assert!(original_condition < f64::INFINITY, "Basis must be positive-definite");

        gram.regularize(1e-6);

        println!("Condition after regularization: {}", gram.overall_condition);
        assert!(gram.overall_condition <= original_condition);
        assert!(gram.regularized);
    }
}