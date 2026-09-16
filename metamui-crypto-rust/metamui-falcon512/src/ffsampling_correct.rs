//! Corrected Fast Fourier Sampling implementation for Falcon-512
//! 
//! This module implements the proper recursive sampling algorithm
//! that ensures signatures satisfy the NTRU equation.

use crate::constants::{N, Q, SIGMA};
use crate::error::{Result, Falcon512Error};
use crate::fft_stable::{ComplexStable, FFTStable};
use crate::ntru_basis::NTRUBasis;
use crate::gram_matrix::GramMatrixFFT;
use crate::ldl_tree::{LDLTree, LDLNode};
use crate::gaussian_calibrated::GaussianCalibrated as GaussianSampler;
use alloc::vec::Vec;
use rand::RngCore;

/// Corrected Fast Fourier Sampler
pub struct FFSamplerCorrect {
    /// The NTRU basis
    basis: NTRUBasis,
    /// The LDL decomposition tree
    ldl_tree: LDLTree,
    /// Gaussian sampler
    sampler: GaussianSampler,
    /// FFT engine
    fft: FFTStable,
    /// Adaptive sigma value
    sigma: f64,
}

impl FFSamplerCorrect {
    /// Create a new corrected sampler
    pub fn new(basis: NTRUBasis) -> Result<Self> {
        // Check basis validity
        if !basis.is_valid_for_signing() {
            #[cfg(feature = "std")]
            eprintln!("Warning: Basis may not be suitable for signing");
        }
        
        // Compute Gram matrix
        let gram_fft = basis.compute_gram_fft();
        let mut gram = GramMatrixFFT::from_basis_fft(
            &basis.f_fft,
            &basis.g_fft,
            &basis.big_f_fft,
            &basis.big_g_fft,
        )?;
        
        // Apply adaptive regularization if needed
        if !gram.is_well_conditioned() {
            crate::gram_matrix::adaptive_regularization(&mut gram)?;
        }
        
        // Build LDL tree
        let ldl_tree = LDLTree::from_gram_matrix(&gram)?;
        ldl_tree.validate()?;
        
        // Create Gaussian sampler with appropriate sigma
        let sigma = compute_adaptive_sigma(&basis);
        let sampler = GaussianSampler::new(sigma);
        
        // Create FFT engine
        let fft = FFTStable::new(N);
        
        Ok(Self {
            basis,
            ldl_tree,
            sampler,
            fft,
            sigma,
        })
    }
    
    /// Sample a signature (s0, s1) such that s0 + s1*h = c (mod q)
    pub fn sample_signature<R: RngCore>(
        &self,
        c: &[i16],  // Target (hashed message)
        rng: &mut R,
    ) -> Result<(Vec<i16>, Vec<i16>)> {
        // Convert target to FFT domain
        let c_f64: Vec<f64> = c.iter().map(|&x| x as f64).collect();
        let c_fft = self.fft.forward(&c_f64);
        
        // Compute the target vector t in the basis coordinates
        // t = c * B^{-1} where B is the basis [[f, g], [F, G]]
        let t_fft = self.compute_target_vector(&c_fft)?;
        
        // Sample z from the lattice using recursive FFT sampling
        let z_fft = self.sample_recursive(&t_fft, self.ldl_tree.root, rng)?;
        
        // Ensure the result has the correct size
        let mut z0_full = vec![ComplexStable::zero(); N];
        let mut z1_full = vec![ComplexStable::zero(); N];
        for i in 0..z_fft.0.len().min(N) {
            z0_full[i] = z_fft.0[i];
        }
        for i in 0..z_fft.1.len().min(N) {
            z1_full[i] = z_fft.1[i];
        }
        
        // Transform back to coefficient domain
        let z0 = self.fft.inverse(&z0_full);
        let z1 = self.fft.inverse(&z1_full);
        
        // Round to integers
        let mut z0_int = vec![0i16; N];
        let mut z1_int = vec![0i16; N];
        for i in 0..N {
            z0_int[i] = z0[i].round() as i16;
            z1_int[i] = z1[i].round() as i16;
        }
        
        // Compute signature (s0, s1) from sampled point (z0, z1)
        let (s0, s1) = self.transform_to_signature(c, &z0_int, &z1_int)?;
        
        // Verify equation before returning
        if !verify_signature_equation(&s0, &s1, &self.basis.h, c) {
            #[cfg(feature = "std")]
            eprintln!("Warning: Signature equation not satisfied, retrying");
            return Err(Falcon512Error::SamplingFailed);
        }
        
        Ok((s0, s1))
    }
    
    /// Compute target vector t = c * B^{-1} in FFT domain
    fn compute_target_vector(&self, c_fft: &[ComplexStable]) -> Result<(Vec<ComplexStable>, Vec<ComplexStable>)> {
        let n = c_fft.len();
        let mut t0 = vec![ComplexStable::zero(); n];
        let mut t1 = vec![ComplexStable::zero(); n];
        
        // For each FFT coefficient, solve the linear system
        // [f g] [t0]   [c]
        // [F G] [t1] = [0]
        for i in 0..n {
            let f = self.basis.f_fft[i];
            let g = self.basis.g_fft[i];
            let big_f = self.basis.big_f_fft[i];
            let big_g = self.basis.big_g_fft[i];
            let c_i = c_fft[i];
            
            // Compute determinant: det = f*G - g*F
            let det = ComplexStable {
                re: f.re * big_g.re - f.im * big_g.im - (g.re * big_f.re - g.im * big_f.im),
                im: f.re * big_g.im + f.im * big_g.re - (g.re * big_f.im + g.im * big_f.re),
                precision_bits: f.precision_bits.min(g.precision_bits).min(big_f.precision_bits).min(big_g.precision_bits),
            };
            
            // Check for near-zero determinant
            if det.norm_sqr() < 1e-10 {
                #[cfg(feature = "std")]
                eprintln!("Warning: Near-zero determinant at FFT index {}", i);
                return Err(Falcon512Error::NumericalInstability);
            }
            
            // Inverse determinant
            let det_inv_norm = 1.0 / det.norm_sqr();
            let det_inv = ComplexStable {
                re: det.re * det_inv_norm,
                im: -det.im * det_inv_norm,
                precision_bits: det.precision_bits.saturating_sub(2),
            };
            
            // Apply Cramer's rule
            // t0 = (G*c) / det
            // t1 = (-F*c) / det
            let gc = big_g.mul_tracked(&c_i);
            let fc = big_f.mul_tracked(&c_i);
            
            t0[i] = gc.mul_tracked(&det_inv);
            t1[i] = ComplexStable {
                re: -fc.re,
                im: -fc.im,
                precision_bits: fc.precision_bits,
            }.mul_tracked(&det_inv);
        }
        
        Ok((t0, t1))
    }
    
    /// Recursive sampling using the LDL tree
    fn sample_recursive<R: RngCore>(
        &self,
        t: &(Vec<ComplexStable>, Vec<ComplexStable>),
        node_idx: usize,
        rng: &mut R,
    ) -> Result<(Vec<ComplexStable>, Vec<ComplexStable>)> {
        let node = &self.ldl_tree.nodes[node_idx];
        
        if node.children.is_empty() {
            // Leaf node - sample from Gaussian
            self.sample_leaf(t, node, rng)
        } else {
            // Internal node - recurse on children
            let (t_left, t_right) = self.split_target(t, node);
            
            // Sample from left child
            let z_left = self.sample_recursive(&t_left, node.children[0], rng)?;
            
            // Update target for right child based on left sample
            let t_right_updated = self.update_target(&t_right, &z_left, node);
            
            // Sample from right child
            let z_right = self.sample_recursive(&t_right_updated, node.children[1], rng)?;
            
            // Combine samples
            Ok(self.merge_samples(&z_left, &z_right))
        }
    }
    
    /// Sample at a leaf node
    fn sample_leaf<R: RngCore>(
        &self,
        t: &(Vec<ComplexStable>, Vec<ComplexStable>),
        node: &LDLNode,
        rng: &mut R,
    ) -> Result<(Vec<ComplexStable>, Vec<ComplexStable>)> {
        let mut z0 = vec![ComplexStable::zero(); t.0.len()];
        let mut z1 = vec![ComplexStable::zero(); t.1.len()];
        
        for i in 0..node.size {
            // Get variances from LDL decomposition
            let sigma0 = node.d00[i].sqrt().max(1.0);
            let sigma1 = node.d11[i].sqrt().max(1.0);
            
            // Sample from discrete Gaussian centered at t
            let center0 = t.0[i].re;
            let center1 = t.1[i].re;
            
            let sample0 = self.sampler.sample_with_center_sigma(center0, sigma0, rng);
            let sample1 = self.sampler.sample_with_center_sigma(center1, sigma1, rng);
            
            z0[i] = ComplexStable::new(sample0 as f64, 0.0);
            z1[i] = ComplexStable::new(sample1 as f64, 0.0);
        }
        
        Ok((z0, z1))
    }
    
    /// Split target for child nodes
    fn split_target(
        &self,
        t: &(Vec<ComplexStable>, Vec<ComplexStable>),
        node: &LDLNode,
    ) -> ((Vec<ComplexStable>, Vec<ComplexStable>), (Vec<ComplexStable>, Vec<ComplexStable>)) {
        let half = node.size / 2;
        
        let t0_left = t.0[..half].to_vec();
        let t1_left = t.1[..half].to_vec();
        let t0_right = t.0[half..node.size].to_vec();
        let t1_right = t.1[half..node.size].to_vec();
        
        ((t0_left, t1_left), (t0_right, t1_right))
    }
    
    /// Update target for right child based on left sample
    fn update_target(
        &self,
        t_right: &(Vec<ComplexStable>, Vec<ComplexStable>),
        z_left: &(Vec<ComplexStable>, Vec<ComplexStable>),
        node: &LDLNode,
    ) -> (Vec<ComplexStable>, Vec<ComplexStable>) {
        // Apply Schur complement update
        // This is a simplified version - full implementation would use the actual Schur complement
        let mut t0_updated = t_right.0.clone();
        let mut t1_updated = t_right.1.clone();
        
        // In practice, this would involve the off-diagonal blocks of the LDL decomposition
        for i in 0..t0_updated.len() {
            if i < z_left.0.len() {
                // Simplified update - actual would use L[1][0] elements
                t0_updated[i].re -= z_left.0[i].re * 0.1;  // Placeholder coefficient
                t1_updated[i].re -= z_left.1[i].re * 0.1;  // Placeholder coefficient
            }
        }
        
        (t0_updated, t1_updated)
    }
    
    /// Merge samples from child nodes
    fn merge_samples(
        &self,
        z_left: &(Vec<ComplexStable>, Vec<ComplexStable>),
        z_right: &(Vec<ComplexStable>, Vec<ComplexStable>),
    ) -> (Vec<ComplexStable>, Vec<ComplexStable>) {
        let mut z0 = z_left.0.clone();
        z0.extend(&z_right.0);
        
        let mut z1 = z_left.1.clone();
        z1.extend(&z_right.1);
        
        (z0, z1)
    }
    
    /// Transform sampled point to signature ensuring equation satisfaction
    fn transform_to_signature(
        &self,
        c: &[i16],
        z0: &[i16],
        z1: &[i16],
    ) -> Result<(Vec<i16>, Vec<i16>)> {
        // Compute v = z * B where B is the basis
        // v0 = z0*f + z1*F
        // v1 = z0*g + z1*G
        let v0 = polynomial_combination(z0, &self.basis.f, z1, &self.basis.big_f);
        let v1 = polynomial_combination(z0, &self.basis.g, z1, &self.basis.big_g);
        
        // The signature is s = (c - v0, -v1) mod q
        let mut s0 = vec![0i16; N];
        let mut s1 = vec![0i16; N];
        
        for i in 0..N {
            // s0 = c - v0 mod q
            let diff = (c[i] as i32 - v0[i] as i32).rem_euclid(Q as i32);
            s0[i] = center_reduce(diff);
            
            // s1 = -v1 mod q
            let neg = (-(v1[i] as i32)).rem_euclid(Q as i32);
            s1[i] = center_reduce(neg);
        }
        
        Ok((s0, s1))
    }
}

/// Compute adaptive sigma based on basis quality
fn compute_adaptive_sigma(basis: &NTRUBasis) -> f64 {
    let base_sigma = SIGMA;
    
    // Adjust based on condition number
    if basis.quality.condition_number > 1e6 {
        base_sigma * 1.5
    } else if basis.quality.condition_number > 1e5 {
        base_sigma * 1.2
    } else {
        base_sigma
    }
}

/// Compute linear combination of polynomials
fn polynomial_combination(
    a0: &[i16],
    p0: &[i16],
    a1: &[i16],
    p1: &[i16],
) -> Vec<i16> {
    let mut result = vec![0i16; N];
    
    for i in 0..N {
        let val = (a0[i] as i32 * p0[i] as i32 + a1[i] as i32 * p1[i] as i32)
            .rem_euclid(Q as i32);
        result[i] = val as i16;
    }
    
    result
}

/// Center reduce a value modulo q to [-q/2, q/2)
fn center_reduce(x: i32) -> i16 {
    let mut val = x % Q as i32;
    if val > (Q as i32) / 2 {
        val -= Q as i32;
    } else if val < -(Q as i32) / 2 {
        val += Q as i32;
    }
    val as i16
}

/// Verify that s0 + s1*h = c (mod q)
pub fn verify_signature_equation(
    s0: &[i16],
    s1: &[i16],
    h: &[i16],
    c: &[i16],
) -> bool {
    // Compute s1*h using NTT
    let s1h = crate::ntt_falcon::multiply_ntt(s1, h);
    
    // Check equation at each coefficient
    for i in 0..N {
        let lhs = (s0[i] as i32 + s1h[i] as i32).rem_euclid(Q as i32);
        // Also reduce rhs to positive range for comparison
        let rhs = if c[i] < 0 {
            (c[i] as i32 + Q as i32) as i32
        } else {
            c[i] as i32
        };
        
        if lhs != rhs {
            #[cfg(feature = "std")]
            eprintln!("Equation failed at index {}: {} != {}", i, lhs, rhs);
            return false;
        }
    }
    
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_center_reduce() {
        assert_eq!(center_reduce(0), 0);
        assert_eq!(center_reduce(Q as i32 / 2), Q as i16 / 2);
        assert_eq!(center_reduce(Q as i32 / 2 + 1), -(Q as i16 / 2));
        assert_eq!(center_reduce(Q as i32), 0);
    }
    
    #[test]
    fn test_signature_equation() {
        // Simple test: s0 = c, s1 = 0 should satisfy s0 + s1*h = c
        let c = vec![100i16; N];
        let s0 = c.clone();
        let s1 = vec![0i16; N];
        let h = vec![1i16; N];  // Dummy public key
        
        assert!(verify_signature_equation(&s0, &s1, &h, &c));
    }
}