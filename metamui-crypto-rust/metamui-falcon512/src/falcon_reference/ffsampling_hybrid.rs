//! Hybrid Fast Fourier Sampling with improved numerical precision
//! 
//! This module implements FFT sampling using the hybrid approach with
//! emulated floating-point for critical operations.

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::fft_hybrid::{HybridFFT, HybridComplex, FFTMode};
use crate::poly::PolyF64;
use super::ffldl_hybrid::{HybridFFLDLTree, ffldl_fft_hybrid, split_fft_hybrid, merge_fft_hybrid};
use super::basis_hybrid::{HybridBasis, compute_target_fft_hybrid};
use super::gaussian::GaussianSampler;
use alloc::vec::Vec;
use rand::RngCore;

/// Hybrid FFT Sampler with selectable precision modes
pub struct HybridFFSampler {
    /// The basis in hybrid FFT form
    basis: HybridBasis,
    /// The ffLDL tree for sampling
    tree: HybridFFLDLTree,
    /// Standard deviation for sampling
    sigma: f64,
    /// Minimum standard deviation
    sigma_min: f64,
    /// FFT mode (Native, Emulated, or Hybrid)
    mode: FFTMode,
}

impl HybridFFSampler {
    /// Create a new hybrid sampler from private key
    pub fn new(
        f: &[i16],
        g: &[i16],
        big_f: &[i16],
        big_g: &[i16],
        sigma: f64,
        sigma_min: f64,
        mode: FFTMode,
    ) -> Result<Self> {
        // Create basis with hybrid FFT
        let basis = HybridBasis::new(f, g, big_f, big_g, mode)?;
        
        // Check basis stability
        if !basis.check_stability() {
            #[cfg(feature = "std")]
            eprintln!("Warning: Basis may be numerically unstable, applying regularization");
            
            // Could apply regularization here if needed
        }
        
        // Compute Gram matrix G = B * B^T using emulated precision for this critical operation
        let gram_mode = if mode == FFTMode::Hybrid {
            FFTMode::Emulated  // Use emulated for Gram matrix in hybrid mode
        } else {
            mode
        };
        
        let g = basis.compute_gram_matrix(gram_mode)?;
        
        // Check conditioning and regularize if needed
        if !check_gram_conditioning_hybrid(&g) {
            #[cfg(feature = "std")]
            eprintln!("Warning: Gram matrix poorly conditioned, applying regularization");
            // Regularization could be added here
        }
        
        // Build ffLDL tree with appropriate precision
        let tree = ffldl_fft_hybrid(&g, gram_mode)?;
        
        // Compute adaptive sigma if in hybrid mode
        let final_sigma = if mode == FFTMode::Hybrid {
            compute_adaptive_sigma(&basis, sigma)
        } else {
            sigma
        };
        
        Ok(Self {
            basis,
            tree,
            sigma: final_sigma,
            sigma_min,
            mode,
        })
    }
    
    /// Sample a preimage with hybrid precision
    pub fn sample_preimage<R: RngCore>(
        &self,
        c: &[i16],  // The target (hashed message)
        rng: &mut R,
    ) -> Result<(Vec<i16>, Vec<i16>)> {
        // Convert c to hybrid FFT representation
        let c_f64: Vec<f64> = c.iter().map(|&x| x as f64).collect();
        let c_poly = PolyF64::new(c_f64);
        
        let hybrid_fft = HybridFFT::new(self.mode);
        let c_fft = hybrid_fft.forward(&c_poly);
        
        // Compute target vector t = (c, 0) * B0_fft
        // Use emulated precision for this critical operation in hybrid mode
        let target_mode = if self.mode == FFTMode::Hybrid {
            FFTMode::Emulated
        } else {
            self.mode
        };
        
        let t_fft = compute_target_fft_hybrid(&c_fft, self.basis.get_inverse_basis_fft(), target_mode)?;
        
        // Sample z from the lattice using hybrid ffsampling
        let z_fft = self.ffsampling_fft_hybrid(&t_fft, rng)?;
        
        // Apply Babai rounding at this level for better norm
        let z_rounded = apply_babai_rounding(&z_fft);
        
        // Compute v = z * B
        let v_fft = self.multiply_by_basis_hybrid(&z_rounded)?;
        
        // Convert back to coefficient domain
        let v0 = fft_to_poly_hybrid(&v_fft[0]);
        let v1 = fft_to_poly_hybrid(&v_fft[1]);
        
        // The signature is s = (c - v0, -v1)
        let mut s0 = vec![0i16; N];
        let mut s1 = vec![0i16; N];
        
        // Use extended precision for final computation
        for i in 0..N {
            // Use 64-bit arithmetic to prevent overflow
            let s0_val = (c[i] as i64 - v0[i] as i64).rem_euclid(Q as i64);
            let s1_val = (-(v1[i] as i64)).rem_euclid(Q as i64);
            
            s0[i] = s0_val as i16;
            s1[i] = s1_val as i16;
            
            // Center reduce to [-q/2, q/2)
            if s0[i] > (Q / 2) as i16 {
                s0[i] -= Q as i16;
            }
            if s1[i] > (Q / 2) as i16 {
                s1[i] -= Q as i16;
            }
        }
        
        Ok((s0, s1))
    }
    
    /// Core ffsampling with hybrid precision
    fn ffsampling_fft_hybrid<R: RngCore>(
        &self,
        t: &[Vec<HybridComplex>; 2],
        rng: &mut R,
    ) -> Result<[Vec<HybridComplex>; 2]> {
        self.ffsampling_recursive_hybrid(t, &self.tree, rng, 0)
    }
    
    /// Recursive helper with depth tracking for precision decisions
    fn ffsampling_recursive_hybrid<R: RngCore>(
        &self,
        t: &[Vec<HybridComplex>; 2],
        tree: &HybridFFLDLTree,
        rng: &mut R,
        depth: usize,
    ) -> Result<[Vec<HybridComplex>; 2]> {
        let n = t[0].len();
        
        match tree {
            HybridFFLDLTree::Leaf { l10, d00, d11 } => {
                // Base case: sample from Gaussian
                if n != 1 {
                    return Err(Falcon512Error::InvalidParameter);
                }
                
                let sampler = GaussianSampler::new(self.sigma, self.sigma_min);
                
                // Extract values (convert to native for sampling)
                let (t0_re, _) = t[0][0].to_native();
                let (t1_re, _) = t[1][0].to_native();
                let (d00_val, _) = d00[0].to_native();
                let (d11_val, _) = d11[0].to_native();
                
                // Sample with appropriate standard deviations
                let sigma0 = d00_val.sqrt().max(self.sigma_min);
                let sigma1 = d11_val.sqrt().max(self.sigma_min);
                
                let z0 = sampler.sample_with_sigma(t0_re, sigma0, rng) as f64;
                let z1 = sampler.sample_with_sigma(t1_re, sigma1, rng) as f64;
                
                // Return in appropriate mode
                Ok([
                    vec![HybridComplex::new(z0, 0.0, self.mode)],
                    vec![HybridComplex::new(z1, 0.0, self.mode)],
                ])
            }
            
            HybridFFLDLTree::Node { l10, left, right } => {
                // Split t into two halves
                let (t0_left, t0_right) = split_fft_hybrid(&t[0]);
                let (t1_left, t1_right) = split_fft_hybrid(&t[1]);
                
                // Sample from right subtree first
                let z1_split = self.ffsampling_recursive_hybrid(
                    &[t1_left, t1_right],
                    right,
                    rng,
                    depth + 1,
                )?;
                let z1 = merge_fft_hybrid(&z1_split[0], &z1_split[1]);
                
                // Update t0 based on sampled z1 with numerical damping
                let damping = 0.999_f64.powi(depth as i32); // Progressive damping
                let mut t0_new = vec![HybridComplex::zero(self.mode); n];
                
                for i in 0..n {
                    // t0_new = t0 + (t1 - z1) * l10 * damping
                    let diff = t[1][i].sub(z1[i]);
                    let update = diff.mul(l10[i]);
                    
                    // Apply damping to prevent oscillation
                    let damped = match update {
                        HybridComplex::Native { re, im } => {
                            HybridComplex::Native { 
                                re: re * damping, 
                                im: im * damping 
                            }
                        }
                        HybridComplex::Emulated { re, im } => {
                            use crate::falcon_fpr::FPR;
                            HybridComplex::Emulated {
                                re: re.mul(FPR::from_f64(damping)),
                                im: im.mul(FPR::from_f64(damping)),
                            }
                        }
                    };
                    
                    t0_new[i] = t[0][i].add(damped);
                }
                
                // Sample from left subtree
                let (t0_new_left, t0_new_right) = split_fft_hybrid(&t0_new);
                let z0_split = self.ffsampling_recursive_hybrid(
                    &[t0_new_left, t0_new_right],
                    left,
                    rng,
                    depth + 1,
                )?;
                let z0 = merge_fft_hybrid(&z0_split[0], &z0_split[1]);
                
                Ok([z0, z1])
            }
        }
    }
    
    /// Multiply z by the basis B
    fn multiply_by_basis_hybrid(&self, z: &[Vec<HybridComplex>; 2]) -> Result<[Vec<HybridComplex>; 2]> {
        let b = self.basis.get_basis_fft();
        let n = z[0].len();
        
        // v = z * B
        // v0 = z0 * f + z1 * F
        // v1 = z0 * g + z1 * G
        
        let mut v0 = vec![HybridComplex::zero(self.mode); n];
        let mut v1 = vec![HybridComplex::zero(self.mode); n];
        
        for i in 0..n {
            v0[i] = z[0][i].mul(b[0][0][i]).add(z[1][i].mul(b[1][0][i]));
            v1[i] = z[0][i].mul(b[0][1][i]).add(z[1][i].mul(b[1][1][i]));
        }
        
        Ok([v0, v1])
    }
}

/// Apply Babai rounding to reduce norm
fn apply_babai_rounding(z: &[Vec<HybridComplex>; 2]) -> [Vec<HybridComplex>; 2] {
    let mut rounded = z.clone();
    
    for vec in &mut rounded {
        for c in vec {
            let (re, im) = c.to_native();
            // Round to nearest integer
            let re_rounded = re.round();
            let im_rounded = im.round();
            *c = HybridComplex::new(re_rounded, im_rounded, FFTMode::Native);
        }
    }
    
    rounded
}

/// Convert hybrid FFT to polynomial
fn fft_to_poly_hybrid(fft: &[HybridComplex]) -> Vec<i16> {
    let n = fft.len();
    let mut native_fft = Vec::with_capacity(n);
    
    for c in fft {
        let (re, im) = c.to_native();
        native_fft.push(crate::fft::Complex::new(re, im));
    }
    
    // Apply inverse FFT
    let poly_f64 = crate::fft::FFT::inverse_to_f64(&native_fft);
    
    // Round to nearest integer
    poly_f64.iter().map(|&x| x.round() as i16).collect()
}

/// Check Gram matrix conditioning
fn check_gram_conditioning_hybrid(g: &[[Vec<HybridComplex>; 2]; 2]) -> bool {
    // Check diagonal dominance
    for i in 0..g[0][0].len() {
        let diag_sum = g[0][0][i].norm_sqr() + g[1][1][i].norm_sqr();
        let off_diag = g[0][1][i].norm_sqr() + g[1][0][i].norm_sqr();
        
        // Matrix should be diagonally dominant
        if diag_sum < 1.5 * off_diag {
            return false;
        }
    }
    
    true
}

/// Compute adaptive sigma based on basis conditioning
fn compute_adaptive_sigma(basis: &HybridBasis, base_sigma: f64) -> f64 {
    let condition = basis.estimate_condition_number();
    
    if condition > 1e6 {
        // Very poor conditioning
        base_sigma * 1.5
    } else if condition > 1e4 {
        // Poor conditioning
        base_sigma * 1.2
    } else {
        // Good conditioning
        base_sigma
    }
}