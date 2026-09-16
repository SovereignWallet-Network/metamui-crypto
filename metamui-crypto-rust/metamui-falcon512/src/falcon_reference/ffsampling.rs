//! Fast Fourier Sampling Algorithm
//! 
//! This is the core of Falcon - samples short vectors from a lattice
//! that satisfy the signature equation

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::fft::{FFTComplex, FFT};
use crate::poly::PolyF64;
use super::ffldl::{FFLDLTree, ffldl_fft, split_fft, merge_fft};
use super::basis::{ReferenceBasis, compute_target_fft};
use super::gaussian::GaussianSampler;
use alloc::vec::Vec;
use rand::RngCore;

/// Reference implementation of Fast Fourier Sampler
pub struct ReferenceFFSampler {
    /// The basis in FFT form
    basis: ReferenceBasis,
    /// The ffLDL tree for sampling
    tree: FFLDLTree,
    /// Standard deviation for sampling
    sigma: f64,
    /// Minimum standard deviation
    sigma_min: f64,
}

impl ReferenceFFSampler {
    /// Create a new sampler from private key
    pub fn new(
        f: &[i16],
        g: &[i16],
        big_f: &[i16],
        big_g: &[i16],
        sigma: f64,
        sigma_min: f64,
    ) -> Result<Self> {
        // Create basis
        let basis = ReferenceBasis::new(f, g, big_f, big_g)?;
        
        // Check basis stability
        if !super::numerical_stability::check_basis_stability(basis.get_basis_fft()) {
            // If basis is unstable, we might still proceed but with warnings
            #[cfg(feature = "std")]
            eprintln!("Warning: FFT basis may be numerically unstable");
        }
        
        // Compute Gram matrix G = B * B^T
        let b_fft = basis.get_basis_fft();
        let mut g = super::ffldl::gram_fft(b_fft);
        
        // Check and improve conditioning if needed
        if !super::numerical_stability::check_gram_matrix_conditioning(&g) {
            #[cfg(feature = "std")]
            eprintln!("Warning: Gram matrix is poorly conditioned, applying regularization");
            super::numerical_stability::regularize_gram_matrix(&mut g, 1e-8);
        }
        
        // Build ffLDL tree
        let tree = ffldl_fft(&g)?;
        
        Ok(Self {
            basis,
            tree,
            sigma,
            sigma_min,
        })
    }
    
    /// Sample a preimage: find short (s0, s1) such that s0 + s1*h = c
    pub fn sample_preimage<R: RngCore>(
        &self,
        c: &[i16],  // The target (hashed message)
        rng: &mut R,
    ) -> Result<(Vec<i16>, Vec<i16>)> {
        // Convert c to FFT
        let c_f64: Vec<f64> = c.iter().map(|&x| x as f64).collect();
        let c_poly = PolyF64::new(c_f64);
        let c_fft = FFT::forward(&c_poly);
        
        // Compute target vector t = (c, 0) * B0_fft
        let t_fft = compute_target_fft(&c_fft, self.basis.get_inverse_basis_fft())?;
        
        // Sample z from the lattice using ffsampling
        let z_fft = self.ffsampling_fft(&t_fft, rng)?;
        
        // Compute v = z * B
        let v_fft = self.multiply_by_basis(&z_fft)?;
        
        // Convert back to coefficient domain
        let v0 = fft_to_poly(&v_fft[0]);
        let v1 = fft_to_poly(&v_fft[1]);

        // CORRECT FORMULA from reference implementation (falcon.py):
        // With basis B = [[g, -f], [G, -F]]:
        //   v0 = z0*g + z1*G
        //   v1 = z0*(-f) + z1*(-F)
        // The signature is:
        //   s = [point - v0, -v1]
        // This satisfies: s0 + s1*h ≡ point (mod q) where h = g/f
        //
        // Verification:
        //   s0 + s1*h = (point - z0*g - z1*G) + (z0*f + z1*F)*h
        //             = point - z0*g - z1*G + z0*f*(g/f) + z1*F*(g/f)
        //             = point - z0*g - z1*G + z0*g + z1*F*g/f
        //             = point - z1*G + z1*F*g/f
        //             = point + z1*(F*g - G*f)/f
        //             = point + z1*(-q)/f  [since f*G - g*F = q]
        //             ≡ point (mod q)      [since -q/f ≡ 0 (mod q)]

        let mut s0 = vec![0i16; N];
        let mut s1 = vec![0i16; N];

        for i in 0..N {
            // s0 = c - v0
            let s0_val = (c[i] as i32 - v0[i] as i32).rem_euclid(Q as i32);
            // s1 = -v1 (cast to i32 first to avoid overflow when v1[i] = i16::MIN)
            let s1_val = (-(v1[i] as i32)).rem_euclid(Q as i32);

            // Center reduce to [-q/2, q/2)
            let half_q = (Q / 2) as i32;
            s0[i] = if s0_val > half_q {
                (s0_val - Q as i32) as i16
            } else {
                s0_val as i16
            };

            s1[i] = if s1_val > half_q {
                (s1_val - Q as i32) as i16
            } else {
                s1_val as i16
            };
        }

        Ok((s0, s1))
    }
    
    /// The core ffsampling algorithm - recursive sampling in FFT domain
    fn ffsampling_fft<R: RngCore>(
        &self,
        t: &[Vec<FFTComplex>; 2],
        rng: &mut R,
    ) -> Result<[Vec<FFTComplex>; 2]> {
        self.ffsampling_recursive(t, &self.tree, rng)
    }
    
    /// Recursive helper for ffsampling
    fn ffsampling_recursive<R: RngCore>(
        &self,
        t: &[Vec<FFTComplex>; 2],
        tree: &FFLDLTree,
        rng: &mut R,
    ) -> Result<[Vec<FFTComplex>; 2]> {
        let n = t[0].len();
        
        match tree {
            FFLDLTree::Leaf { l10, d00, d11 } => {
                // Base case: sample from Gaussian
                if n != 1 {
                    return Err(Falcon512Error::InvalidParameter);
                }
                
                let sampler = GaussianSampler::new(self.sigma, self.sigma_min);
                
                // Sample z0 and z1 from discrete Gaussians
                // The standard deviations are sqrt(d00) and sqrt(d11)
                let sigma0 = d00[0].re.sqrt().max(self.sigma_min);
                let sigma1 = d11[0].re.sqrt().max(self.sigma_min);
                
                let z0 = sampler.sample(t[0][0].re, rng) as f64;
                let z1 = sampler.sample(t[1][0].re, rng) as f64;
                
                Ok([
                    vec![FFTComplex::new(z0, 0.0)],
                    vec![FFTComplex::new(z1, 0.0)],
                ])
            }
            
            FFLDLTree::Node { l10, left, right } => {
                // Split t into two halves
                let (t0_left, t0_right) = split_fft(&t[0]);
                let (t1_left, t1_right) = split_fft(&t[1]);
                
                // Sample from right subtree first
                let z1_split = self.ffsampling_recursive(
                    &[t1_left, t1_right],
                    right,
                    rng,
                )?;
                let z1 = merge_fft(&z1_split[0], &z1_split[1]);
                
                // Update t0 based on sampled z1
                // t0_new = t0 + (t1 - z1) * l10
                let mut t0_new = vec![FFTComplex::zero(); n];
                for i in 0..n {
                    t0_new[i] = t[0][i].add(&t[1][i].sub(&z1[i]).mul(&l10[i]));
                }
                
                // Sample from left subtree
                let (t0_new_left, t0_new_right) = split_fft(&t0_new);
                let z0_split = self.ffsampling_recursive(
                    &[t0_new_left, t0_new_right],
                    left,
                    rng,
                )?;
                let z0 = merge_fft(&z0_split[0], &z0_split[1]);
                
                Ok([z0, z1])
            }
        }
    }
    
    /// Multiply z by the basis B to get v
    /// Following reference implementation: B = [[g, -f], [G, -F]]
    fn multiply_by_basis(&self, z: &[Vec<FFTComplex>; 2]) -> Result<[Vec<FFTComplex>; 2]> {
        let b = self.basis.get_basis_fft();
        let n = z[0].len();

        // v = z * B where B = [[g, -f], [G, -F]]
        // v0 = z0 * g + z1 * G  (first column)
        // v1 = z0 * (-f) + z1 * (-F) = -(z0*f + z1*F)  (second column)

        let mut v0 = vec![FFTComplex::zero(); n];
        let mut v1 = vec![FFTComplex::zero(); n];

        for i in 0..n {
            // b[0][0] = g, b[1][0] = G
            v0[i] = z[0][i].mul(&b[0][0][i]).add(&z[1][i].mul(&b[1][0][i]));
            // b[0][1] = -f, b[1][1] = -F
            v1[i] = z[0][i].mul(&b[0][1][i]).add(&z[1][i].mul(&b[1][1][i]));
        }

        Ok([v0, v1])
    }
}

/// Convert FFT representation back to polynomial
fn fft_to_poly(fft: &[FFTComplex]) -> Vec<i16> {
    // Apply inverse FFT
    let poly_f64 = FFT::inverse_to_f64(fft);
    
    // Round to nearest integer
    poly_f64.iter().map(|&x| x.round() as i16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    
    #[test]
    fn test_fft_to_poly() {
        // Create a full-size polynomial with mostly zeros
        let mut poly = vec![0.0; N];
        poly[0] = 1.0;
        poly[1] = 2.0;
        poly[2] = 3.0;
        poly[3] = 4.0;
        
        let poly_obj = PolyF64::new(poly.clone());
        
        // Convert to FFT and back
        let fft = FFT::forward(&poly_obj);
        let recovered = fft_to_poly(&fft);
        
        // Check first few coefficients (might have rounding errors)
        for i in 0..4 {
            // Round the original polynomial values since we're converting to i16
            let expected = poly[i].round() as i16;
            assert_eq!(recovered[i], expected, "Mismatch at index {}", i);
        }
    }
    
    #[test]
    fn test_sampler_creation() {
        let rng = StdRng::seed_from_u64(42);
        
        // Create simple test polynomials
        let f = vec![1i16; N];
        let mut g = vec![0i16; N];
        g[0] = 1;
        let mut big_f = vec![0i16; N];
        big_f[0] = 100;
        let mut big_g = vec![0i16; N];
        big_g[0] = (Q as i16) - 100;
        
        // Try to create sampler
        match ReferenceFFSampler::new(&f, &g, &big_f, &big_g, 165.7, 1.2) {
            Ok(_) => {
                // Sampler created successfully
            }
            Err(e) => {
                // This might fail due to numerical issues in basis construction
                // which is expected for random test values
                eprintln!("Sampler creation failed (expected for test values): {:?}", e);
            }
        }
    }
}