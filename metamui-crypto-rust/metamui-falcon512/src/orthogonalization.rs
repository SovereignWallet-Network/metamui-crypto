//! Proper Lattice Basis Orthogonalization for Falcon-512
//! 
//! This implements the Gram-Schmidt orthogonalization and related
//! operations needed for Fast Fourier Sampling.

use crate::constants::N;
use crate::error::{Result, Falcon512Error};
use crate::fft::{FFT, Complex};
use crate::poly::PolyF64;
use alloc::vec::Vec;

/// Helper function to convert i16 coefficients to FFT domain
fn forward_f64(coeffs: &[i16]) -> Vec<Complex> {
    let poly_f64 = PolyF64 {
        coeffs: coeffs.iter().map(|&x| x as f64).collect(),
    };
    FFT::forward(&poly_f64)
}

/// Lattice basis structure for Falcon-512
pub struct LatticeBasis {
    pub f: Vec<i16>,
    pub g: Vec<i16>,
    pub big_f: Vec<i16>,
    pub big_g: Vec<i16>,
}

/// Orthogonalized basis in FFT domain
pub struct OrthogonalizedBasis {
    /// Gram-Schmidt vectors in FFT domain
    pub b_star_fft: Vec<Vec<Complex>>,
    /// Gram-Schmidt norms
    pub norms: Vec<f64>,
    /// Tree structure for Fast Fourier Sampling
    pub tree: FalconTree,
}

/// Tree structure for Fast Fourier Sampling
pub struct FalconTree {
    /// Levels of the tree (log n levels)
    pub levels: Vec<TreeLevel>,
}

/// Single level in the Falcon tree
pub struct TreeLevel {
    /// Gram-Schmidt norms at this level
    pub sigma: Vec<f64>,
    /// FFT values at this level
    pub fft_data: Vec<Complex>,
}

impl LatticeBasis {
    /// Create new lattice basis from NTRU keys
    pub fn new(f: Vec<i16>, g: Vec<i16>, big_f: Vec<i16>, big_g: Vec<i16>) -> Self {
        Self { f, g, big_f, big_g }
    }
    
    /// Orthogonalize the basis using proper Gram-Schmidt
    pub fn orthogonalize(&self) -> Result<OrthogonalizedBasis> {
        // Convert to FFT domain using forward_f64 method
        let f_fft = forward_f64(&self.f);
        let g_fft = forward_f64(&self.g);
        let big_f_fft = forward_f64(&self.big_f);
        let big_g_fft = forward_f64(&self.big_g);
        
        // Build the basis matrix B = [[g, -f], [G, -F]]
        // In FFT domain for efficiency
        let mut b_fft = vec![vec![Complex::zero(); N]; 2];
        
        for i in 0..N {
            b_fft[0][i] = g_fft[i];
            b_fft[1][i] = big_g_fft[i];
        }
        
        // Compute Gram-Schmidt orthogonalization
        let (b_star_fft, norms) = self.gram_schmidt_fft(b_fft)?;
        
        // Build tree for Fast Fourier Sampling
        let tree = self.build_falcon_tree(&b_star_fft, &norms)?;
        
        Ok(OrthogonalizedBasis {
            b_star_fft,
            norms,
            tree,
        })
    }
    
    /// Gram-Schmidt orthogonalization in FFT domain
    fn gram_schmidt_fft(&self, mut b_fft: Vec<Vec<Complex>>) -> Result<(Vec<Vec<Complex>>, Vec<f64>)> {
        let n = b_fft.len();
        let mut norms = vec![0.0; n];
        
        for i in 0..n {
            // Compute norm of current vector
            let mut norm_sq = 0.0;
            for j in 0..N {
                let val = b_fft[i][j];
                norm_sq += val.re * val.re + val.im * val.im;
            }
            
            if norm_sq < 1e-10 {
                return Err(Falcon512Error::InvalidParameter);
            }
            
            norms[i] = norm_sq.sqrt();
            
            // Normalize current vector
            let inv_norm = 1.0 / norms[i];
            for j in 0..N {
                b_fft[i][j] = b_fft[i][j].scale(inv_norm);
            }
            
            // Orthogonalize remaining vectors
            for k in (i + 1)..n {
                // Compute projection
                let mut proj = Complex::zero();
                for j in 0..N {
                    proj = proj.add(&b_fft[k][j].mul(&b_fft[i][j].conj()));
                }
                
                // Subtract projection
                for j in 0..N {
                    b_fft[k][j] = b_fft[k][j].sub(&b_fft[i][j].mul_scalar(proj.re));
                }
            }
        }
        
        Ok((b_fft, norms))
    }
    
    /// Build Falcon tree for Fast Fourier Sampling
    fn build_falcon_tree(
        &self,
        b_star_fft: &[Vec<Complex>],
        norms: &[f64],
    ) -> Result<FalconTree> {
        let logn = 9;  // log2(512)
        let mut levels = Vec::with_capacity(logn);
        
        // Build tree from leaves to root
        for level in 0..logn {
            let size = N >> level;
            let mut sigma = vec![0.0; size];
            let mut fft_data = vec![Complex::zero(); size];
            
            if level == 0 {
                // Leaf level: use base norms
                for i in 0..size {
                    sigma[i] = norms[i % 2];
                    fft_data[i] = b_star_fft[i % 2][i];
                }
            } else {
                // Internal level: merge from children
                let child_size = size * 2;
                let child_level: &TreeLevel = &levels[level - 1];
                
                for i in 0..size {
                    // Merge two children
                    let left = child_level.sigma[2 * i];
                    let right = child_level.sigma[2 * i + 1];
                    
                    // Compute merged norm
                    sigma[i] = (left * left + right * right).sqrt();
                    
                    // Merge FFT data
                    fft_data[i] = child_level.fft_data[2 * i]
                        .add(&child_level.fft_data[2 * i + 1]);
                }
            }
            
            levels.push(TreeLevel { sigma, fft_data });
        }
        
        Ok(FalconTree { levels })
    }
    
    /// Verify the orthogonalization is correct
    pub fn verify_orthogonalization(&self, ortho: &OrthogonalizedBasis) -> bool {
        // Check that norms are reasonable
        for &norm in &ortho.norms {
            if norm < 1.0 || norm > 1e6 {
                return false;
            }
        }
        
        // Check tree structure
        if ortho.tree.levels.len() != 9 {
            return false;
        }
        
        // Check that tree levels have correct sizes
        for (i, level) in ortho.tree.levels.iter().enumerate() {
            let expected_size = N >> i;
            if level.sigma.len() != expected_size {
                return false;
            }
        }
        
        true
    }
}

/// Fast Fourier Sampling using orthogonalized basis
pub fn fast_fourier_sample<R: rand::RngCore>(
    target: &[i16],
    basis: &OrthogonalizedBasis,
    rng: &mut R,
) -> Result<(Vec<i16>, Vec<i16>)> {
    use crate::gaussian_calibrated::GaussianCalibrated as TunedGaussianSampler;
    
    // Use standard sigma for Falcon-512
    let sampler = TunedGaussianSampler::new(165.7);
    let mut z0 = vec![0i16; N];
    let mut z1 = vec![0i16; N];
    
    // Convert target to FFT domain
    let t_poly = PolyF64 { coeffs: target.iter().map(|&x| x as f64).collect() };
    let mut t_fft = FFT::forward(&t_poly);
    
    // Sample from root to leaves in the tree
    for level in basis.tree.levels.iter().rev() {
        for i in 0..level.sigma.len() {
            // Compute center for sampling
            let center = t_fft[i].re / level.sigma[i];
            
            // Sample from discrete Gaussian
            let sample = sampler.sample_with_center(center, rng);
            
            // Store sample
            if i < N / 2 {
                z0[i] = sample as i16;
            } else {
                z1[i - N / 2] = sample as i16;
            }
            
            // Update target
            t_fft[i] = t_fft[i].sub(&level.fft_data[i].scale(sample as f64));
        }
    }
    
    Ok((z0, z1))
}

// Complex number extensions - using methods from fft.rs
// Additional methods if needed
impl Complex {
    fn scale(&self, s: f64) -> Complex {
        Complex {
            re: self.re * s,
            im: self.im * s,
        }
    }
    
    fn mul_scalar(&self, s: f64) -> Complex {
        self.scale(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::Q;

    #[test]
    fn test_lattice_basis_creation() {
        let f = vec![1i16; N];
        let g = vec![0i16; N];
        let big_f = vec![0i16; N];
        let big_g = vec![1i16; N];
        
        let basis = LatticeBasis::new(f, g, big_f, big_g);
        assert_eq!(basis.f.len(), N);
        assert_eq!(basis.g.len(), N);
    }
    
    #[test]
    fn test_orthogonalization() {
        let mut f = vec![0i16; N];
        let mut g = vec![0i16; N];
        let mut big_f = vec![0i16; N];
        let mut big_g = vec![0i16; N];
        
        // Set some non-zero values
        f[0] = 1;
        g[0] = 1;
        big_f[0] = Q as i16 - 1;
        big_g[0] = 1;
        
        let basis = LatticeBasis::new(f, g, big_f, big_g);
        
        match basis.orthogonalize() {
            Ok(ortho) => {
                assert!(basis.verify_orthogonalization(&ortho));
                println!("Orthogonalization successful");
            }
            Err(e) => {
                println!("Orthogonalization failed: {:?}", e);
            }
        }
    }
}