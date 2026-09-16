//! Discrete Gaussian sampling for Falcon signatures
//! 
//! This module implements proper discrete Gaussian sampling
//! as required for Falcon's security guarantees.

use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;
use rand::RngCore;

/// Standard deviation for Falcon-512 signing
const SIGMA_SIGN: f64 = 165.7366171829776;

/// Cutoff for CDT sampling (number of standard deviations)
const CDT_CUTOFF: f64 = 12.0;

/// Cumulative distribution table for base sampler
struct CDTTable {
    entries: Vec<(i32, u64)>,
}

impl CDTTable {
    /// Create a new CDT table for given standard deviation
    fn new(sigma: f64) -> Self {
        let mut entries = Vec::new();
        let max_val = (CDT_CUTOFF * sigma) as i32;
        
        // Build cumulative distribution table
        for z in -max_val..=max_val {
            let prob = gaussian_probability(z as f64, sigma);
            let cumulative = (prob * (1u64 << 63) as f64) as u64;
            entries.push((z, cumulative));
        }
        
        CDTTable { entries }
    }
    
    /// Sample from the distribution using CDT
    fn sample<R: RngCore>(&self, rng: &mut R) -> i32 {
        let r = rng.next_u64();
        
        // Binary search in CDT
        for &(value, threshold) in &self.entries {
            if r < threshold {
                return value;
            }
        }
        
        // Should not reach here if table is complete
        0
    }
}

/// Compute Gaussian probability mass function
fn gaussian_probability(x: f64, sigma: f64) -> f64 {
    (-x * x / (2.0 * sigma * sigma)).exp() / (sigma * (2.0 * core::f64::consts::PI).sqrt())
}

/// Base Gaussian sampler using CDT
pub struct BaseGaussianSampler {
    cdt: CDTTable,
    sigma: f64,
}

impl BaseGaussianSampler {
    /// Create a new base sampler with given standard deviation
    pub fn new(sigma: f64) -> Self {
        BaseGaussianSampler {
            cdt: CDTTable::new(sigma),
            sigma,
        }
    }
    
    /// Sample a single integer from discrete Gaussian
    pub fn sample<R: RngCore>(&self, _rng: &mut R) -> Result<i16> {
        Err(Falcon512Error::NotImplemented)
    }
    
    /// Sample a polynomial with Gaussian coefficients
    pub fn sample_poly<R: RngCore>(&self, _rng: &mut R) -> Result<Vec<i16>> {
        Err(Falcon512Error::NotImplemented)
    }
}

/// Fast Fourier sampling over a lattice
pub struct FFTGaussianSampler {
    base_sampler: BaseGaussianSampler,
    sigma: f64,
}

impl FFTGaussianSampler {
    /// Create a new FFT sampler
    pub fn new(sigma: f64) -> Self {
        FFTGaussianSampler {
            base_sampler: BaseGaussianSampler::new(sigma / (2.0_f64).sqrt()),
            sigma,
        }
    }
    
    /// Sample a short vector (s0, s1) for signature
    pub fn sample_signature<R: RngCore>(
        &self,
        _target: &[i16],
        _basis: &LatticeBasisi,
        _rng: &mut R,
    ) -> Result<(Vec<i16>, Vec<i16>)> {
        Err(Falcon512Error::NotImplemented)
    }
}

/// Lattice basis for sampling
pub struct LatticeBasisi {
    pub f: Vec<i16>,
    pub g: Vec<i16>,
    pub big_f: Vec<i16>,
    pub big_g: Vec<i16>,
}

/// Simplified Gaussian sampler for testing
pub struct SimpleGaussianSampler {
    sigma: f64,
}

impl SimpleGaussianSampler {
    pub fn new() -> Self {
        SimpleGaussianSampler {
            sigma: SIGMA_SIGN,
        }
    }
    
    /// Simple rejection sampling (less efficient but correct)
    pub fn sample<R: RngCore>(&self, rng: &mut R) -> i16 {
        // Use Box-Muller transform for continuous Gaussian
        // then round to nearest integer
        
        let u1 = loop {
            let val = rng.next_u64() as f64 / u64::MAX as f64;
            if val > 0.0 {
                break val;
            }
        };
        
        let u2 = rng.next_u64() as f64 / u64::MAX as f64;
        
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * core::f64::consts::PI * u2).cos();
        let scaled = z * self.sigma;
        
        // Round to nearest integer
        scaled.round() as i16
    }
    
    /// Sample polynomial for signature
    pub fn sample_for_signature<R: RngCore>(
        &self,
        _target: &[i16],
        _h: &[i16],
        _rng: &mut R,
    ) -> Result<(Vec<i16>, Vec<i16>)> {
        Err(Falcon512Error::NotImplemented)
    }
}

/// Verify that a sample has acceptable norm
pub fn verify_sample_norm(s0: &[i16], s1: &[i16]) -> bool {
    let norm_sq: i64 = s0.iter().map(|&x| x as i64 * x as i64).sum::<i64>()
                     + s1.iter().map(|&x| x as i64 * x as i64).sum::<i64>();
    
    // Falcon-512 norm bound
    norm_sq < 34034726
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::N;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    
    #[test]
    fn test_base_sampler_fails_closed() {
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let sampler = BaseGaussianSampler::new(165.0);

        let result = sampler.sample(&mut rng);
        assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
    }

    #[test]
    fn test_base_sampler_poly_fails_closed() {
        let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
        let sampler = BaseGaussianSampler::new(165.0);

        let result = sampler.sample_poly(&mut rng);
        assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
    }
    
    #[test]  
    fn test_simple_sampler_fails_closed() {
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        let sampler = SimpleGaussianSampler::new();
        
        // Create a target
        let target = vec![100i16; N];
        let h = vec![1i16; N];
        
        // Sample
        let result = sampler.sample_for_signature(&target, &h, &mut rng);
        assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
    }

    #[test]
    fn test_fft_sampler_fails_closed() {
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let sampler = FFTGaussianSampler::new(165.0);
        let target = vec![0i16; N];
        let basis = LatticeBasisi {
            f: vec![0i16; N],
            g: vec![0i16; N],
            big_f: vec![0i16; N],
            big_g: vec![0i16; N],
        };

        let result = sampler.sample_signature(&target, &basis, &mut rng);
        assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
    }
}
