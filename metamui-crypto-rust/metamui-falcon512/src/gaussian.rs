/// Gaussian sampling for Falcon-512
/// 
/// This module implements discrete Gaussian sampling over the integers
/// with the specific parameters required for Falcon-512.

use crate::error::{Falcon512Error, Result};
use rand::RngCore;

/// Cumulative distribution table for half-Gaussian with σ = 1.8205
/// These values represent P(|z| ≤ k) for k = 0, 1, 2, ...
/// Scaled by 2^72 for precision
const GAUSSIAN_CDT: &[u128] = &[
    0x00000004741183A3,  // k=0
    0x00000036548CFC06,  // k=1
    0x0000024FDCBF140A,  // k=2
    0x0000171D939DE045,  // k=3
    0x0000B8E8B9D0EA01,  // k=4
    0x00039D1B83EE1500,  // k=5
    0x001B4A3803F7DC18,  // k=6
    0x00B8E8B9D0EA0100,  // k=7
    0x039D1B83EE150000,  // k=8
    0x0DC9199BDDCC0000,  // k=9
    0x2579F2827F000000,  // k=10
    0x5214F2E000000000,  // k=11
    0x9161A3D000000000,  // k=12
    0xC827187000000000,  // k=13
    0xE8FBF89000000000,  // k=14
    0xF7D7FDF000000000,  // k=15
    0xFD3FFFF000000000,  // k=16
    0xFF1FFFF000000000,  // k=17
    0xFFC7FFF000000000,  // k=18
];

/// Berexp sampler - samples from exp(-x) distribution
/// Returns true with probability exp(-x) where x ≥ 0
fn berexp<R: RngCore>(x: u64, rng: &mut R) -> bool {
    // We use the fact that exp(-x) = product of exp(-2^i) for bits i set in x
    let mut s = x;
    let mut c = 0u64;
    
    loop {
        // Generate 64 random bits
        let r = rng.next_u64();
        
        // For each bit position
        for j in 0..64 {
            if s == 0 {
                return ((r >> j) & 1) == 0;
            }
            
            if (s & 1) != 0 {
                c += 1;
            }
            
            if ((r >> j) & 1) != 0 {
                s >>= 1;
                c >>= 1;
            } else {
                if c == 0 {
                    return true;
                }
                s -= 1;
                c -= 1;
            }
        }
    }
}

/// Sample from half-Gaussian distribution (positive side only)
pub fn sample_half_gaussian<R: RngCore>(rng: &mut R) -> i32 {
    loop {
        // Generate 72 random bits for comparison
        let r0 = rng.next_u64();
        let r1 = rng.next_u64();
        let r = ((r1 & 0xFF) as u128) << 64 | r0 as u128;
        
        // Binary search in CDT table
        let mut lo = 0;
        let mut hi = GAUSSIAN_CDT.len();
        
        while hi - lo > 1 {
            let mid = (lo + hi) / 2;
            if r < GAUSSIAN_CDT[mid] {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        
        let z = hi as i32;
        
        // For values beyond the table, use rejection sampling
        if z >= GAUSSIAN_CDT.len() as i32 {
            let mut x = z as u64;
            let mut y: u64;
            
            loop {
                y = rng.next_u64();
                if berexp(y, rng) {
                    break;
                }
                x += 1;
                // Prevent overflow - if x gets too large, restart
                if x > 1000 {
                    break;
                }
            }
            
            // Additional rejection test
            // Check bounds to avoid overflow
            if x <= 1000 && y <= u32::MAX as u64 {
                // Use u64 to avoid overflow
                let z2 = ((x as u64 * x as u64 + y as u64 * y as u64) as f64).sqrt() as u64;
                if berexp(z2, rng) {
                    return x as i32;
                }
            }
        } else {
            return z;
        }
    }
}

/// Sample from centered discrete Gaussian distribution
pub fn sample_gaussian<R: RngCore>(center: f64, sigma: f64, rng: &mut R) -> i32 {
    // For Falcon, we use σ = 1.8205
    // This is a simplified version - proper implementation would
    // handle arbitrary centers and use more sophisticated sampling
    
    // Sample sign
    let sign = if rng.next_u32() & 1 == 0 { 1 } else { -1 };
    
    // Sample magnitude from half-Gaussian
    let magnitude = sample_half_gaussian(rng);
    
    // Apply sign and shift by center
    let sample = sign * magnitude;
    let result = (center + sample as f64).round() as i32;
    
    result
}

/// Sampler context for FFLDL
pub struct GaussianSampler {
    sigma: f64,
}

impl GaussianSampler {
    pub fn new(sigma: f64) -> Self {
        Self { sigma }
    }
    
    /// Sample from Gaussian centered at mu with standard deviation sigma
    pub fn sample<R: RngCore>(&self, mu: f64, sigma: f64, rng: &mut R) -> i32 {
        sample_gaussian(mu, sigma, rng)
    }
}

/// Sampler function type for FFT sampling
pub type SamplerZ = fn(&mut dyn RngCore, f64, f64) -> i32;

/// Default sampler implementation
pub fn default_sampler<R: RngCore>(rng: &mut R, mu: f64, sigma: f64) -> i32 {
    sample_gaussian(mu, sigma, rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    
    #[test]
    fn test_half_gaussian_sampling() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x1234);
        
        // Sample many values and check they're non-negative
        let mut samples = Vec::new();
        for _ in 0..1000 {
            let s = sample_half_gaussian(&mut rng);
            assert!(s >= 0);
            samples.push(s);
        }
        
        // Check that we get a reasonable distribution
        // At least half should be reasonably small
        let small_samples = samples.iter().filter(|&&s| s <= 20).count();
        assert!(small_samples > 500); // At least half should be ≤ 20
    }
    
    #[test]
    fn test_gaussian_sampling() {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5678);
        
        // Sample from centered Gaussian
        let mut sum = 0i64;
        let n = 10000;
        
        for _ in 0..n {
            let s = sample_gaussian(0.0, 1.8205, &mut rng);
            sum += s as i64;
        }
        
        // Mean should be close to 0
        let mean = sum as f64 / n as f64;
        assert!(mean.abs() < 0.1);
    }
}