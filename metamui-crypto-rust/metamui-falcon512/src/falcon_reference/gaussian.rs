//! Discrete Gaussian Sampler
//! 
//! Samples from discrete Gaussian distribution over the integers

use rand::RngCore;
use alloc::vec::Vec;

/// Sample from discrete Gaussian distribution centered at mu with standard deviation sigma
pub fn sample_z(mu: f64, sigma: f64, sigma_min: f64, rng: &mut impl RngCore) -> i32 {
    // Use rejection sampling
    // Sample from discrete Gaussian with sigma_min, then accept/reject based on actual sigma
    
    let s = sigma.max(sigma_min);
    let r = mu - mu.floor();
    let c_star = sample_ber_exp(r * (r - 1.0) / (2.0 * s * s), rng);
    
    let mut z: i32;
    loop {
        z = sample_discrete_gaussian_sigma(s, rng);
        let z0_star = sample_ber_exp(-(z as f64 - r) * (z as f64 - r) / (2.0 * s * s), rng);
        
        if z0_star == 1 {
            break;
        }
    }
    
    let z0 = if c_star == 1 { z } else { -z };
    z0 + mu.floor() as i32
}

/// Sample from Bernoulli distribution with probability exp(-x)
fn sample_ber_exp(x: f64, rng: &mut impl RngCore) -> i32 {
    if x <= 0.0 {
        return 1;
    }
    
    // Use rejection sampling
    // This is a simplified version - a real implementation would use
    // a more sophisticated algorithm for efficiency
    let threshold = exp_approx(-x);
    let r = (rng.next_u32() as f64) / (u32::MAX as f64);
    
    if r < threshold { 1 } else { 0 }
}

/// Sample from discrete Gaussian with fixed standard deviation
fn sample_discrete_gaussian_sigma(sigma: f64, rng: &mut impl RngCore) -> i32 {
    // Simplified discrete Gaussian sampling
    // In practice, this would use precomputed CDT tables
    
    let bound = (6.0 * sigma) as i32;
    
    loop {
        let z = (rng.next_u32() % (2 * bound as u32 + 1)) as i32 - bound;
        let prob = exp_approx(-(z as f64 * z as f64) / (2.0 * sigma * sigma));
        let r = (rng.next_u32() as f64) / (u32::MAX as f64);
        
        if r < prob {
            return z;
        }
    }
}

/// exp(x) (kept as a named helper for the sampler's call sites)
fn exp_approx(x: f64) -> f64 {
    x.exp()
}

/// Sampler with precomputed tables for efficiency
pub struct GaussianSampler {
    sigma: f64,
    sigma_min: f64,
}

impl GaussianSampler {
    /// Create a new Gaussian sampler
    pub fn new(sigma: f64, sigma_min: f64) -> Self {
        Self { sigma, sigma_min }
    }
    
    /// Sample a single value
    pub fn sample(&self, mu: f64, rng: &mut impl RngCore) -> i32 {
        sample_z(mu, self.sigma, self.sigma_min, rng)
    }
    
    /// Sample with specific sigma
    pub fn sample_with_sigma(&self, mu: f64, sigma: f64, rng: &mut impl RngCore) -> i32 {
        sample_z(mu, sigma, self.sigma_min, rng)
    }
    
    /// Sample a vector of values
    pub fn sample_vector(&self, mu: &[f64], rng: &mut impl RngCore) -> Vec<i32> {
        mu.iter().map(|&m| self.sample(m, rng)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    
    #[test]
    fn test_gaussian_sampler() {
        let mut rng = StdRng::seed_from_u64(42);
        let sampler = GaussianSampler::new(100.0, 1.2);
        
        // Sample some values
        let mut samples = Vec::new();
        for _ in 0..100 {
            samples.push(sampler.sample(0.0, &mut rng));
        }
        
        // Check that samples are reasonable
        let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / samples.len() as f64;
        assert!(mean.abs() < 20.0, "Mean should be close to 0, got {}", mean);
        
        // Check that we get some variety
        let unique_values: std::collections::HashSet<_> = samples.iter().collect();
        assert!(unique_values.len() > 10, "Should have variety in samples");
    }
    
    #[test]
    fn test_sample_ber_exp() {
        let mut rng = StdRng::seed_from_u64(42);
        
        // For x = 0, should always return 1
        assert_eq!(sample_ber_exp(0.0, &mut rng), 1);
        
        // For negative x, should always return 1
        assert_eq!(sample_ber_exp(-1.0, &mut rng), 1);
        
        // For large positive x, should usually return 0
        let mut zeros = 0;
        for _ in 0..100 {
            if sample_ber_exp(10.0, &mut rng) == 0 {
                zeros += 1;
            }
        }
        assert!(zeros > 90, "Should mostly return 0 for large x");
    }
}