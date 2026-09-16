//! Properly calibrated Gaussian sampler for Falcon-512
//! 
//! This module implements discrete Gaussian sampling with correct
//! parameters and numerical stability for lattice-based signatures.

use rand::RngCore;
use alloc::vec::Vec;
use core::f64;

/// Calibrated Gaussian sampler with precomputed CDT tables
pub struct GaussianCalibrated {
    /// Standard deviation
    sigma: f64,
    /// Minimum sigma for numerical stability
    sigma_min: f64,
    /// Maximum sigma for security
    sigma_max: f64,
    /// Precomputed CDT (Cumulative Distribution Table)
    cdt: Vec<CDTEntry>,
    /// Precision parameter for sampling
    precision: u32,
}

/// Entry in the cumulative distribution table
#[derive(Clone, Debug)]
struct CDTEntry {
    /// The integer value
    z: i32,
    /// Cumulative probability scaled to 2^precision
    prob: u64,
}

impl GaussianCalibrated {
    /// Create a new calibrated Gaussian sampler
    pub fn new(sigma: f64) -> Self {
        let sigma = sigma.max(1.0).min(1000.0);  // Clamp to reasonable range
        let sigma_min = 1.0;
        let sigma_max = 1000.0;
        let precision = 64;
        
        // Build CDT for this sigma
        let cdt = build_cdt(sigma, precision);
        
        Self {
            sigma,
            sigma_min,
            sigma_max,
            cdt,
            precision,
        }
    }
    
    /// Sample from discrete Gaussian centered at 0
    pub fn sample<R: RngCore>(&self, rng: &mut R) -> i32 {
        self.sample_with_center(0.0, rng)
    }
    
    /// Sample from discrete Gaussian centered at c
    pub fn sample_with_center<R: RngCore>(&self, c: f64, rng: &mut R) -> i32 {
        // Split center into integer and fractional parts
        let c_int = c.round() as i32;
        let c_frac = c - c_int as f64;
        
        // Sample base value centered at 0
        let base = self.sample_base(rng);
        
        // Apply center shift with randomized rounding for fractional part
        if c_frac.abs() > 1e-10 {
            // Randomized rounding for fractional center
            let scale = if self.precision >= 53 {
                (1u64 << 53) as f64
            } else {
                (1u64 << self.precision) as f64
            };
            let mask = if self.precision >= 53 {
                (1u64 << 53) - 1
            } else {
                (1u64 << self.precision) - 1
            };
            let threshold = (c_frac.abs() * scale) as u64;
            let rand_val = rng.next_u64() & mask;
            
            if rand_val < threshold {
                if c_frac > 0.0 {
                    base + c_int + 1
                } else {
                    base + c_int - 1
                }
            } else {
                base + c_int
            }
        } else {
            base + c_int
        }
    }
    
    /// Sample from discrete Gaussian with custom sigma
    pub fn sample_with_sigma<R: RngCore>(&self, sigma: f64, rng: &mut R) -> i32 {
        if (sigma - self.sigma).abs() < 1e-6 {
            // Use precomputed CDT
            self.sample_base(rng)
        } else {
            // Fall back to rejection sampling for different sigma
            self.sample_rejection(0.0, sigma, rng)
        }
    }
    
    /// Sample with both custom center and sigma
    pub fn sample_with_center_sigma<R: RngCore>(
        &self,
        center: f64,
        sigma: f64,
        rng: &mut R,
    ) -> i32 {
        // Clamp sigma to valid range
        let sigma = sigma.max(self.sigma_min).min(self.sigma_max);
        
        if (sigma - self.sigma).abs() < 1e-6 {
            // Use efficient CDT-based sampling
            self.sample_with_center(center, rng)
        } else {
            // Use rejection sampling for custom sigma
            self.sample_rejection(center, sigma, rng)
        }
    }
    
    /// Base sampling using CDT
    fn sample_base<R: RngCore>(&self, rng: &mut R) -> i32 {
        // Sample uniform value
        // Use same precision limit as in build_cdt
        let mask = if self.precision >= 53 {
            (1u64 << 53) - 1  // Match the scale used in build_cdt
        } else {
            (1u64 << self.precision) - 1
        };
        let u = rng.next_u64() & mask;
        
        // Binary search in CDT
        let mut left = 0;
        let mut right = self.cdt.len();
        
        while left < right {
            let mid = (left + right) / 2;
            if self.cdt[mid].prob <= u {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        
        // Get the sampled value
        let z = if left > 0 && left <= self.cdt.len() {
            self.cdt[left - 1].z
        } else if left == 0 {
            0
        } else {
            // u is larger than all CDT entries, use the last value
            self.cdt.last().map(|e| e.z).unwrap_or(0)
        };
        
        // Random sign
        if rng.next_u32() & 1 == 0 {
            z
        } else {
            -z
        }
    }
    
    /// Rejection sampling for arbitrary parameters
    fn sample_rejection<R: RngCore>(&self, center: f64, sigma: f64, rng: &mut R) -> i32 {
        // Use rejection sampling with exponential bound
        let max_attempts = 1000;
        
        for _ in 0..max_attempts {
            // Sample from uniform distribution over reasonable range
            let range = (6.0 * sigma).ceil() as i32;
            let z = (rng.next_u32() % (2 * range as u32 + 1)) as i32 - range;
            
            // Compute acceptance probability
            let x = (z as f64 - center) / sigma;
            let log_prob = -0.5 * x * x;
            
            // Accept/reject
            if sample_bernoulli_exp(log_prob, rng) {
                return z;
            }
        }
        
        // Fallback to nearest integer if rejection sampling fails
        center.round() as i32
    }
}

/// Build cumulative distribution table for given sigma
fn build_cdt(sigma: f64, precision: u32) -> Vec<CDTEntry> {
    let mut cdt = Vec::new();
    let max_z = (6.0 * sigma).ceil() as i32;  // Cover 6 sigma
    
    // Use a reasonable scale that won't overflow
    // For precision=64, use 2^53 (max safe integer in f64) instead of f64::MAX
    let scale = if precision >= 53 {
        (1u64 << 53) as f64  // Max safe integer in f64
    } else {
        (1u64 << precision) as f64
    };
    
    // First compute normalization constant (only for positive half + z=0)
    let mut norm_const = 0.0;
    for z in 0..=max_z {
        let x = z as f64 / sigma;
        let weight = if z == 0 { 0.5 } else { 1.0 }; // z=0 is shared between positive and negative
        norm_const += weight * (-0.5 * x * x).exp();
    }
    
    // Now compute cumulative probabilities for z = 0, 1, 2, ...
    let mut prob_sum = 0.0;
    
    for z in 0..=max_z {
        // Compute probability mass at z
        let x = z as f64 / sigma;
        let weight = if z == 0 { 0.5 } else { 1.0 };
        let prob = weight * (-0.5 * x * x).exp() / norm_const;
        prob_sum += prob;
        
        // Scale cumulative probability
        let cumulative_scaled = (prob_sum * scale) as u64;
        
        cdt.push(CDTEntry {
            z,
            prob: cumulative_scaled,
        });
        
        // Stop when we've covered essentially all probability mass
        if prob_sum > 0.999999 {
            break;
        }
    }
    
    // Normalize to ensure we cover the full range
    if let Some(last) = cdt.last_mut() {
        last.prob = if precision >= 64 {
            u64::MAX
        } else {
            (1u64 << precision.min(63)) - 1
        };
    }
    
    cdt
}

/// Sample from Bernoulli distribution with probability exp(log_p)
fn sample_bernoulli_exp<R: RngCore>(log_p: f64, rng: &mut R) -> bool {
    if log_p >= 0.0 {
        return true;
    }
    if log_p < -50.0 {
        return false;
    }
    
    // Use exponential comparison trick
    let threshold = log_p.exp();
    let u = (rng.next_u64() as f64) / (u64::MAX as f64);
    u < threshold
}

/// Precomputed Gaussian sampler for Falcon-512 standard parameters
pub struct FalconGaussianSampler {
    /// Sampler for sigma = 165.7
    standard: GaussianCalibrated,
    /// Sampler for sigma = 1.17*165.7 (used in some cases)
    extended: GaussianCalibrated,
}

impl FalconGaussianSampler {
    /// Create standard Falcon-512 sampler
    pub fn new() -> Self {
        let sigma_standard = 165.7;
        let sigma_extended = 1.17 * sigma_standard;
        
        Self {
            standard: GaussianCalibrated::new(sigma_standard),
            extended: GaussianCalibrated::new(sigma_extended),
        }
    }
    
    /// Sample with standard parameters
    pub fn sample_standard<R: RngCore>(&self, center: f64, rng: &mut R) -> i32 {
        self.standard.sample_with_center(center, rng)
    }
    
    /// Sample with extended parameters
    pub fn sample_extended<R: RngCore>(&self, center: f64, rng: &mut R) -> i32 {
        self.extended.sample_with_center(center, rng)
    }
    
    /// Sample with adaptive sigma based on basis quality
    pub fn sample_adaptive<R: RngCore>(
        &self,
        center: f64,
        quality_factor: f64,
        rng: &mut R,
    ) -> i32 {
        if quality_factor > 1.1 {
            self.sample_extended(center, rng)
        } else {
            self.sample_standard(center, rng)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    
    #[test]
    fn test_gaussian_sampling() {
        let mut rng = StdRng::seed_from_u64(12345);
        let sampler = GaussianCalibrated::new(10.0);
        
        // Sample multiple values
        let mut samples = Vec::new();
        for _ in 0..1000 {
            samples.push(sampler.sample(&mut rng));
        }
        
        // Check that samples are reasonable
        let mean = samples.iter().sum::<i32>() as f64 / samples.len() as f64;
        assert!(mean.abs() < 1.0, "Mean should be close to 0, got {}", mean);
        
        // Check that we get a variety of values
        let unique: std::collections::HashSet<_> = samples.iter().collect();
        assert!(unique.len() > 10, "Should have variety in samples");
    }
    
    #[test]
    fn test_centered_sampling() {
        let mut rng = StdRng::seed_from_u64(67890);
        let sampler = GaussianCalibrated::new(5.0);
        
        // Sample with center at 100
        let mut samples = Vec::new();
        for _ in 0..1000 {
            samples.push(sampler.sample_with_center(100.0, &mut rng));
        }
        
        // Check that samples are centered around 100
        let mean = samples.iter().sum::<i32>() as f64 / samples.len() as f64;
        assert!((mean - 100.0).abs() < 2.0, "Mean should be close to 100, got {}", mean);
    }
    
    #[test]
    fn test_falcon_sampler() {
        let mut rng = StdRng::seed_from_u64(11111);
        let sampler = FalconGaussianSampler::new();
        
        // Test standard sampling
        let s1 = sampler.sample_standard(0.0, &mut rng);
        let s2 = sampler.sample_extended(0.0, &mut rng);
        
        // Both should produce valid samples
        assert!(s1.abs() < 1000);
        assert!(s2.abs() < 1500);
    }
}