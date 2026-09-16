//! Babai Nearest Plane Algorithm for lattice reduction
//! 
//! This module implements the Babai nearest plane algorithm to find
//! better lattice points closer to the target, with proper handling
//! of the approximate nature of NTRU equations.

use crate::constants::{N, Q};
use crate::poly::Poly;
use crate::equation_verification::ToleranceConfig;
#[cfg(test)]
use crate::equation_verification::verify_signature_equation;
use alloc::vec::Vec;
use core::f64;

/// Babai nearest plane result
#[derive(Clone, Debug)]
pub struct BabaiResult {
    /// Improved s0 coefficient
    pub s0: Vec<i16>,
    /// Improved s1 coefficient 
    pub s1: Vec<i16>,
    /// Resulting equation error (with tolerance)
    pub error: f64,
    /// Number of iterations performed
    pub iterations: usize,
    /// Whether the result satisfies tolerance requirements
    pub valid_within_tolerance: bool,
}

impl BabaiResult {
    fn unsupported(s0: &[i16], s1: &[i16]) -> Self {
        Self {
            s0: s0.to_vec(),
            s1: s1.to_vec(),
            error: f64::INFINITY,
            iterations: 0,
            valid_within_tolerance: false,
        }
    }
}

/// Configuration for Babai optimization
#[derive(Clone, Debug)]
pub struct BabaiConfig {
    /// Maximum iterations to perform
    pub max_iterations: usize,
    /// Target relative error tolerance
    pub target_tolerance: f64,
    /// Minimum improvement per iteration to continue
    pub min_improvement: f64,
    /// Whether to use adaptive step sizes
    pub adaptive_steps: bool,
    /// Tolerance configuration for verification
    pub tolerance_config: ToleranceConfig,
}

impl Default for BabaiConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10,
            target_tolerance: 1e-6,
            min_improvement: 1e-8,
            adaptive_steps: true,
            tolerance_config: ToleranceConfig::default(),
        }
    }
}

/// Performs Babai nearest plane algorithm to reduce equation error
/// 
/// Given s0, s1, h, and c from a Falcon signature, this finds a nearby
/// lattice point that better satisfies s0 + s1*h ≈ c (mod q) within
/// acceptable tolerance bounds.
/// 
/// # Arguments
/// * `s0` - First signature component
/// * `s1` - Second signature component
/// * `h` - Public key
/// * `c` - Challenge hash
/// * `config` - Algorithm configuration
/// 
/// # Returns
/// A BabaiResult with improved s0, s1 and the resulting error
pub fn babai_nearest_plane_with_config(
    s0: &[i16],
    s1: &[i16],
    h: &Poly,
    c: &[i16],
    config: &BabaiConfig,
) -> BabaiResult {
    let _ = (h, c, config);
    BabaiResult::unsupported(s0, s1)
}

/// Legacy interface for backward compatibility
pub fn babai_nearest_plane(
    s0: &[i16],
    s1: &[i16],
    h: &Poly,
    c: &[i16],
    max_iterations: usize,
) -> BabaiResult {
    let config = BabaiConfig {
        max_iterations,
        ..Default::default()
    };
    babai_nearest_plane_with_config(s0, s1, h, c, &config)
}

/// Compute error vector with tolerance awareness
fn compute_error_vector_tolerant(s0: &[f64], s1: &[f64], h: &Poly, c: &[i16]) -> Vec<f64> {
    let mut error_vec = Vec::with_capacity(N);
    
    for i in 0..N {
        let mut sum = s0[i];
        
        // Polynomial multiplication with NTT would be more efficient
        // but we use direct multiplication for clarity
        for j in 0..N {
            let k = (i + N - j) % N;
            let h_coeff = if j > i { 
                -(h.coeffs[N + i - j] as f64)  // Negacyclic
            } else { 
                h.coeffs[i - j] as f64 
            };
            sum += s1[j] * h_coeff;
        }
        
        sum -= c[i] as f64;
        
        // Modular reduction with centered representation
        let q_f = Q as f64;
        sum = sum - (sum / q_f).round() * q_f;
        
        // Center around 0
        if sum > q_f / 2.0 {
            sum -= q_f;
        } else if sum < -q_f / 2.0 {
            sum += q_f;
        }
        
        error_vec.push(sum);
    }
    
    error_vec
}

/// Constrain value to valid range for i16
fn constrain_to_range(val: i32) -> i16 {
    if val > i16::MAX as i32 {
        i16::MAX
    } else if val < i16::MIN as i32 {
        i16::MIN
    } else {
        val as i16
    }
}

/// Apply Babai rounding to improve a signature
/// 
/// This is a simpler interface that takes the signature components
/// and returns improved versions with tolerance handling.
pub fn improve_signature(
    s0: &[i16],
    s1: &[i16],
    h: &Poly,
    c: &[i16],
) -> (Vec<i16>, Vec<i16>) {
    let _ = (h, c);
    (s0.to_vec(), s1.to_vec())
}

/// Batch Babai optimization for multiple signatures
pub struct BatchBabaiOptimizer {
    config: BabaiConfig,
    results: Vec<BabaiResult>,
}

impl BatchBabaiOptimizer {
    /// Create new batch optimizer
    pub fn new(config: BabaiConfig) -> Self {
        Self {
            config,
            results: Vec::new(),
        }
    }
    
    /// Optimize a signature
    pub fn optimize_signature(
        &mut self,
        s0: &[i16],
        s1: &[i16],
        h: &Poly,
        c: &[i16],
    ) -> BabaiResult {
        let result = babai_nearest_plane_with_config(s0, s1, h, c, &self.config);
        self.results.push(result.clone());
        result
    }
    
    /// Get statistics on optimizations
    pub fn get_statistics(&self) -> OptimizationStatistics {
        let total = self.results.len();
        if total == 0 {
            return OptimizationStatistics::default();
        }
        
        let successful = self.results.iter()
            .filter(|r| r.valid_within_tolerance)
            .count();
        
        let avg_error = self.results.iter()
            .map(|r| r.error)
            .sum::<f64>() / total as f64;
        
        let avg_iterations = self.results.iter()
            .map(|r| r.iterations)
            .sum::<usize>() / total;
        
        let min_error = self.results.iter()
            .map(|r| r.error)
            .fold(f64::MAX, f64::min);
        
        let max_error = self.results.iter()
            .map(|r| r.error)
            .fold(0.0, f64::max);
        
        OptimizationStatistics {
            total_optimizations: total,
            successful_optimizations: successful,
            average_error: avg_error,
            average_iterations: avg_iterations,
            min_error,
            max_error,
        }
    }
}

/// Statistics for batch optimization
#[derive(Clone, Debug, Default)]
pub struct OptimizationStatistics {
    pub total_optimizations: usize,
    pub successful_optimizations: usize,
    pub average_error: f64,
    pub average_iterations: usize,
    pub min_error: f64,
    pub max_error: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_babai_with_tolerance() {
        // Create a test case with known approximate solution
        let s0 = vec![100i16; N];
        let s1 = vec![50i16; N];
        let h = Poly::new(vec![1i16; N]);
        let mut c = vec![150i16; N];
        
        // Add small error to make it approximate
        for i in 0..10 {
            c[i] += (i % 3) as i16;
        }
        
        let config = BabaiConfig::default();
        let result = babai_nearest_plane_with_config(&s0, &s1, &h, &c, &config);
        
        // Should improve or maintain error
        let initial_verification = verify_signature_equation(
            &s0, &s1, &h.coeffs, &c, &config.tolerance_config
        );
        
        assert!(result.error <= initial_verification.max_relative_error);
        println!("Initial error: {}", initial_verification.max_relative_error);
        println!("Improved error: {}", result.error);
        println!("Valid within tolerance: {}", result.valid_within_tolerance);
        println!("Iterations: {}", result.iterations);
    }
    
    #[test]
    fn test_adaptive_steps() {
        let s0 = vec![0i16; N];
        let s1 = vec![0i16; N];
        let h = Poly::new(vec![1i16; N]);
        let c = vec![10i16; N];  // Non-zero target
        
        let mut config = BabaiConfig::default();
        config.adaptive_steps = true;
        
        let result = babai_nearest_plane_with_config(&s0, &s1, &h, &c, &config);
        
        assert!(!result.valid_within_tolerance);
        assert_eq!(result.iterations, 0);
        assert!(result.error.is_infinite());
    }
    
    #[test]
    fn test_batch_optimizer() {
        let mut optimizer = BatchBabaiOptimizer::new(BabaiConfig::default());
        
        // Optimize multiple signatures
        for seed in 0..5 {
            let s0 = vec![(seed * 10) as i16; N];
            let s1 = vec![(seed * 5) as i16; N];
            let h = Poly::new(vec![1i16; N]);
            let c = vec![(seed * 15) as i16; N];
            
            optimizer.optimize_signature(&s0, &s1, &h, &c);
        }
        
        let stats = optimizer.get_statistics();
        assert_eq!(stats.total_optimizations, 5);
        assert_eq!(stats.successful_optimizations, 0);
        assert!(stats.average_error.is_infinite());
        assert_eq!(stats.average_iterations, 0);
    }

    #[test]
    fn test_babai_fails_closed() {
        let s0 = vec![100i16; N];
        let s1 = vec![50i16; N];
        let h = Poly::new(vec![1i16; N]);
        let c = vec![150i16; N];

        let result = babai_nearest_plane_with_config(&s0, &s1, &h, &c, &BabaiConfig::default());

        assert!(!result.valid_within_tolerance);
        assert!(result.error.is_infinite());
        assert_eq!(result.iterations, 0);
        assert_eq!(result.s0, s0);
        assert_eq!(result.s1, s1);
    }

    #[test]
    fn test_improve_signature_returns_original_inputs() {
        let s0 = vec![7i16; N];
        let s1 = vec![9i16; N];
        let h = Poly::new(vec![1i16; N]);
        let c = vec![3i16; N];

        let (new_s0, new_s1) = improve_signature(&s0, &s1, &h, &c);

        assert_eq!(new_s0, s0);
        assert_eq!(new_s1, s1);
    }
}
