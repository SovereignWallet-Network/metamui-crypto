//! Numerical stability management for Falcon-512
//! Handles floating-point precision, error tracking, and fixed-point arithmetic

use alloc::vec::Vec;
use crate::error::{Result, Falcon512Error};

/// Precision parameters for Falcon-512
pub const PRECISION_BITS: u32 = 53;  // Double precision mantissa
pub const FIXED_POINT_BITS: u32 = 32;  // Fixed-point precision
pub const ERROR_THRESHOLD: f64 = 1e-9;  // Maximum acceptable error
pub const NORM_THRESHOLD: f64 = 1e10;  // Maximum norm before overflow concern

/// Numerical stability manager
pub struct NumericalStability {
    precision_bits: u32,
    fixed_point_bits: u32,
    error_threshold: f64,
    accumulated_error: f64,
    error_log: Vec<(String, f64)>,
}

impl NumericalStability {
    /// Create new numerical stability manager
    pub fn new() -> Self {
        Self {
            precision_bits: PRECISION_BITS,
            fixed_point_bits: FIXED_POINT_BITS,
            error_threshold: ERROR_THRESHOLD,
            accumulated_error: 0.0,
            error_log: Vec::new(),
        }
    }
    
    /// Convert floating-point to fixed-point representation
    pub fn to_fixed_point(&self, value: f64) -> i64 {
        let scale = (1i64 << self.fixed_point_bits) as f64;
        (value * scale).round() as i64
    }
    
    /// Convert fixed-point back to floating-point
    pub fn from_fixed_point(&self, value: i64) -> f64 {
        let scale = (1i64 << self.fixed_point_bits) as f64;
        value as f64 / scale
    }
    
    /// Track error from an operation
    pub fn track_error(&mut self, operation: &str, error: f64) -> Result<()> {
        self.accumulated_error += error.abs();
        self.error_log.push((operation.to_string(), error));
        
        if error.abs() > self.error_threshold {
            return Err(Falcon512Error::NumericalInstability);
        }
        
        if self.accumulated_error > 10.0 * self.error_threshold {
            return Err(Falcon512Error::AccumulatedErrorTooLarge);
        }
        
        Ok(())
    }
    
    /// Reset error tracking
    pub fn reset_errors(&mut self) {
        self.accumulated_error = 0.0;
        self.error_log.clear();
    }
    
    /// Get current accumulated error
    pub fn get_accumulated_error(&self) -> f64 {
        self.accumulated_error
    }
    
    /// Kahan summation for improved accuracy
    pub fn kahan_sum(&self, values: &[f64]) -> f64 {
        let mut sum = 0.0;
        let mut c = 0.0;  // Compensation for lost low-order bits
        
        for &value in values {
            let y = value - c;    // Compensate for error
            let t = sum + y;       // New sum
            c = (t - sum) - y;     // New compensation
            sum = t;
        }
        
        sum
    }
    
    /// Neumaier summation (improved Kahan)
    pub fn neumaier_sum(&self, values: &[f64]) -> f64 {
        let mut sum = values[0];
        let mut c = 0.0;  // Compensation
        
        for &value in &values[1..] {
            let t = sum + value;
            if sum.abs() >= value.abs() {
                c += (sum - t) + value;  // If sum is bigger, low-order digits of value are lost
            } else {
                c += (value - t) + sum;  // If value is bigger, low-order digits of sum are lost
            }
            sum = t;
        }
        
        sum + c  // Correction only applied once at the end
    }
    
    /// Pairwise summation for better accuracy with large arrays
    pub fn pairwise_sum(&self, values: &[f64]) -> f64 {
        self.pairwise_sum_recursive(values)
    }
    
    fn pairwise_sum_recursive(&self, values: &[f64]) -> f64 {
        match values.len() {
            0 => 0.0,
            1 => values[0],
            2 => values[0] + values[1],
            n if n <= 128 => {
                // For small arrays, use Kahan summation
                self.kahan_sum(values)
            }
            n => {
                // Split and recurse
                let mid = n / 2;
                let (left, right) = values.split_at(mid);
                self.pairwise_sum_recursive(left) + self.pairwise_sum_recursive(right)
            }
        }
    }
    
    /// Check if a value might cause overflow
    pub fn check_overflow_risk(&self, value: f64) -> bool {
        value.abs() > NORM_THRESHOLD || !value.is_finite()
    }
    
    /// Safe multiplication with overflow checking
    pub fn safe_multiply(&self, a: f64, b: f64) -> Result<f64> {
        let result = a * b;
        
        if !result.is_finite() {
            return Err(Falcon512Error::Overflow);
        }
        
        if self.check_overflow_risk(result) {
            return Err(Falcon512Error::NearOverflow);
        }
        
        Ok(result)
    }
    
    /// Safe division with underflow checking
    pub fn safe_divide(&self, a: f64, b: f64) -> Result<f64> {
        if b.abs() < f64::EPSILON {
            return Err(Falcon512Error::DivisionByZero);
        }
        
        let result = a / b;
        
        if !result.is_finite() {
            return Err(Falcon512Error::Overflow);
        }
        
        Ok(result)
    }
    
    /// Compute norm with overflow protection
    pub fn safe_norm(&self, values: &[f64]) -> Result<f64> {
        // Use scaled computation to avoid overflow
        let max_val = values.iter()
            .map(|x| x.abs())
            .fold(0.0, f64::max);
        
        if max_val < f64::EPSILON {
            return Ok(0.0);
        }
        
        // Scale values to prevent overflow
        let scaled_sum = values.iter()
            .map(|x| {
                let scaled = x / max_val;
                scaled * scaled
            })
            .sum::<f64>();
        
        Ok(max_val * scaled_sum.sqrt())
    }
}

/// Fixed-point arithmetic for critical operations
pub struct FixedPoint {
    bits: u32,
    scale: i64,
}

impl FixedPoint {
    /// Create new fixed-point handler
    pub fn new(bits: u32) -> Self {
        Self {
            bits,
            scale: 1i64 << bits,
        }
    }
    
    /// Convert to fixed-point
    pub fn encode(&self, value: f64) -> i64 {
        (value * self.scale as f64).round() as i64
    }
    
    /// Convert from fixed-point
    pub fn decode(&self, value: i64) -> f64 {
        value as f64 / self.scale as f64
    }
    
    /// Fixed-point multiplication
    pub fn multiply(&self, a: i64, b: i64) -> i64 {
        ((a as i128 * b as i128) >> self.bits) as i64
    }
    
    /// Fixed-point division
    pub fn divide(&self, a: i64, b: i64) -> Result<i64> {
        if b == 0 {
            return Err(Falcon512Error::DivisionByZero);
        }
        
        let scaled_a = (a as i128) << self.bits;
        Ok((scaled_a / b as i128) as i64)
    }
    
    /// Fixed-point square root using Newton's method
    pub fn sqrt(&self, x: i64) -> i64 {
        if x <= 0 {
            return 0;
        }
        
        // Initial guess
        let mut guess = x;
        let mut prev_guess = 0;
        
        // Newton iterations
        while (guess - prev_guess).abs() > 1 {
            prev_guess = guess;
            guess = (guess + self.divide(x, guess).unwrap_or(guess)) / 2;
        }
        
        guess
    }
}

/// Error bound tracker for complex operations
pub struct ErrorBoundTracker {
    operations: Vec<String>,
    bounds: Vec<f64>,
    total_bound: f64,
}

impl ErrorBoundTracker {
    /// Create new error bound tracker
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
            bounds: Vec::new(),
            total_bound: 0.0,
        }
    }
    
    /// Add operation with error bound
    pub fn add_operation(&mut self, op: &str, bound: f64) {
        self.operations.push(op.to_string());
        self.bounds.push(bound);
        self.total_bound += bound;
    }
    
    /// Check if total error is acceptable
    pub fn is_acceptable(&self, threshold: f64) -> bool {
        self.total_bound <= threshold
    }
    
    /// Get total error bound
    pub fn get_total_bound(&self) -> f64 {
        self.total_bound
    }
    
    /// Reset tracker
    pub fn reset(&mut self) {
        self.operations.clear();
        self.bounds.clear();
        self.total_bound = 0.0;
    }
}

/// Condition number estimator for matrices
pub struct ConditionNumberEstimator {
    n: usize,
}

impl ConditionNumberEstimator {
    /// Create new condition number estimator
    pub fn new(n: usize) -> Self {
        Self { n }
    }
    
    /// Estimate condition number of a 2x2 matrix
    pub fn estimate_2x2(&self, a: [[f64; 2]; 2]) -> f64 {
        let [[a11, a12], [a21, a22]] = a;
        
        // Compute determinant
        let det = a11 * a22 - a12 * a21;
        
        if det.abs() < f64::EPSILON {
            return f64::INFINITY;
        }
        
        // Compute norms
        let norm1 = (a11.abs() + a21.abs()).max(a12.abs() + a22.abs());
        let norm_inf = (a11.abs() + a12.abs()).max(a21.abs() + a22.abs());
        
        // Inverse matrix elements
        let inv_a11 = a22 / det;
        let inv_a12 = -a12 / det;
        let inv_a21 = -a21 / det;
        let inv_a22 = a11 / det;
        
        // Norms of inverse
        let inv_norm1 = (inv_a11.abs() + inv_a21.abs()).max(inv_a12.abs() + inv_a22.abs());
        let inv_norm_inf = (inv_a11.abs() + inv_a12.abs()).max(inv_a21.abs() + inv_a22.abs());
        
        // Condition number (using 1-norm)
        norm1 * inv_norm1
    }
    
    /// Check if matrix is well-conditioned
    pub fn is_well_conditioned(&self, cond: f64) -> bool {
        cond < 1e10  // Threshold for well-conditioned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fixed_point_arithmetic() {
        let fp = FixedPoint::new(16);
        
        // Test encoding/decoding
        let value = 3.14159;
        let encoded = fp.encode(value);
        let decoded = fp.decode(encoded);
        assert!((decoded - value).abs() < 0.0001);
        
        // Test multiplication
        let a = fp.encode(2.5);
        let b = fp.encode(3.0);
        let product = fp.multiply(a, b);
        let result = fp.decode(product);
        assert!((result - 7.5).abs() < 0.01);
        
        // Test division
        let quotient = fp.divide(a, b).unwrap();
        let result = fp.decode(quotient);
        assert!((result - 0.8333).abs() < 0.01);
    }
    
    #[test]
    fn test_kahan_summation() {
        let ns = NumericalStability::new();
        
        // Test with values that would lose precision in naive summation
        let values = vec![1e10, 1.0, -1e10, 2.0];
        let sum = ns.kahan_sum(&values);
        assert!((sum - 3.0).abs() < f64::EPSILON);
        
        // Compare with naive sum
        let naive_sum: f64 = values.iter().sum();
        // Naive sum might not be exactly 3.0 due to floating-point errors
        assert!((sum - 3.0).abs() <= (naive_sum - 3.0).abs());
    }
    
    #[test]
    fn test_neumaier_summation() {
        let ns = NumericalStability::new();
        
        let values = vec![1e20, 1.0, 2.0, -1e20, 3.0];
        let sum = ns.neumaier_sum(&values);
        assert!((sum - 6.0).abs() < 1e-10);
    }
    
    #[test]
    fn test_error_tracking() {
        let mut ns = NumericalStability::new();
        
        // Track small errors
        ns.track_error("operation1", 1e-12).unwrap();
        ns.track_error("operation2", 1e-11).unwrap();
        
        assert!(ns.get_accumulated_error() < 1e-10);
        
        // Reset and track large error
        ns.reset_errors();
        let result = ns.track_error("bad_operation", 1e-6);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_safe_operations() {
        let ns = NumericalStability::new();
        
        // Test safe multiplication
        let result = ns.safe_multiply(1e100, 1e100);
        assert!(result.is_err());  // Would overflow
        
        let result = ns.safe_multiply(2.0, 3.0);
        assert_eq!(result.unwrap(), 6.0);
        
        // Test safe division
        let result = ns.safe_divide(1.0, 0.0);
        assert!(result.is_err());
        
        let result = ns.safe_divide(6.0, 2.0);
        assert_eq!(result.unwrap(), 3.0);
        
        // Test safe norm
        let values = vec![3.0, 4.0];
        let norm = ns.safe_norm(&values).unwrap();
        assert!((norm - 5.0).abs() < f64::EPSILON);
    }
    
    #[test]
    fn test_condition_number() {
        let cne = ConditionNumberEstimator::new(2);
        
        // Well-conditioned matrix
        let good_matrix = [[2.0, 1.0], [1.0, 2.0]];
        let cond = cne.estimate_2x2(good_matrix);
        assert!(cne.is_well_conditioned(cond));
        
        // Ill-conditioned matrix - more extreme example
        let bad_matrix = [[1e10, 1e10], [1e10, 1e10 + 1.0]];
        let cond = cne.estimate_2x2(bad_matrix);
        println!("Condition number of ill-conditioned matrix: {}", cond);
        // For nearly singular matrices, condition number should be very large
        assert!(cond > 1e8, "Nearly singular matrix should have large condition number");
    }
}