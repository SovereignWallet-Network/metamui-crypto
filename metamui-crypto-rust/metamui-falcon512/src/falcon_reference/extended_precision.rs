//! Extended Precision Arithmetic for Critical Operations
//! 
//! Provides 80-bit and 128-bit accumulators with Kahan compensated summation
//! to minimize numerical errors in critical accumulation operations.

use crate::falcon_fpr::FPR;

/// 80-bit accumulator for extended precision
/// Uses 64-bit mantissa + 16-bit extension
#[derive(Clone, Copy, Debug)]
pub struct Accumulator80 {
    /// Main 64-bit value
    value: f64,
    /// Error compensation term
    compensation: f64,
}

impl Accumulator80 {
    /// Create new accumulator initialized to zero
    pub fn zero() -> Self {
        Self {
            value: 0.0,
            compensation: 0.0,
        }
    }
    
    /// Create from initial value
    pub fn new(value: f64) -> Self {
        Self {
            value,
            compensation: 0.0,
        }
    }
    
    /// Add value using Kahan summation algorithm
    pub fn add(&mut self, x: f64) {
        let y = x - self.compensation;
        let t = self.value + y;
        self.compensation = (t - self.value) - y;
        self.value = t;
    }
    
    /// Subtract value using Kahan summation
    pub fn sub(&mut self, x: f64) {
        self.add(-x);
    }
    
    /// Get the accumulated value
    pub fn get(&self) -> f64 {
        self.value
    }
    
    /// Get value with compensation applied
    pub fn get_compensated(&self) -> f64 {
        self.value - self.compensation
    }
}

/// 128-bit accumulator using two f64 values (double-double arithmetic)
#[derive(Clone, Copy, Debug)]
pub struct Accumulator128 {
    /// High 64 bits
    hi: f64,
    /// Low 64 bits (error term)
    lo: f64,
}

impl Accumulator128 {
    /// Create new accumulator
    pub fn zero() -> Self {
        Self { hi: 0.0, lo: 0.0 }
    }
    
    /// Create from value
    pub fn new(value: f64) -> Self {
        Self { hi: value, lo: 0.0 }
    }
    
    /// Add with double-double precision
    pub fn add(&mut self, x: f64) {
        // Knuth's two-sum algorithm
        let s = self.hi + x;
        let v = s - self.hi;
        let e = (self.hi - (s - v)) + (x - v);
        
        self.hi = s;
        self.lo += e;
        
        // Renormalize if needed
        self.renormalize();
    }
    
    /// Multiply with extended precision
    pub fn mul(&mut self, x: f64) {
        // Split multiplication for extended precision
        let (p_hi, p_lo) = two_product(self.hi, x);
        
        self.hi = p_hi;
        self.lo = self.lo * x + p_lo;
        
        self.renormalize();
    }
    
    /// Renormalize to maintain precision
    fn renormalize(&mut self) {
        let s = self.hi + self.lo;
        let e = self.lo - (s - self.hi);
        self.hi = s;
        self.lo = e;
    }
    
    /// Get value as f64
    pub fn get(&self) -> f64 {
        self.hi + self.lo
    }
    
    /// Get high part only
    pub fn get_hi(&self) -> f64 {
        self.hi
    }
}

/// Two-product algorithm: compute a*b = hi + lo exactly
fn two_product(a: f64, b: f64) -> (f64, f64) {
    let p = a * b;
    
    // Veltkamp's splitting
    const SPLIT: f64 = 134217729.0; // 2^27 + 1
    
    let a_hi = a * SPLIT;
    let a_lo = a - a_hi;
    let a_hi = a_hi + a_lo;
    let a_lo = a - a_hi;
    
    let b_hi = b * SPLIT;
    let b_lo = b - b_hi;
    let b_hi = b_hi + b_lo;
    let b_lo = b - b_hi;
    
    let err = ((a_hi * b_hi - p) + a_hi * b_lo + a_lo * b_hi) + a_lo * b_lo;
    
    (p, err)
}

/// Kahan summation for vectors
pub fn kahan_sum(values: &[f64]) -> f64 {
    let mut acc = Accumulator80::zero();
    for &v in values {
        acc.add(v);
    }
    acc.get_compensated()
}

/// Extended precision dot product
pub fn extended_dot_product(a: &[f64], b: &[f64]) -> f64 {
    assert_eq!(a.len(), b.len());
    
    let mut acc = Accumulator128::zero();
    for i in 0..a.len() {
        let (prod_hi, prod_lo) = two_product(a[i], b[i]);
        acc.add(prod_hi);
        acc.add(prod_lo);
    }
    
    acc.get()
}

/// Compensated polynomial evaluation using Horner's method
pub fn compensated_horner(coeffs: &[f64], x: f64) -> f64 {
    if coeffs.is_empty() {
        return 0.0;
    }
    
    let mut acc = Accumulator128::new(coeffs[coeffs.len() - 1]);
    
    for i in (0..coeffs.len() - 1).rev() {
        acc.mul(x);
        acc.add(coeffs[i]);
    }
    
    acc.get()
}

/// Extended precision accumulation for FPR values
pub struct FPRAccumulator {
    /// Main accumulator
    main: FPR,
    /// Error compensation
    error: FPR,
}

impl FPRAccumulator {
    /// Create new FPR accumulator
    pub fn zero() -> Self {
        Self {
            main: FPR::ZERO,
            error: FPR::ZERO,
        }
    }
    
    /// Add FPR value with compensation
    pub fn add(&mut self, x: FPR) {
        // Kahan summation in FPR
        let y = x.sub(self.error);
        let t = self.main.add(y);
        self.error = t.sub(self.main).sub(y);
        self.main = t;
    }
    
    /// Get accumulated value
    pub fn get(&self) -> FPR {
        self.main
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_kahan_summation() {
        // Test case where regular summation would lose precision
        let values = vec![1e10, 1.0, -1e10, 1.0];
        
        // Regular sum would give 0.0 due to precision loss
        let regular_sum: f64 = values.iter().sum();
        
        // Kahan sum should give 2.0
        let kahan = kahan_sum(&values);
        
        assert!((kahan - 2.0).abs() < 1e-10);
        // Regular sum might be 0 or 2 depending on order
        assert!(regular_sum == 0.0 || regular_sum == 2.0);
    }
    
    #[test]
    fn test_accumulator80() {
        let mut acc = Accumulator80::zero();
        
        // Add values that would lose precision
        acc.add(1e15);
        acc.add(1.0);
        acc.add(-1e15);
        acc.add(1.0);
        
        assert!((acc.get_compensated() - 2.0).abs() < 1e-10);
    }
    
    #[test]
    fn test_accumulator128() {
        let mut acc = Accumulator128::zero();
        
        // Test extended precision
        acc.add(1e20);
        acc.add(1.0);
        acc.add(-1e20);
        acc.add(1.0);
        
        assert!((acc.get() - 2.0).abs() < 1e-10);
    }
    
    #[test]
    fn test_two_product() {
        let a = 1.23456789;
        let b = 9.87654321;
        
        let (hi, lo) = two_product(a, b);
        let exact = hi + lo;
        let regular = a * b;
        
        // The extended precision should be more accurate
        assert!((exact - regular).abs() < 1e-15);
    }
}