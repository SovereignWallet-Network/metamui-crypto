//! Polynomial Extended GCD for Cyclotomic Rings
//! 
//! This implements the polynomial extended GCD algorithm specifically for
//! the ring Z[X]/(X^n + 1) used in Falcon-512. The key challenge is handling
//! the cyclotomic structure properly to avoid infinite loops.

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use crate::falcon_reference::extended_precision::extended_dot_product;
use alloc::vec::Vec;

/// Polynomial in the ring Z[X]/(X^n + 1)
#[derive(Clone, Debug)]
pub struct CyclotomicPoly {
    /// Coefficients of the polynomial
    pub coeffs: Vec<i32>,
    /// Degree of the cyclotomic polynomial (n such that X^n + 1)
    pub n: usize,
}

impl CyclotomicPoly {
    /// Create a new cyclotomic polynomial
    pub fn new(coeffs: Vec<i32>, n: usize) -> Self {
        let mut poly = Self { coeffs, n };
        poly.reduce();
        poly
    }
    
    /// Create zero polynomial
    pub fn zero(n: usize) -> Self {
        Self {
            coeffs: vec![0; n],
            n,
        }
    }
    
    /// Create unit polynomial (1)
    pub fn one(n: usize) -> Self {
        let mut coeffs = vec![0; n];
        coeffs[0] = 1;
        Self { coeffs, n }
    }
    
    /// Get the degree of the polynomial (highest non-zero coefficient)
    pub fn degree(&self) -> usize {
        for i in (0..self.coeffs.len()).rev() {
            if self.coeffs[i] != 0 {
                return i;
            }
        }
        0
    }
    
    /// Check if polynomial is zero
    pub fn is_zero(&self) -> bool {
        self.coeffs.iter().all(|&c| c == 0)
    }
    
    /// Check if polynomial is constant
    pub fn is_constant(&self) -> bool {
        self.degree() == 0
    }
    
    /// Get the leading coefficient
    pub fn leading_coeff(&self) -> i32 {
        let deg = self.degree();
        if deg < self.coeffs.len() {
            self.coeffs[deg]
        } else {
            0
        }
    }
    
    /// Reduce polynomial modulo X^n + 1
    pub fn reduce(&mut self) {
        // Handle coefficients beyond n
        while self.coeffs.len() > self.n {
            let excess = self.coeffs.len() - self.n;
            for i in 0..excess {
                if self.coeffs.len() > self.n + i {
                    // X^(n+i) = -X^i in Z[X]/(X^n + 1)
                    let val = self.coeffs[self.n + i];
                    self.coeffs[i] -= val;
                }
            }
            self.coeffs.truncate(self.n);
        }
        
        // Ensure we have exactly n coefficients
        while self.coeffs.len() < self.n {
            self.coeffs.push(0);
        }
    }
    
    /// Add two polynomials
    pub fn add(&self, other: &Self) -> Self {
        let mut result = vec![0i32; self.n];
        for i in 0..self.n {
            result[i] = self.coeffs[i] + other.coeffs[i];
        }
        Self::new(result, self.n)
    }
    
    /// Subtract two polynomials
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = vec![0i32; self.n];
        for i in 0..self.n {
            result[i] = self.coeffs[i] - other.coeffs[i];
        }
        Self::new(result, self.n)
    }
    
    /// Multiply two polynomials in Z[X]/(X^n + 1)
    pub fn mul(&self, other: &Self) -> Self {
        let mut result = vec![0i64; 2 * self.n];
        
        // Standard polynomial multiplication
        for i in 0..self.n {
            for j in 0..self.n {
                result[i + j] += self.coeffs[i] as i64 * other.coeffs[j] as i64;
            }
        }
        
        // Reduce modulo X^n + 1
        // X^n = -1, so X^(n+k) = -X^k
        for i in self.n..result.len() {
            if result[i] != 0 {
                result[i - self.n] -= result[i];
            }
        }
        
        // Convert back to i32
        let mut coeffs = vec![0i32; self.n];
        for i in 0..self.n {
            coeffs[i] = result[i] as i32;
        }
        
        Self::new(coeffs, self.n)
    }
    
    /// Divide with remainder (for use in XGCD)
    /// Returns (quotient, remainder)
    pub fn div_rem(&self, divisor: &Self) -> Result<(Self, Self)> {
        if divisor.is_zero() {
            return Err(Falcon512Error::DivisionByZero);
        }
        
        let mut remainder = self.clone();
        let mut quotient = Self::zero(self.n);
        
        let divisor_deg = divisor.degree();
        let divisor_lc = divisor.leading_coeff();
        
        if divisor_lc == 0 {
            return Err(Falcon512Error::DivisionByZero);
        }
        
        // Polynomial long division
        while !remainder.is_zero() && remainder.degree() >= divisor_deg {
            let rem_deg = remainder.degree();
            let rem_lc = remainder.leading_coeff();
            
            // Compute quotient coefficient
            let q_coeff = rem_lc / divisor_lc;
            if q_coeff == 0 {
                break;
            }
            
            let deg_diff = rem_deg - divisor_deg;
            quotient.coeffs[deg_diff] += q_coeff;
            
            // Subtract q_coeff * X^deg_diff * divisor from remainder
            for i in 0..=divisor_deg {
                let idx = i + deg_diff;
                if idx < self.n {
                    remainder.coeffs[idx] -= q_coeff * divisor.coeffs[i];
                } else {
                    // Handle wrap-around due to X^n = -1
                    remainder.coeffs[idx - self.n] += q_coeff * divisor.coeffs[i];
                }
            }
            
            remainder.reduce();
        }
        
        Ok((quotient, remainder))
    }
}

/// Extended GCD for polynomials in Z[X]/(X^n + 1)
/// Returns (gcd, u, v) such that a*u + b*v = gcd
pub fn polynomial_xgcd_cyclotomic(
    a: &[i16],
    b: &[i16],
    n: usize
) -> Result<(Vec<i16>, Vec<i16>, Vec<i16>)> {
    // Convert to cyclotomic polynomials
    let a_coeffs: Vec<i32> = a.iter().map(|&x| x as i32).collect();
    let b_coeffs: Vec<i32> = b.iter().map(|&x| x as i32).collect();
    
    let mut r0 = CyclotomicPoly::new(a_coeffs, n);
    let mut r1 = CyclotomicPoly::new(b_coeffs, n);
    let mut u0 = CyclotomicPoly::one(n);
    let mut u1 = CyclotomicPoly::zero(n);
    let mut v0 = CyclotomicPoly::zero(n);
    let mut v1 = CyclotomicPoly::one(n);
    
    // Iteration counter to prevent infinite loops
    let mut iterations = 0;
    const MAX_ITERATIONS: usize = 1000;
    
    // Extended Euclidean algorithm
    while !r1.is_zero() && iterations < MAX_ITERATIONS {
        // Compute quotient and remainder
        let (q, r) = match r0.div_rem(&r1) {
            Ok(result) => result,
            Err(_) => break,
        };
        
        // Update sequences
        let new_u = u0.sub(&q.mul(&u1));
        let new_v = v0.sub(&q.mul(&v1));
        
        r0 = r1;
        r1 = r;
        u0 = u1;
        u1 = new_u;
        v0 = v1;
        v1 = new_v;
        
        iterations += 1;
    }
    
    if iterations >= MAX_ITERATIONS {
        return Err(Falcon512Error::XGCDTimeout);
    }
    
    // Convert back to i16
    let gcd: Vec<i16> = r0.coeffs.iter().map(|&x| x as i16).collect();
    let u: Vec<i16> = u0.coeffs.iter().map(|&x| x as i16).collect();
    let v: Vec<i16> = v0.coeffs.iter().map(|&x| x as i16).collect();
    
    Ok((gcd, u, v))
}

/// Solve NTRU equation f*G - g*F = q using polynomial XGCD
pub fn solve_ntru_xgcd(f: &[i16], g: &[i16]) -> Result<(Vec<i16>, Vec<i16>)> {
    // Use XGCD to find initial F, G
    let (gcd, mut big_g, mut big_f) = polynomial_xgcd_cyclotomic(f, g, N)?;
    
    // Check if gcd is close to a constant
    let gcd_poly = CyclotomicPoly::new(
        gcd.iter().map(|&x| x as i32).collect(),
        N
    );
    
    if !gcd_poly.is_constant() {
        return Err(Falcon512Error::NotCoprime);
    }
    
    // Scale to get f*G - g*F = q
    let gcd_const = gcd_poly.coeffs[0];
    if gcd_const == 0 {
        return Err(Falcon512Error::InvalidParameter);
    }
    
    let scale = Q as i32 / gcd_const;
    
    // Scale F and G
    for i in 0..N {
        big_f[i] = ((big_f[i] as i32 * scale) % Q as i32) as i16;
        big_g[i] = ((big_g[i] as i32 * scale) % Q as i32) as i16;
    }
    
    // Apply reduction to minimize norms
    reduce_ntru_solution(f, g, &mut big_f, &mut big_g);
    
    Ok((big_f, big_g))
}

/// Reduce NTRU solution to minimize norms using extended precision
fn reduce_ntru_solution(f: &[i16], g: &[i16], big_f: &mut [i16], big_g: &mut [i16]) {
    // Babai's nearest plane algorithm with extended precision
    // Convert to f64 for precise calculations
    let f_f64: Vec<f64> = f.iter().map(|&x| x as f64).collect();
    let g_f64: Vec<f64> = g.iter().map(|&x| x as f64).collect();
    
    // Compute norms with extended precision
    let norm_f = extended_dot_product(&f_f64, &f_f64);
    let norm_g = extended_dot_product(&g_f64, &g_f64);
    
    if norm_f == 0.0 || norm_g == 0.0 {
        return;
    }
    
    for _ in 0..100 {
        // Convert current big_f, big_g to f64
        let big_f_f64: Vec<f64> = big_f.iter().map(|&x| x as f64).collect();
        let big_g_f64: Vec<f64> = big_g.iter().map(|&x| x as f64).collect();
        
        // Compute projections with extended precision
        let proj_f = extended_dot_product(&f_f64, &big_f_f64);
        let proj_g = extended_dot_product(&g_f64, &big_g_f64);
        
        // Compute reduction coefficients with extended precision
        let k_f = (proj_f / norm_f).round() as i32;
        let k_g = (proj_g / norm_g).round() as i32;
        
        if k_f == 0 && k_g == 0 {
            break;
        }
        
        // Apply reduction
        for i in 0..N {
            big_f[i] = (big_f[i] as i32 - k_f * f[i] as i32) as i16;
            big_g[i] = (big_g[i] as i32 - k_g * g[i] as i32) as i16;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cyclotomic_poly_basic() {
        let poly = CyclotomicPoly::new(vec![1, 2, 3, 4], 4);
        assert_eq!(poly.degree(), 3);
        assert!(!poly.is_zero());
        assert!(!poly.is_constant());
    }
    
    #[test]
    fn test_cyclotomic_reduction() {
        // Test that X^4 = -1 in Z[X]/(X^4 + 1)
        let mut poly = CyclotomicPoly::new(vec![0, 0, 0, 0, 1], 4);
        poly.reduce();
        // X^4 should become -1
        assert_eq!(poly.coeffs[0], -1);
        assert_eq!(poly.coeffs[1], 0);
        assert_eq!(poly.coeffs[2], 0);
        assert_eq!(poly.coeffs[3], 0);
    }
    
    #[test]
    fn test_cyclotomic_mul() {
        // Test (1 + X) * (1 - X) = 1 - X^2
        let a = CyclotomicPoly::new(vec![1, 1, 0, 0], 4);
        let b = CyclotomicPoly::new(vec![1, -1, 0, 0], 4);
        let c = a.mul(&b);
        
        assert_eq!(c.coeffs[0], 1);
        assert_eq!(c.coeffs[1], 0);
        assert_eq!(c.coeffs[2], -1);
        assert_eq!(c.coeffs[3], 0);
    }
    
    #[test]
    fn test_polynomial_xgcd() {
        // Simple test with small polynomials
        let f = vec![1i16, 0, 0, 0];  // f = 1
        let g = vec![0i16, 1, 0, 0];  // g = X
        
        match polynomial_xgcd_cyclotomic(&f, &g, 4) {
            Ok((gcd, u, v)) => {
                // gcd(1, X) = 1
                assert!(gcd[0] != 0);
                for i in 1..4 {
                    assert_eq!(gcd[i], 0);
                }
            }
            Err(e) => panic!("XGCD failed: {:?}", e),
        }
    }
}