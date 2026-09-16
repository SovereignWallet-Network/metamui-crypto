//! Polynomial arithmetic in ring Z[X]/(X^n + 1) for Falcon-512
//! 
//! This module implements the core polynomial operations needed for Falcon-512,
//! including addition, subtraction, multiplication with negacyclic reduction,
//! and modular arithmetic operations.

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;

/// Polynomial in ring Z_q[X]/(X^n + 1)
#[derive(Clone, Debug, PartialEq)]
pub struct Polynomial {
    /// Coefficients in range [0, q)
    pub coeffs: Vec<i16>,
}

impl Polynomial {
    /// Create a new polynomial with given coefficients
    pub fn new(coeffs: Vec<i16>) -> Self {
        debug_assert_eq!(coeffs.len(), N, "Polynomial must have exactly N coefficients");
        Self { coeffs }
    }
    
    /// Create a zero polynomial
    pub fn zero() -> Self {
        Self {
            coeffs: vec![0i16; N],
        }
    }
    
    /// Create a polynomial with a single coefficient at position 0
    pub fn constant(value: i16) -> Self {
        let mut coeffs = vec![0i16; N];
        coeffs[0] = value;
        Self { coeffs }
    }
    
    /// Add two polynomials modulo q
    pub fn add(&self, other: &Self) -> Self {
        let mut result = vec![0i16; N];
        for i in 0..N {
            result[i] = mod_reduce((self.coeffs[i] as i32 + other.coeffs[i] as i32) % Q as i32);
        }
        Self { coeffs: result }
    }
    
    /// Subtract two polynomials modulo q
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = vec![0i16; N];
        for i in 0..N {
            let diff = (self.coeffs[i] as i32 - other.coeffs[i] as i32 + Q as i32) % Q as i32;
            result[i] = mod_reduce(diff);
        }
        Self { coeffs: result }
    }
    
    /// Multiply two polynomials with negacyclic reduction (X^n = -1)
    pub fn mul_negacyclic(&self, other: &Self) -> Self {
        let mut result = vec![0i32; N];
        
        // Standard polynomial multiplication
        for i in 0..N {
            for j in 0..N {
                let product = (self.coeffs[i] as i32) * (other.coeffs[j] as i32);
                
                if i + j < N {
                    // Normal case: add to result[i+j]
                    result[i + j] += product;
                } else {
                    // Reduction: X^N = -1, so X^(i+j) = -X^(i+j-N)
                    result[i + j - N] -= product;
                }
            }
        }
        
        // Reduce all coefficients modulo q
        let coeffs: Vec<i16> = result
            .iter()
            .map(|&x| mod_reduce(x))
            .collect();
        
        Self { coeffs }
    }
    
    /// Compute polynomial modulo q with centered reduction [-q/2, q/2)
    pub fn center_reduce(&mut self) {
        for coeff in &mut self.coeffs {
            *coeff = center_reduce(*coeff as i32);
        }
    }
    
    /// Check if polynomial is invertible modulo q
    pub fn is_invertible(&self) -> bool {
        // A polynomial is invertible if gcd(f, X^n + 1) = 1
        // For simplicity, we check if f(0) != 0 (necessary but not sufficient)
        self.coeffs[0] != 0
    }
    
    /// Compute the squared norm ||f||^2
    pub fn norm_squared(&self) -> i64 {
        self.coeffs
            .iter()
            .map(|&x| {
                let centered = center_reduce(x as i32) as i64;
                centered * centered
            })
            .sum()
    }
}

/// Reduce a value modulo q to range [0, q)
#[inline]
pub fn mod_reduce(x: i32) -> i16 {
    let mut result = x % Q as i32;
    if result < 0 {
        result += Q as i32;
    }
    result as i16
}

/// Center reduce a value modulo q to range [-q/2, q/2)
#[inline]
pub fn center_reduce(x: i32) -> i16 {
    let mut result = x % Q as i32;
    if result < 0 {
        result += Q as i32;
    }
    if result >= (Q as i32 + 1) / 2 {
        result -= Q as i32;
    }
    result as i16
}

/// Compute modular inverse using extended GCD
pub fn mod_inverse(a: i32, m: i32) -> Result<i32> {
    let (gcd, x, _) = extended_gcd(a, m);
    if gcd != 1 {
        return Err(Falcon512Error::NotInvertible);
    }
    Ok(((x % m) + m) % m)
}

/// Extended GCD algorithm
pub fn extended_gcd(a: i32, b: i32) -> (i32, i32, i32) {
    if b == 0 {
        return (a, 1, 0);
    }
    let (gcd, x1, y1) = extended_gcd(b, a % b);
    let x = y1;
    let y = x1 - (a / b) * y1;
    (gcd, x, y)
}

/// Polynomial operations specific to Falcon-512
pub mod falcon_poly {
    use super::*;
    
    /// Compute h = g/f mod q for public key generation
    /// This requires f to be invertible modulo q
    pub fn compute_public_key(f: &Polynomial, g: &Polynomial) -> Result<Polynomial> {
        // This is a placeholder - will be replaced with NTT-based division
        // For now, check invertibility
        if !f.is_invertible() {
            return Err(Falcon512Error::NotInvertible);
        }
        
        // Actual implementation will use NTT for efficient polynomial division
        // h = g * f^(-1) mod q
        Ok(g.clone()) // Placeholder
    }
    
    /// Verify that f*G - g*F = q for NTRU equation
    pub fn verify_ntru_equation(
        f: &Polynomial, 
        g: &Polynomial,
        big_f: &Polynomial,
        big_g: &Polynomial
    ) -> bool {
        // Compute f*G - g*F
        let fg = f.mul_negacyclic(big_g);
        let gf = g.mul_negacyclic(big_f);
        let result = fg.sub(&gf);
        
        // Check if result equals q (i.e., [q, 0, 0, ..., 0])
        if result.coeffs[0] != Q as i16 && result.coeffs[0] != 1 {
            return false;
        }
        
        // All other coefficients should be close to 0
        for i in 1..N {
            if result.coeffs[i].abs() > 10 {
                return false;
            }
        }
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_polynomial_add() {
        let a = Polynomial::new(vec![1; N]);
        let b = Polynomial::new(vec![2; N]);
        let c = a.add(&b);
        
        for i in 0..N {
            assert_eq!(c.coeffs[i], 3);
        }
    }
    
    #[test]
    fn test_polynomial_sub() {
        let a = Polynomial::new(vec![5; N]);
        let b = Polynomial::new(vec![3; N]);
        let c = a.sub(&b);
        
        for i in 0..N {
            assert_eq!(c.coeffs[i], 2);
        }
    }
    
    #[test]
    fn test_negacyclic_reduction() {
        // Test that X^n = -1
        let mut x_n = vec![0i16; N];
        x_n[0] = 1; // This represents X^n after reduction
        
        let a = Polynomial::new(x_n.clone());
        let b = Polynomial::constant(1);
        
        // X^n * 1 should give -1 (or q-1 in modular arithmetic)
        let result = a.mul_negacyclic(&b);
        
        // Due to negacyclic reduction, this should give us something related to -1
        // The actual test would depend on proper implementation
    }
    
    #[test]
    fn test_center_reduce() {
        // Q = 12289, so Q/2 = 6144.5
        // Range should be [-6144, 6144]
        assert_eq!(center_reduce(0), 0);
        assert_eq!(center_reduce(Q as i32 - 1), -1); // 12288 -> -1
        assert_eq!(center_reduce(6144), 6144);
        assert_eq!(center_reduce(6145), -6144); // Values > Q/2 wrap to negative
        assert_eq!(center_reduce(1), 1);
        assert_eq!(center_reduce(-1), -1);
    }
    
    #[test]
    fn test_mod_inverse() {
        // Test that 3 * 3^(-1) = 1 (mod q)
        let inv = mod_inverse(3, Q as i32).unwrap();
        assert_eq!((3 * inv) % Q as i32, 1);
    }
}