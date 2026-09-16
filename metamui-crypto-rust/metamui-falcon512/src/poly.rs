//! Polynomial operations for Falcon-512

use std::vec::Vec;

#[derive(Clone, Debug)]
pub struct Poly {
    pub coeffs: Vec<i16>,
}

impl Poly {
    pub fn new(coeffs: Vec<i16>) -> Self {
        Poly { coeffs }
    }
    
    pub fn zero(n: usize) -> Self {
        Poly { coeffs: vec![0; n] }
    }
    
    pub fn from_i16_slice(slice: &[i16]) -> Self {
        Poly { coeffs: slice.to_vec() }
    }
    
    /// Create a random polynomial for testing
    #[cfg(test)]
    pub fn random() -> Self {
        use crate::constants::N;
        Poly { coeffs: vec![1i16; N] }  // Simple deterministic "random" for tests
    }
    
    /// Multiply two polynomials modulo x^n + 1
    pub fn mul(&self, other: &Poly) -> Poly {
        let n = self.coeffs.len();
        let mut result = vec![0i32; n];
        
        for i in 0..n {
            for j in 0..n {
                let prod = self.coeffs[i] as i32 * other.coeffs[j] as i32;
                let idx = (i + j) % n;
                if i + j >= n {
                    // x^n = -1 mod (x^n + 1)
                    result[idx] -= prod;
                } else {
                    result[idx] += prod;
                }
            }
        }
        
        Poly {
            coeffs: result.iter().map(|&x| x as i16).collect()
        }
    }
}

#[derive(Clone, Debug)]
pub struct PolyF64 {
    pub coeffs: Vec<f64>,
}

impl PolyF64 {
    pub fn new(coeffs: Vec<f64>) -> Self {
        PolyF64 { coeffs }
    }
    
    pub fn from_poly(poly: &Poly) -> Self {
        PolyF64 {
            coeffs: poly.coeffs.iter().map(|&x| x as f64).collect()
        }
    }
}
