//! Polynomial operations for ML-KEM


#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

/// ML-KEM modulus q = 3329
pub const Q: i16 = 3329;
/// Polynomial degree n = 256
pub const N: usize = 256;

/// Polynomial in R_q = Z_q[X]/(X^n + 1)
#[derive(Clone, Debug)]
pub struct Polynomial {
    /// Coefficients in range [0, q)
    pub coefficients: [i16; N],
}

impl Polynomial {
    /// Create a zero polynomial
    pub fn zero() -> Self {
        Polynomial {
            coefficients: [0; N],
        }
    }
    
    /// Create polynomial from coefficients
    pub fn from_coefficients(coeffs: [i16; N]) -> Self {
        Polynomial {
            coefficients: coeffs,
        }
    }
    
    /// Add another polynomial
    pub fn add(&mut self, other: &Polynomial) {
        for i in 0..N {
            self.coefficients[i] = self.coefficients[i] + other.coefficients[i];
        }
    }
    
    /// Subtract another polynomial
    pub fn sub(&mut self, other: &Polynomial) {
        for i in 0..N {
            self.coefficients[i] = self.coefficients[i] - other.coefficients[i];
        }
    }
    
    /// Multiply by another polynomial in NTT domain using basemul
    pub fn multiply_ntt(&mut self, other: &Polynomial) {
        use crate::ntt::{basemul, ZETAS};
        
        // Multiplication in NTT domain - process 4 coefficients at a time
        for i in 0..64 {
            let zeta = ZETAS[64 + i];
            
            // First pair
            let a_pair = [self.coefficients[4*i], self.coefficients[4*i + 1]];
            let b_pair = [other.coefficients[4*i], other.coefficients[4*i + 1]];
            let result = basemul(&a_pair, &b_pair, zeta);
            self.coefficients[4*i] = result[0];
            self.coefficients[4*i + 1] = result[1];
            
            // Second pair (with negated zeta: q - zeta)
            let neg_zeta = if zeta == 0 { 0 } else { crate::polynomial::Q - zeta };
            let a_pair = [self.coefficients[4*i + 2], self.coefficients[4*i + 3]];
            let b_pair = [other.coefficients[4*i + 2], other.coefficients[4*i + 3]];
            let result = basemul(&a_pair, &b_pair, neg_zeta);
            self.coefficients[4*i + 2] = result[0];
            self.coefficients[4*i + 3] = result[1];
        }
    }
    
    /// Reduce coefficients modulo q to [0, Q)
    pub fn reduce(&mut self) {
        for i in 0..N {
            self.coefficients[i] = crate::ntt::barrett_reduce(self.coefficients[i]);
        }
    }
    
    /// Reduce coefficients to centered representation [-(Q-1)/2, (Q-1)/2]
    pub fn reduce_centered(&mut self) {
        for i in 0..N {
            // First reduce to [0, Q)
            let mut c = crate::ntt::barrett_reduce(self.coefficients[i]);
            // Then center to [-(Q-1)/2, (Q-1)/2]
            if c > Q / 2 {
                c -= Q;
            }
            self.coefficients[i] = c;
        }
    }
    
    // Montgomery form conversion removed - using normal form throughout
    
    /// Normalize coefficients to [0, Q)
    pub fn normalize(&mut self) {
        for i in 0..N {
            let mut c = self.coefficients[i] % Q;
            if c < 0 {
                c += Q;
            }
            self.coefficients[i] = c;
        }
    }
    
    /// Conditional reduce - reduce only if coefficient is outside valid range
    pub fn cond_reduce(&mut self) {
        for i in 0..N {
            let c = self.coefficients[i];
            if c >= Q {
                self.coefficients[i] = c - Q;
            } else if c < -Q {
                self.coefficients[i] = c + 2*Q;
            } else if c < 0 {
                self.coefficients[i] = c + Q;
            }
        }
    }
    
    /// Pack polynomial into bytes (12 bits per coefficient)
    pub fn pack(&self, output: &mut [u8]) {
        let mut j = 0;
        for i in (0..N).step_by(2) {
            // Ensure coefficients are in [0, Q) before packing
            let mut c0 = self.coefficients[i];
            let mut c1 = self.coefficients[i + 1];
            while c0 < 0 { c0 += Q; }
            while c0 >= Q { c0 -= Q; }
            while c1 < 0 { c1 += Q; }
            while c1 >= Q { c1 -= Q; }
            
            let t0 = c0 as u16;
            let t1 = c1 as u16;
            
            output[j] = (t0 & 0xff) as u8;
            output[j + 1] = ((t0 >> 8) | ((t1 & 0x0f) << 4)) as u8;
            output[j + 2] = (t1 >> 4) as u8;
            j += 3;
        }
    }
    
    /// Unpack polynomial from bytes
    pub fn unpack(input: &[u8]) -> Self {
        let mut poly = Polynomial::zero();
        let mut j = 0;
        
        for i in (0..N).step_by(2) {
            poly.coefficients[i] = ((input[j] as u16) | ((input[j + 1] as u16 & 0x0f) << 8)) as i16;
            poly.coefficients[i + 1] = (((input[j + 1] as u16) >> 4) | ((input[j + 2] as u16) << 4)) as i16;
            j += 3;
        }
        
        poly
    }
}

/// Vector of polynomials
#[derive(Clone, Debug)]
pub struct PolynomialVector {
    /// Vector of polynomials
    pub polynomials: Vec<Polynomial>,
}

impl PolynomialVector {
    /// Create a new polynomial vector
    pub fn new(k: usize) -> Self {
        PolynomialVector {
            polynomials: vec![Polynomial::zero(); k],
        }
    }
    
    /// Reduce all polynomials
    pub fn reduce(&mut self) {
        for poly in &mut self.polynomials {
            poly.reduce();
        }
    }
    
    /// Reduce all polynomials to centered representation
    pub fn reduce_centered(&mut self) {
        for poly in &mut self.polynomials {
            poly.reduce_centered();
        }
    }
    
    /// Add another polynomial vector
    pub fn add(&mut self, other: &PolynomialVector) {
        for i in 0..self.polynomials.len() {
            self.polynomials[i].add(&other.polynomials[i]);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pack_unpack() {
        let mut poly = Polynomial::zero();
        
        // Set some test values
        for i in 0..N {
            poly.coefficients[i] = ((i * 17) % Q as usize) as i16;
        }
        
        // Pack
        let mut packed = [0u8; 384];
        poly.pack(&mut packed);
        
        // Unpack
        let unpacked = Polynomial::unpack(&packed);
        
        // Check if values are preserved
        for i in 0..N {
            // Both should be in [0, Q)
            let mut orig = poly.coefficients[i];
            while orig < 0 { orig += Q; }
            while orig >= Q { orig -= Q; }
            
            let result = unpacked.coefficients[i];
            
            assert_eq!(orig, result, "Coefficient {} doesn't match after pack/unpack", i);
        }
    }
    
    #[test]
    fn test_polynomial_operations() {
        let mut p1 = Polynomial::zero();
        let mut p2 = Polynomial::zero();
        
        p1.coefficients[0] = 100;
        p2.coefficients[0] = 200;
        
        p1.add(&p2);
        assert_eq!(p1.coefficients[0], 300);
        
        p1.reduce();
        assert_eq!(p1.coefficients[0], 300);
    }
    
    #[test]
    fn test_barrett_reduce() {
        use crate::ntt::barrett_reduce;
        
        // Test basic reduction
        assert_eq!(barrett_reduce(Q), 0);  // Q reduces to 0
        assert_eq!(barrett_reduce(Q + 1), 1);  // Q+1 reduces to 1
        assert_eq!(barrett_reduce(Q - 1), Q - 1);  // Q-1 stays Q-1
        
        // Test that results are in [0, Q)
        assert!(barrett_reduce(2 * Q) >= 0 && barrett_reduce(2 * Q) < Q);
        assert!(barrett_reduce(5000) >= 0 && barrett_reduce(5000) < Q);
        assert!(barrett_reduce(-100) >= 0 && barrett_reduce(-100) < Q);
    }
    

}