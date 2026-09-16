/// Negacyclic NTT implementation for Falcon-512
/// 
/// This module implements the Number Theoretic Transform for negacyclic
/// convolution, where X^n = -1 in the polynomial ring.
/// 
/// This module now includes automatic optimization detection and fallback.

use crate::constants::{N, Q};
use crate::poly::Poly;
use alloc::vec::Vec;

#[cfg(feature = "optimized")]
use crate::ntt_optimized::OptimizedNTT;

/// Montgomery parameters for efficient modular arithmetic
mod montgomery {
    use super::Q;
    
    /// Montgomery parameter R = 2^16
    pub const MONT_R: u32 = 65536;
    
    /// R^2 mod q for converting to Montgomery form
    pub const MONT_R2: u32 = 10952;
    
    /// -q^(-1) mod R for Montgomery reduction
    pub const QINV: u32 = 12287;
    
    /// Convert to Montgomery form
    #[inline(always)]
    pub fn to_mont(a: u32) -> u32 {
        mont_mul(a, MONT_R2)
    }
    
    /// Convert from Montgomery form
    #[inline(always)]
    pub fn from_mont(a: u32) -> u32 {
        mont_reduce(a)
    }
    
    /// Montgomery multiplication
    #[inline(always)]
    pub fn mont_mul(a: u32, b: u32) -> u32 {
        let t = a as u64 * b as u64;
        mont_reduce((t & 0xFFFFFFFF) as u32)
    }
    
    /// Montgomery reduction
    #[inline(always)]
    pub fn mont_reduce(a: u32) -> u32 {
        let m = a.wrapping_mul(QINV) & 0xFFFF;
        let t = (a as u64 + m as u64 * Q as u64) >> 16;
        let r = t as u32;
        
        // Constant-time conditional subtraction
        let mask = ((Q as u32).wrapping_sub(r).wrapping_sub(1) >> 31).wrapping_sub(1);
        r.wrapping_sub(Q as u32 & mask)
    }
}

/// Negacyclic NTT implementation
pub struct NegacyclicNTT;

impl NegacyclicNTT {
    /// Precomputed powers of psi (square root of omega)
    /// psi = omega^(1/2) where omega is the n-th root of unity
    /// This gives us psi^n = omega^(n/2) = -1 (mod q)
    const PSI: u16 = 10302; // Precomputed: g^((q-1)/(2n))
    
    /// Primitive 2n-th root of unity
    const OMEGA: u32 = 49;
    
    /// Compute a^b mod q using fast exponentiation
    fn pow_mod(base: u16, exp: u32) -> u16 {
        let mut result = 1u32;
        let mut base = base as u32;
        let mut exp = exp;
        
        while exp > 0 {
            if exp & 1 == 1 {
                result = (result * base) % (Q as u32);
            }
            base = (base * base) % (Q as u32);
            exp >>= 1;
        }
        
        result as u16
    }
    
    /// Forward negacyclic NTT transform with automatic optimization
    /// Implements X_k = sum_{j=0}^{n-1} x_j * psi^{j*(2k+1)}
    pub fn forward(poly: &Poly) -> Vec<u16> {
        #[cfg(feature = "optimized")]
        {
            return OptimizedNTT::forward(poly);
        }
        
        #[cfg(not(feature = "optimized"))]
        {
            Self::forward_reference(poly)
        }
    }
    
    /// Reference implementation (fallback)
    fn forward_reference(poly: &Poly) -> Vec<u16> {
        let mut result = vec![0u16; N];
        
        // Convert coefficients to unsigned
        let coeffs: Vec<u16> = poly.coeffs.iter()
            .map(|&c| {
                if c < 0 {
                    (c + Q as i16) as u16
                } else {
                    c as u16
                }
            })
            .collect();
        
        // Precompute powers of psi for efficiency
        let mut psi_powers = vec![1u16; 2 * N];
        for i in 1..(2 * N) {
            psi_powers[i] = ((psi_powers[i - 1] as u32 * Self::PSI as u32) % (Q as u32)) as u16;
        }
        
        // Apply negacyclic NTT formula
        for k in 0..N {
            let mut sum = 0u32;
            for j in 0..N {
                let exp = (j * (2 * k + 1)) % (2 * N);
                sum = (sum + (coeffs[j] as u32 * psi_powers[exp] as u32)) % (Q as u32);
            }
            result[k] = sum as u16;
        }
        
        result
    }
    
    /// Inverse negacyclic NTT transform
    /// Implements x_j = n^{-1} * sum_{k=0}^{n-1} X_k * psi^{-j*(2k+1)}
    /// Inverse negacyclic NTT transform with automatic optimization
    pub fn inverse(ntt: &[u16]) -> Poly {
        #[cfg(feature = "optimized")]
        {
            return OptimizedNTT::inverse(ntt);
        }
        
        #[cfg(not(feature = "optimized"))]
        {
            Self::inverse_reference(ntt)
        }
    }
    
    /// Reference inverse implementation (fallback)
    fn inverse_reference(ntt: &[u16]) -> Poly {
        let mut result = vec![0u16; N];
        let n_inv = Self::pow_mod(N as u16, Q as u32 - 2);
        let psi_inv = Self::pow_mod(Self::PSI, Q as u32 - 2);
        
        // Precompute powers of psi_inv for efficiency
        let mut psi_inv_powers = vec![1u16; 2 * N];
        for i in 1..(2 * N) {
            psi_inv_powers[i] = ((psi_inv_powers[i - 1] as u32 * psi_inv as u32) % (Q as u32)) as u16;
        }
        
        // Apply inverse negacyclic NTT formula
        for j in 0..N {
            let mut sum = 0u32;
            for k in 0..N {
                let exp = (j * (2 * k + 1)) % (2 * N);
                sum = (sum + (ntt[k] as u32 * psi_inv_powers[exp] as u32)) % (Q as u32);
            }
            // Multiply by n^(-1)
            result[j] = ((sum * n_inv as u32) % (Q as u32)) as u16;
        }
        
        // Convert to signed representation
        let coeffs: Vec<i16> = result.iter()
            .map(|&c| {
                if c > Q / 2 {
                    c as i16 - Q as i16
                } else {
                    c as i16
                }
            })
            .collect();
        
        Poly { coeffs }
    }
    
    /// Multiply two polynomials using negacyclic NTT
    /// Polynomial multiplication with automatic optimization
    pub fn multiply(a: &Poly, b: &Poly) -> Poly {
        #[cfg(feature = "optimized")]
        {
            return OptimizedNTT::multiply(a, b);
        }
        
        #[cfg(not(feature = "optimized"))]
        {
            Self::multiply_reference(a, b)
        }
    }
    
    /// Reference multiplication implementation (fallback)
    fn multiply_reference(a: &Poly, b: &Poly) -> Poly {
        let a_ntt = Self::forward(a);
        let b_ntt = Self::forward(b);
        
        let mut c_ntt = vec![0u16; N];
        for i in 0..N {
            c_ntt[i] = ((a_ntt[i] as u32 * b_ntt[i] as u32) % (Q as u32)) as u16;
        }
        
        Self::inverse(&c_ntt)
    }
    

}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_psi_properties() {
        // Check that psi^n = -1 (mod q)
        let psi_n = NegacyclicNTT::pow_mod(NegacyclicNTT::PSI, N as u32);
        assert_eq!(psi_n, Q - 1, "psi^n should equal -1 mod q");
        
        // Check that psi^(2n) = 1 (mod q)
        let psi_2n = NegacyclicNTT::pow_mod(NegacyclicNTT::PSI, 2 * N as u32);
        assert_eq!(psi_2n, 1, "psi^(2n) should equal 1 mod q");
    }
    
    #[test]
    fn test_negacyclic_ntt_forward_inverse() {
        let mut poly = Poly::zero(N);
        poly.coeffs[0] = 1;
        poly.coeffs[1] = 2;
        poly.coeffs[2] = 3;
        
        let ntt = NegacyclicNTT::forward(&poly);
        let recovered = NegacyclicNTT::inverse(&ntt);
        
        assert_eq!(poly.coeffs[0], recovered.coeffs[0]);
        assert_eq!(poly.coeffs[1], recovered.coeffs[1]);
        assert_eq!(poly.coeffs[2], recovered.coeffs[2]);
    }
    
    #[test]
    fn test_negacyclic_multiply() {
        let mut a = Poly::zero(N);
        let mut b = Poly::zero(N);
        
        a.coeffs[0] = 1;
        a.coeffs[1] = 2;
        b.coeffs[0] = 3;
        b.coeffs[1] = 4;
        
        let c_ntt = NegacyclicNTT::multiply(&a, &b);
        let c_direct = a.mul(&b);
        
        // Check that results match
        for i in 0..10 {
            assert_eq!(c_ntt.coeffs[i], c_direct.coeffs[i], 
                      "Mismatch at index {}: NTT = {}, direct = {}", 
                      i, c_ntt.coeffs[i], c_direct.coeffs[i]);
        }
    }
    
    #[test]
    fn test_negacyclic_property() {
        // Test that X^n = -1 in our multiplication
        let mut x_n = Poly::zero(N);
        x_n.coeffs[0] = 1; // This represents X^n after reduction
        
        let mut one = Poly::zero(N);
        one.coeffs[0] = 1;
        
        // In negacyclic ring, X^n should multiply to give -1
        let mut x_to_n_minus_1 = Poly::zero(N);
        x_to_n_minus_1.coeffs[N - 1] = 1; // X^(n-1)
        
        let mut x = Poly::zero(N);
        x.coeffs[1] = 1; // X
        
        let result = NegacyclicNTT::multiply(&x_to_n_minus_1, &x);
        
        // Result should be -1 (which is Q-1 in our representation)
        assert_eq!(result.coeffs[0], -1);
        for i in 1..N {
            assert_eq!(result.coeffs[i], 0);
        }
    }
}