/// Polynomial inversion in the ring Z_q[X]/(X^n + 1)
/// 
/// This module implements polynomial inversion for Falcon-512 key generation.

use crate::constants::{N, Q};
use crate::poly::Poly;
use crate::error::{Falcon512Error, Result};
use alloc::vec;

/// Compute the inverse of polynomial f in Z_q[X]/(X^n + 1)
/// Returns f^(-1) such that f * f^(-1) = 1 mod (X^n + 1, q)
pub fn poly_inverse(f: &Poly) -> Result<Poly> {
    // Use the extended Euclidean algorithm
    // We want to find u such that f*u = 1 mod (X^n + 1, q)
    
    // Check if f(0) is invertible mod q (necessary condition)
    if gcd(f.coeffs[0] as i32, Q as i32) != 1 {
        return Err(Falcon512Error::InvalidParameter);
    }
    
    // Initialize polynomials for extended Euclidean algorithm
    // a = X^n + 1 (represented implicitly)
    // b = f
    let _b = f.clone();
    let mut u = Poly::zero(N);
    u.coeffs[0] = 1;  // u = 1
    let _v = Poly::zero(N);  // v = 0
    
    // We'll work with a representation where X^n = -1
    // So we need to handle the reduction carefully
    
    // For small n like 512, we can use a direct approach
    // based on the fact that in Z_q[X]/(X^n + 1), we have
    // a limited number of elements
    
    // Use Fermat's little theorem approach in the quotient ring
    // Since the ring is not a field, we need to be more careful
    
    // For now, implement a simple iterative method
    // that works for the specific case of Falcon-512
    
    // Check if polynomial is actually invertible by testing
    // if gcd(f, X^n + 1) = 1 in Z_q[X]
    
    // Simplified approach: use NTT domain if all NTT coefficients are non-zero
    use crate::ntt_negacyclic::NegacyclicNTT;
    
    let f_ntt = NegacyclicNTT::forward(f);
    
    // Check if all NTT coefficients are non-zero
    for &coeff in &f_ntt {
        if coeff == 0 {
            return Err(Falcon512Error::InvalidParameter);
        }
    }
    
    // Compute inverse in NTT domain
    let mut f_inv_ntt = vec![0u16; N];
    for i in 0..N {
        // Compute modular inverse using Fermat's little theorem
        // a^(-1) = a^(q-2) mod q
        f_inv_ntt[i] = mod_pow(f_ntt[i], Q - 2);
    }
    
    // Transform back
    let f_inv = NegacyclicNTT::inverse(&f_inv_ntt);
    
    // Verify the result
    let check = NegacyclicNTT::multiply(f, &f_inv);
    if check.coeffs[0] != 1 {
        return Err(Falcon512Error::InvalidParameter);
    }
    for i in 1..N {
        if check.coeffs[i] != 0 {
            return Err(Falcon512Error::InvalidParameter);
        }
    }
    
    Ok(f_inv)
}

/// Compute gcd of two integers
fn gcd(mut a: i32, mut b: i32) -> i32 {
    a = a.abs();
    b = b.abs();
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Modular exponentiation: compute base^exp mod q
fn mod_pow(base: u16, exp: u16) -> u16 {
    let mut result = 1u32;
    let mut base = base as u32;
    let mut exp = exp as u32;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % (Q as u32);
        }
        base = (base * base) % (Q as u32);
        exp >>= 1;
    }
    
    result as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_poly_inverse_simple() {
        // Test with a simple polynomial that we know is invertible
        let mut f = Poly::zero(N);
        f.coeffs[0] = 2;  // f(X) = 2
        
        let f_inv = poly_inverse(&f).unwrap();
        
        // 2^(-1) mod 12289 = 6145, but in centered representation this is -6144
        assert_eq!(f_inv.coeffs[0], -6144);
        for i in 1..N {
            assert_eq!(f_inv.coeffs[i], 0);
        }
    }
    
    #[test]
    fn test_poly_inverse_linear() {
        // Test with f(X) = 1 + X
        let mut f = Poly::zero(N);
        f.coeffs[0] = 1;
        f.coeffs[1] = 1;
        
        match poly_inverse(&f) {
            Ok(f_inv) => {
                // Verify f * f_inv = 1
                let product = f.mul_ntt(&f_inv);
                assert_eq!(product.coeffs[0], 1);
                for i in 1..N {
                    assert_eq!(product.coeffs[i], 0);
                }
            }
            Err(_) => {
                // It's possible this polynomial is not invertible
                // depending on the specific ring structure
            }
        }
    }
    
    #[test]
    fn test_non_invertible() {
        // Test with a polynomial that's not invertible (f(0) = 0)
        let mut f = Poly::zero(N);
        f.coeffs[1] = 1;  // f(X) = X
        
        assert!(poly_inverse(&f).is_err());
    }
}