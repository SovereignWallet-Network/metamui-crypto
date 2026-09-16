//! Karatsuba Multiplication for Polynomials
//! 
//! This implements efficient polynomial multiplication using the Karatsuba algorithm,
//! which reduces complexity from O(n²) to O(n^1.585) for large polynomials.

use alloc::vec::Vec;

/// Threshold below which we use schoolbook multiplication
const KARATSUBA_THRESHOLD: usize = 32;

/// Karatsuba multiplication of two polynomials
/// Returns the product of a and b
pub fn karatsuba_mul(a: &[i32], b: &[i32]) -> Vec<i32> {
    let n = a.len().max(b.len());
    
    // Base case: use schoolbook multiplication for small polynomials
    if n <= KARATSUBA_THRESHOLD {
        return schoolbook_mul(a, b);
    }
    
    // Pad to next power of 2 for efficiency
    let n = n.next_power_of_two();
    let mut a_padded = vec![0i32; n];
    let mut b_padded = vec![0i32; n];
    
    a_padded[..a.len()].copy_from_slice(a);
    b_padded[..b.len()].copy_from_slice(b);
    
    karatsuba_recursive(&a_padded, &b_padded)
}

/// Recursive Karatsuba multiplication
fn karatsuba_recursive(a: &[i32], b: &[i32]) -> Vec<i32> {
    let n = a.len();
    
    // Base case
    if n <= KARATSUBA_THRESHOLD {
        return schoolbook_mul(a, b);
    }
    
    let half = n / 2;
    
    // Split polynomials: a = a0 + a1*X^(n/2), b = b0 + b1*X^(n/2)
    let a0 = &a[..half];
    let a1 = &a[half..];
    let b0 = &b[..half];
    let b1 = &b[half..];
    
    // Compute three products using Karatsuba's trick
    // z0 = a0 * b0
    let z0 = karatsuba_recursive(a0, b0);
    
    // z2 = a1 * b1
    let z2 = karatsuba_recursive(a1, b1);
    
    // z1 = (a0 + a1) * (b0 + b1) - z0 - z2
    let a0_plus_a1 = add_poly(a0, a1);
    let b0_plus_b1 = add_poly(b0, b1);
    let z1_temp = karatsuba_recursive(&a0_plus_a1, &b0_plus_b1);
    let z1 = sub_poly(&sub_poly(&z1_temp, &z0), &z2);
    
    // Combine results: z0 + z1*X^(n/2) + z2*X^n
    combine_karatsuba(z0, z1, z2, half)
}

/// Schoolbook multiplication for small polynomials
fn schoolbook_mul(a: &[i32], b: &[i32]) -> Vec<i32> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    
    let mut result = vec![0i32; a.len() + b.len() - 1];
    
    for i in 0..a.len() {
        for j in 0..b.len() {
            let prod = (a[i] as i64 * b[j] as i64) as i32;
            result[i + j] = result[i + j].saturating_add(prod);
        }
    }
    
    result
}

/// Add two polynomials
fn add_poly(a: &[i32], b: &[i32]) -> Vec<i32> {
    let n = a.len().max(b.len());
    let mut result = vec![0i32; n];
    
    for i in 0..a.len() {
        result[i] = a[i];
    }
    
    for i in 0..b.len() {
        result[i] = result[i].saturating_add(b[i]);
    }
    
    result
}

/// Subtract two polynomials
fn sub_poly(a: &[i32], b: &[i32]) -> Vec<i32> {
    let n = a.len().max(b.len());
    let mut result = vec![0i32; n];
    
    for i in 0..a.len() {
        result[i] = a[i];
    }
    
    for i in 0..b.len() {
        result[i] = result[i].saturating_sub(b[i]);
    }
    
    result
}

/// Combine Karatsuba results
fn combine_karatsuba(z0: Vec<i32>, z1: Vec<i32>, z2: Vec<i32>, half: usize) -> Vec<i32> {
    let n = half * 2 + z2.len();
    let mut result = vec![0i32; n];
    
    // Add z0
    for i in 0..z0.len() {
        result[i] = result[i].saturating_add(z0[i]);
    }
    
    // Add z1 * X^(half)
    for i in 0..z1.len() {
        result[i + half] = result[i + half].saturating_add(z1[i]);
    }
    
    // Add z2 * X^(2*half)
    for i in 0..z2.len() {
        result[i + 2 * half] = result[i + 2 * half].saturating_add(z2[i]);
    }
    
    result
}

/// Karatsuba multiplication modulo X^n + 1 (for cyclotomic polynomials)
pub fn karatsuba_mul_mod(a: &[i32], b: &[i32], n: usize) -> Vec<i32> {
    // First do regular Karatsuba multiplication
    let product = karatsuba_mul(a, b);
    
    // Then reduce modulo X^n + 1
    let mut result = vec![0i32; n];
    
    for i in 0..product.len() {
        if i < n {
            result[i] = result[i].saturating_add(product[i]);
        } else {
            // X^n = -1, so X^(n+k) = -X^k
            result[i % n] = result[i % n].saturating_sub(product[i]);
        }
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_schoolbook_mul() {
        let a = vec![1, 2, 3];  // 1 + 2x + 3x^2
        let b = vec![4, 5];      // 4 + 5x
        
        let result = schoolbook_mul(&a, &b);
        // (1 + 2x + 3x^2)(4 + 5x) = 4 + 13x + 22x^2 + 15x^3
        assert_eq!(result, vec![4, 13, 22, 15]);
    }
    
    #[test]
    fn test_karatsuba_mul() {
        let a = vec![1, 2, 3, 4];
        let b = vec![5, 6, 7, 8];
        
        let karatsuba_result = karatsuba_mul(&a, &b);
        let schoolbook_result = schoolbook_mul(&a, &b);
        
        assert_eq!(karatsuba_result, schoolbook_result);
    }
    
    #[test]
    fn test_karatsuba_mul_mod() {
        // Test multiplication modulo X^4 + 1
        let a = vec![1, 0, 0, 0];  // 1
        let b = vec![0, 0, 0, 1];  // X^3
        
        let result = karatsuba_mul_mod(&a, &b, 4);
        // X^3 * 1 = X^3
        assert_eq!(result, vec![0, 0, 0, 1]);
        
        // Test wraparound: X^4 = -1
        let a = vec![0, 0, 0, 0, 1];  // X^4 (will become -1)
        let b = vec![1, 0, 0, 0];     // 1
        
        let result = karatsuba_mul_mod(&a, &b, 4);
        // X^4 * 1 = -1 (mod X^4 + 1)
        assert_eq!(result, vec![-1, 0, 0, 0]);
    }
}