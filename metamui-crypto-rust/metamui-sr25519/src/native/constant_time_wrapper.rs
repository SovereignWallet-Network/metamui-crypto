#![allow(dead_code, unused_imports)]
/// Wrapper module to provide Sr25519-specific constant-time operations
/// using the centralized constant-time utilities.
///
/// This maintains API compatibility while eliminating code duplication.

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;

use super::curve::EdwardsPoint;
use super::field::FieldElement;
use metamui_security_utils::{Choice, ConditionallySelectable, ConstantTimeEq};
use metamui_crypto_utilities::operations::constant_time::ConstantTime;

impl ConditionallySelectable for EdwardsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        EdwardsPoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
            t: FieldElement::conditional_select(&a.t, &b.t, choice),
        }
    }
}

impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0u64; 5];
        for i in 0..5 {
            limbs[i] = u64::conditional_select(&a.limbs[i], &b.limbs[i], choice);
        }
        FieldElement { limbs }
    }
}

impl ConstantTimeEq for EdwardsPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Points are equal if x1*z2 = x2*z1 and y1*z2 = y2*z1
        let x1z2 = self.x.mul(&other.z);
        let x2z1 = other.x.mul(&self.z);
        let y1z2 = self.y.mul(&other.z);
        let y2z1 = other.y.mul(&self.z);
        
        x1z2.ct_eq(&x2z1) & y1z2.ct_eq(&y2z1)
    }
}

impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut result = Choice::from(1u8);
        for i in 0..5 {
            result &= self.limbs[i].ct_eq(&other.limbs[i]);
        }
        result
    }
}

impl EdwardsPoint {
    /// Conditional swap of two points
    pub fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        let temp_x = FieldElement::conditional_select(&a.x, &b.x, choice);
        let temp_y = FieldElement::conditional_select(&a.y, &b.y, choice);
        let temp_z = FieldElement::conditional_select(&a.z, &b.z, choice);
        let temp_t = FieldElement::conditional_select(&a.t, &b.t, choice);
        
        b.x = FieldElement::conditional_select(&b.x, &a.x, choice);
        b.y = FieldElement::conditional_select(&b.y, &a.y, choice);
        b.z = FieldElement::conditional_select(&b.z, &a.z, choice);
        b.t = FieldElement::conditional_select(&b.t, &a.t, choice);
        
        a.x = temp_x;
        a.y = temp_y;
        a.z = temp_z;
        a.t = temp_t;
    }
    
    /// Constant-time scalar multiplication using Montgomery ladder
    pub fn scalar_mul_constant_time(&self, scalar: &[u8; 32]) -> Self {
        let mut r0 = EdwardsPoint::identity();
        let mut r1 = *self;
        
        // Process all 256 bits
        for byte in scalar.iter() {
            for i in 0..8 {
                let bit = Choice::from((byte >> i) & 1);
                
                // Conditional swap based on bit
                EdwardsPoint::conditional_swap(&mut r0, &mut r1, bit);
                
                // Always perform both operations
                let doubled = r0.double();
                let summed = r0.add(&r1);
                
                r0 = doubled;
                r1 = summed;
                
                // Conditional swap back
                EdwardsPoint::conditional_swap(&mut r0, &mut r1, bit);
            }
        }
        
        r0
    }
}

/// Constant-time byte comparison using centralized utilities
pub fn ct_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    ConstantTime::compare(a, b)
}

/// Constant-time conditional byte selection
pub fn ct_select_bytes(condition: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.len() != b.len() {
        panic!("Arrays must have same length");
    }
    
    let choice = Choice::from(condition as u8);
    let mut result = vec![0u8; a.len()];
    
    for i in 0..a.len() {
        result[i] = u8::conditional_select(&a[i], &b[i], choice);
    }
    
    result
}

/// Secure memory clearing
pub fn clear(data: &mut [u8]) {
    use metamui_security_utils::Zeroize;
    data.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ct_bytes_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        
        assert!(ct_bytes_eq(&a, &b));
        assert!(!ct_bytes_eq(&a, &c));
    }
    
    #[test]
    fn test_ct_select_bytes() {
        let a = vec![1u8, 2, 3, 4];
        let b = vec![5u8, 6, 7, 8];
        
        let result1 = ct_select_bytes(true, &a, &b);
        assert_eq!(result1, a);
        
        let result2 = ct_select_bytes(false, &a, &b);
        assert_eq!(result2, b);
    }
    
}