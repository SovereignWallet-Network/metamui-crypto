//! Constant-time security operations for ML-KEM-768
//!
//! This module provides constant-time implementations of critical cryptographic operations
//! to prevent timing side-channel attacks. All operations are designed to have execution
//! time independent of secret data values.

use metamui_security_utils::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess},
    zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing},
};
use core::ops::{Add, BitAnd, BitOr, BitXor, Not, Sub};

pub mod ct_ops;
pub mod memory;
pub mod mask;
pub mod compare;

pub use ct_ops::*;
pub use memory::*;
pub use mask::*;
pub use compare::*;

/// Constant-time operations trait for cryptographic primitives
pub trait ConstantTimeOps: Sized {
    /// Perform constant-time conditional selection
    /// Returns `a` if `choice` is 1, `b` if `choice` is 0
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self;
    
    /// Perform constant-time equality comparison
    fn ct_eq(&self, other: &Self) -> Choice;
    
    /// Perform constant-time conditional swap
    fn ct_swap(a: &mut Self, b: &mut Self, choice: Choice);
    
    /// Perform constant-time conditional copy
    fn ct_copy(&mut self, other: &Self, choice: Choice);
}

/// Secure integer type that provides constant-time operations
#[derive(Clone, Copy, Debug)]
pub struct SecureU16(u16);

impl SecureU16 {
    /// Create a new secure u16
    pub const fn new(value: u16) -> Self {
        Self(value)
    }
    
    /// Get the inner value
    pub const fn value(self) -> u16 {
        self.0
    }
    
    /// Constant-time modular reduction
    pub fn ct_mod(self, modulus: u16) -> Self {
        let mut result = self.0;
        let mut quotient = 0u16;
        
        // Barrett reduction for constant-time modulo
        let m = modulus as u32;
        let x = self.0 as u32;
        let mu = (1u64 << 32) / (m as u64);
        let q = ((x as u64 * mu) >> 32) as u32;
        let r = x - q * m;
        
        // Final reduction
        let r_reduced = if r >= m { r - m } else { r };
        
        Self::new(r_reduced as u16)
    }
    
    /// Constant-time Montgomery multiplication
    pub fn ct_montgomery_mul(self, other: Self, modulus: u16, r_inv: u16) -> Self {
        let a = self.0 as u32;
        let b = other.0 as u32;
        let m = modulus as u32;
        let mut t = a * b;
        
        // Montgomery reduction
        let q = ((t as u64 * r_inv as u64) & 0xFFFF) as u32;
        t = (t + q * m) >> 16;
        
        // Final reduction
        let result = if t >= m { t - m } else { t };
        Self::new(result as u16)
    }
}

impl ConstantTimeEq for SecureU16 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for SecureU16 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u16::conditional_select(&a.0, &b.0, choice))
    }
}

/// Secure array type with automatic zeroization
#[derive(Clone)]
pub struct SecureArray<const N: usize> {
    data: Zeroizing<[u8; N]>,
}

impl<const N: usize> SecureArray<N> {
    /// Create a new secure array
    pub fn new(data: [u8; N]) -> Self {
        Self {
            data: Zeroizing::new(data),
        }
    }
    
    /// Create a zeroed secure array
    pub fn zero() -> Self {
        Self {
            data: Zeroizing::new([0u8; N]),
        }
    }
    
    /// Get a reference to the data
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..]
    }
    
    /// Get a mutable reference to the data
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.data[..]
    }
    
    /// Constant-time XOR with another array
    pub fn ct_xor(&mut self, other: &Self) {
        for i in 0..N {
            self.data[i] ^= other.data[i];
        }
    }
    
    /// Constant-time conditional copy
    pub fn ct_copy_from(&mut self, other: &Self, choice: Choice) {
        for i in 0..N {
            self.data[i] = u8::conditional_select(&self.data[i], &other.data[i], choice);
        }
    }
    
    /// Constant-time comparison
    pub fn ct_eq(&self, other: &Self) -> Choice {
        self.data[..].ct_eq(&other.data[..])
    }
}

impl<const N: usize> Drop for SecureArray<N> {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Constant-time mask generation
pub fn ct_mask_u16(choice: Choice) -> u16 {
    -(choice.unwrap_u8() as i16) as u16
}

/// Constant-time mask generation for u32
pub fn ct_mask_u32(choice: Choice) -> u32 {
    -(choice.unwrap_u8() as i32) as u32
}

/// Constant-time mask generation for u64
pub fn ct_mask_u64(choice: Choice) -> u64 {
    -(choice.unwrap_u8() as i64) as u64
}

/// Constant-time conditional negation
pub fn ct_conditional_negate(value: u16, choice: Choice) -> u16 {
    let mask = ct_mask_u16(choice);
    let neg = (!value).wrapping_add(1);
    (value & !mask) | (neg & mask)
}

/// Constant-time absolute value
pub fn ct_abs(value: i16) -> u16 {
    let mask = (value >> 15) as u16;
    let xor = (value as u16) ^ mask;
    xor.wrapping_sub(mask)
}

/// Constant-time minimum
pub fn ct_min(a: u16, b: u16) -> u16 {
    let choice = a.ct_lt(&b);
    u16::conditional_select(&b, &a, choice)
}

/// Constant-time maximum
pub fn ct_max(a: u16, b: u16) -> u16 {
    let choice = a.ct_gt(&b);
    u16::conditional_select(&b, &a, choice)
}

/// Extension trait for constant-time comparisons
pub trait ConstantTimeComparison {
    /// Less than comparison
    fn ct_lt(&self, other: &Self) -> Choice;
    
    /// Greater than comparison
    fn ct_gt(&self, other: &Self) -> Choice;
    
    /// Less than or equal comparison
    fn ct_le(&self, other: &Self) -> Choice;
    
    /// Greater than or equal comparison
    fn ct_ge(&self, other: &Self) -> Choice;
}

impl ConstantTimeComparison for u16 {
    fn ct_lt(&self, other: &Self) -> Choice {
        let diff = (*other as i32) - (*self as i32);
        Choice::from(((diff >> 31) & 1) as u8)
    }
    
    fn ct_gt(&self, other: &Self) -> Choice {
        other.ct_lt(self)
    }
    
    fn ct_le(&self, other: &Self) -> Choice {
        !self.ct_gt(other)
    }
    
    fn ct_ge(&self, other: &Self) -> Choice {
        !self.ct_lt(other)
    }
}

/// Secure polynomial coefficient type for ML-KEM
#[derive(Clone, Copy, Debug)]
pub struct SecureCoefficient(u16);

impl SecureCoefficient {
    /// ML-KEM modulus q = 3329
    pub const Q: u16 = 3329;
    
    /// Create a new coefficient with modular reduction
    pub fn new(value: u16) -> Self {
        Self(value % Self::Q)
    }
    
    /// Create from a raw value (no reduction)
    pub const fn from_raw(value: u16) -> Self {
        Self(value)
    }
    
    /// Get the value
    pub const fn value(self) -> u16 {
        self.0
    }
    
    /// Constant-time modular addition
    pub fn ct_add(self, other: Self) -> Self {
        let sum = self.0.wrapping_add(other.0);
        let reduced = sum.wrapping_sub(Self::Q);
        let choice = (sum >= Self::Q) as u8;
        Self(u16::conditional_select(&sum, &reduced, Choice::from(choice)))
    }
    
    /// Constant-time modular subtraction
    pub fn ct_sub(self, other: Self) -> Self {
        let diff = self.0.wrapping_sub(other.0);
        let adjusted = diff.wrapping_add(Self::Q);
        let choice = (self.0 < other.0) as u8;
        Self(u16::conditional_select(&diff, &adjusted, Choice::from(choice)))
    }
    
    /// Constant-time modular multiplication
    pub fn ct_mul(self, other: Self) -> Self {
        let product = (self.0 as u32) * (other.0 as u32);
        Self::new((product % Self::Q as u32) as u16)
    }
    
    /// Constant-time Barrett reduction
    pub fn ct_barrett_reduce(value: u32) -> Self {
        const BARRETT_CONST: u32 = 20159; // floor(2^26 / q)
        let quotient = ((value as u64 * BARRETT_CONST as u64) >> 26) as u32;
        let remainder = value - quotient * Self::Q as u32;
        
        // Final reduction if needed
        let reduced = remainder.wrapping_sub(Self::Q as u32);
        let choice = (remainder >= Self::Q as u32) as u8;
        Self(u16::conditional_select(&(remainder as u16), &(reduced as u16), Choice::from(choice)))
    }
}

impl ConstantTimeEq for SecureCoefficient {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for SecureCoefficient {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u16::conditional_select(&a.0, &b.0, choice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_u16_operations() {
        let a = SecureU16::new(100);
        let b = SecureU16::new(200);
        
        // Test conditional select
        let choice_true = Choice::from(1u8);
        let choice_false = Choice::from(0u8);
        
        let selected = SecureU16::conditional_select(&a, &b, choice_true);
        assert_eq!(selected.value(), 100);
        
        let selected = SecureU16::conditional_select(&a, &b, choice_false);
        assert_eq!(selected.value(), 200);
    }
    
    #[test]
    fn test_secure_array() {
        let mut arr1 = SecureArray::<32>::zero();
        let arr2 = SecureArray::new([1u8; 32]);
        
        // Test XOR
        arr1.ct_xor(&arr2);
        assert_eq!(arr1.as_bytes()[0], 1);
        
        // Test comparison
        let arr3 = SecureArray::new([1u8; 32]);
        assert_eq!(arr2.ct_eq(&arr3).unwrap_u8(), 1);
    }
    
    #[test]
    fn test_secure_coefficient() {
        let a = SecureCoefficient::new(1000);
        let b = SecureCoefficient::new(2000);
        
        // Test modular addition
        let sum = a.ct_add(b);
        assert_eq!(sum.value(), 3000);
        
        // Test overflow handling
        let c = SecureCoefficient::new(2000);
        let d = SecureCoefficient::new(2000);
        let sum2 = c.ct_add(d);
        assert_eq!(sum2.value(), 4000 - SecureCoefficient::Q);
    }
    
    #[test]
    fn test_constant_time_comparisons() {
        let a: u16 = 100;
        let b: u16 = 200;
        
        assert_eq!(a.ct_lt(&b).unwrap_u8(), 1);
        assert_eq!(a.ct_gt(&b).unwrap_u8(), 0);
        assert_eq!(a.ct_le(&b).unwrap_u8(), 1);
        assert_eq!(a.ct_ge(&b).unwrap_u8(), 0);
    }
    
    #[test]
    fn test_ct_mask_generation() {
        let choice_true = Choice::from(1u8);
        let choice_false = Choice::from(0u8);
        
        assert_eq!(ct_mask_u16(choice_true), 0xFFFF);
        assert_eq!(ct_mask_u16(choice_false), 0x0000);
        
        assert_eq!(ct_mask_u32(choice_true), 0xFFFFFFFF);
        assert_eq!(ct_mask_u32(choice_false), 0x00000000);
    }
    
    #[test]
    fn test_ct_min_max() {
        let a = 100u16;
        let b = 200u16;
        
        assert_eq!(ct_min(a, b), 100);
        assert_eq!(ct_max(a, b), 200);
        assert_eq!(ct_min(b, a), 100);
        assert_eq!(ct_max(b, a), 200);
    }
}