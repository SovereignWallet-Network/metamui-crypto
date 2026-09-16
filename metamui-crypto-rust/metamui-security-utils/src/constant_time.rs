//! Constant-time operations for cryptographic implementations.
//!
//! This module provides types and traits for performing constant-time
//! operations, preventing timing side-channel attacks.

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, Not};

/// A type representing a choice between two values in constant time.
///
/// The `Choice` type is a wrapper around a `u8` that maintains the invariant
/// that the value is always either 0 or 1. This allows constant-time selection
/// between two values without branching.
#[derive(Copy, Clone, Debug)]
pub struct Choice(u8);

impl Choice {
    /// Create a `Choice` representing the value 0 (false).
    #[inline]
    pub const fn from_u8(value: u8) -> Self {
        Choice((value != 0) as u8)
    }

    /// Create a `Choice` representing the value 0 (false).
    #[inline]
    pub const fn zero() -> Self {
        Choice(0)
    }

    /// Create a `Choice` representing the value 1 (true).
    #[inline]
    pub const fn one() -> Self {
        Choice(1)
    }

    /// Unwrap the `Choice` as a `u8`.
    ///
    /// # Returns
    /// * `1` if the choice represents true
    /// * `0` if the choice represents false
    #[inline]
    pub const fn unwrap_u8(&self) -> u8 {
        self.0
    }

    /// Convert the `Choice` to a mask.
    ///
    /// # Returns
    /// * `0xff` if the choice represents true
    /// * `0x00` if the choice represents false
    #[inline]
    pub(crate) const fn mask(&self) -> u8 {
        (self.0 as i8).wrapping_neg() as u8
    }
}

impl From<u8> for Choice {
    #[inline]
    fn from(value: u8) -> Self {
        Choice::from_u8(value)
    }
}

impl From<Choice> for bool {
    #[inline]
    fn from(choice: Choice) -> Self {
        choice.0 != 0
    }
}

impl BitAnd for Choice {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Choice(self.0 & rhs.0)
    }
}

impl BitOr for Choice {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Choice(self.0 | rhs.0)
    }
}

impl BitXor for Choice {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Choice(self.0 ^ rhs.0)
    }
}

impl Not for Choice {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Choice(1 ^ self.0)
    }
}

impl BitAndAssign for Choice {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BitOrAssign for Choice {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A trait for conditionally selecting between two values in constant time.
pub trait ConditionallySelectable: Sized {
    /// Select `a` if `choice == 1` or `b` if `choice == 0`.
    ///
    /// This function must be implemented in constant time.
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self;

    /// Conditionally assign `other` to `self` if `choice == 1`.
    #[inline]
    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        *self = Self::conditional_select(other, self, choice);
    }

    /// Conditionally swap `self` and `other` if `choice == 1`.
    #[inline]
    fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        let t = Self::conditional_select(a, b, choice);
        b.conditional_assign(a, choice);
        *a = t;
    }
}

/// A trait for comparing values in constant time.
pub trait ConstantTimeEq {
    /// Compare two values for equality in constant time.
    ///
    /// # Returns
    /// * `Choice(1)` if the values are equal
    /// * `Choice(0)` if the values are not equal
    fn ct_eq(&self, other: &Self) -> Choice;
}

/// A trait for comparing values for ordering in constant time.
pub trait ConstantTimeGreater {
    /// Compare if `self > other` in constant time.
    ///
    /// # Returns
    /// * `Choice(1)` if `self > other`
    /// * `Choice(0)` if `self <= other`
    fn ct_gt(&self, other: &Self) -> Choice;
}

/// Constant-time conditional selection for bytes.
impl ConditionallySelectable for u8 {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mask = choice.mask();
        (*b & !mask) | (*a & mask)
    }
}

/// Constant-time equality for bytes.
impl ConstantTimeEq for u8 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        let x = self ^ other;
        let x = (x | x.wrapping_neg()) >> 7;
        Choice::from_u8(!x & 1)
    }
}

/// Macro to implement constant-time operations for integer types.
macro_rules! impl_ct_for_integer {
    ($($t:ty),+) => {
        $(
            impl ConditionallySelectable for $t {
                #[inline]
                fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                    // Extend the mask to all bits of the type
                    let mask = (-(choice.unwrap_u8() as i8)) as $t;
                    (*b & !mask) | (*a & mask)
                }
            }

            impl ConstantTimeEq for $t {
                #[inline]
                fn ct_eq(&self, other: &Self) -> Choice {
                    let mut x = 0u8;
                    let self_bytes = self.to_ne_bytes();
                    let other_bytes = other.to_ne_bytes();
                    
                    for i in 0..self_bytes.len() {
                        x |= self_bytes[i] ^ other_bytes[i];
                    }
                    
                    x.ct_eq(&0)
                }
            }

            impl ConstantTimeGreater for $t {
                #[inline]
                fn ct_gt(&self, other: &Self) -> Choice {
                    // Constant-time greater-than comparison
                    // Based on the formula: (x - y - 1) >> (bits - 1) & 1
                    // This works because if x > y, then x - y - 1 >= 0 (no borrow)
                    // If x <= y, then x - y - 1 < 0 (borrow occurs, sign bit set)
                    let diff = self.wrapping_sub(*other).wrapping_sub(1);
                    let sign_bit = diff >> (<$t>::BITS - 1);
                    Choice::from_u8((!sign_bit & 1) as u8)
                }
            }
        )+
    };
}

impl_ct_for_integer!(u16, u32, u64, u128, usize);
impl_ct_for_integer!(i8, i16, i32, i64, i128, isize);

/// Constant-time operations for slices.
impl<T: ConstantTimeEq> ConstantTimeEq for [T] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        if self.len() != other.len() {
            return Choice::zero();
        }

        let mut result = Choice::one();
        for (a, b) in self.iter().zip(other.iter()) {
            result &= a.ct_eq(b);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_choice() {
        assert_eq!(Choice::zero().unwrap_u8(), 0);
        assert_eq!(Choice::one().unwrap_u8(), 1);
        assert_eq!(Choice::from_u8(0).unwrap_u8(), 0);
        assert_eq!(Choice::from_u8(1).unwrap_u8(), 1);
        assert_eq!(Choice::from_u8(255).unwrap_u8(), 1);
    }

    #[test]
    fn test_choice_ops() {
        let zero = Choice::zero();
        let one = Choice::one();

        assert_eq!((zero & zero).unwrap_u8(), 0);
        assert_eq!((zero & one).unwrap_u8(), 0);
        assert_eq!((one & zero).unwrap_u8(), 0);
        assert_eq!((one & one).unwrap_u8(), 1);

        assert_eq!((zero | zero).unwrap_u8(), 0);
        assert_eq!((zero | one).unwrap_u8(), 1);
        assert_eq!((one | zero).unwrap_u8(), 1);
        assert_eq!((one | one).unwrap_u8(), 1);

        assert_eq!((!zero).unwrap_u8(), 1);
        assert_eq!((!one).unwrap_u8(), 0);
    }

    #[test]
    fn test_conditional_select() {
        let a = 5u32;
        let b = 10u32;

        assert_eq!(u32::conditional_select(&a, &b, Choice::one()), a);
        assert_eq!(u32::conditional_select(&a, &b, Choice::zero()), b);
    }

    #[test]
    fn test_constant_time_eq() {
        assert_eq!(5u32.ct_eq(&5).unwrap_u8(), 1);
        assert_eq!(5u32.ct_eq(&6).unwrap_u8(), 0);

        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert_eq!(a.ct_eq(&b).unwrap_u8(), 1);
        assert_eq!(a.ct_eq(&c).unwrap_u8(), 0);
    }

    #[test]
    fn test_constant_time_greater() {
        assert_eq!(10u32.ct_gt(&5).unwrap_u8(), 1);
        assert_eq!(5u32.ct_gt(&10).unwrap_u8(), 0);
        assert_eq!(5u32.ct_gt(&5).unwrap_u8(), 0);
    }
}