/// Constant-time operations for Falcon-512
/// 
/// This module provides constant-time implementations of critical operations
/// to prevent timing side-channel attacks.

use crate::constants::{N, Q};
use metamui_security_utils::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

/// Constant-time conditional selection
/// Returns a if choice == 1, b if choice == 0
#[inline(always)]
pub fn ct_select<T: ConditionallySelectable>(a: T, b: T, choice: Choice) -> T {
    T::conditional_select(&a, &b, choice)
}

/// Constant-time equality check for i16
#[inline(always)]
pub fn ct_eq_i16(a: i16, b: i16) -> Choice {
    (a as u16).ct_eq(&(b as u16))
}

/// Constant-time less-than comparison for i16
#[inline(always)]
pub fn ct_lt_i16(a: i16, b: i16) -> Choice {
    // Convert to unsigned for comparison
    // Add 2^15 to shift range from [-2^15, 2^15-1] to [0, 2^16-1]
    let a_u = (a as i32 + 32768) as u16;
    let b_u = (b as i32 + 32768) as u16;
    // a < b is equivalent to b > a
    b_u.ct_gt(&a_u)
}

/// Constant-time greater-than comparison for i16
#[inline(always)]
pub fn ct_gt_i16(a: i16, b: i16) -> Choice {
    ct_lt_i16(b, a)
}

/// Constant-time absolute value for i16
#[inline(always)]
pub fn ct_abs_i16(x: i16) -> u16 {
    // Use bit manipulation for constant-time abs
    let mask = (x >> 15) as i32;  // All 1s if negative, all 0s if positive
    let x_i32 = x as i32;
    ((x_i32 ^ mask) - mask) as u16
}

/// Constant-time modular reduction
/// Reduces x modulo q to the range [0, q)
#[inline(always)]
pub fn ct_mod_q(x: i32) -> u16 {
    // First reduce to a reasonable range
    let r = x % (Q as i32);
    
    // If negative, add Q
    let is_negative = ct_lt_i16(r as i16, 0);
    let r_positive = ct_select((r + Q as i32) as i16, r as i16, is_negative);
    
    // Now r_positive is in range [0, Q)
    r_positive as u16
}

/// Constant-time centered modular reduction
/// Reduces x modulo q to the range [-q/2, q/2)
#[inline(always)]
pub fn ct_mod_q_centered(x: i32) -> i16 {
    let r = ct_mod_q(x);
    let is_gt_half = ct_gt_i16(r as i16, (Q / 2) as i16);
    ct_select((r as i16) - (Q as i16), r as i16, is_gt_half)
}

/// Constant-time polynomial comparison
/// Returns true if all coefficients are equal
pub fn ct_poly_eq(a: &[i16; N], b: &[i16; N]) -> Choice {
    let mut result = Choice::from(1u8);
    for i in 0..N {
        result &= ct_eq_i16(a[i], b[i]);
    }
    result
}

/// Constant-time polynomial copy
/// Copies polynomial b to a if choice == 1
pub fn ct_poly_copy(a: &mut [i16; N], b: &[i16; N], choice: Choice) {
    for i in 0..N {
        a[i] = ct_select(b[i], a[i], choice);
    }
}

/// Constant-time byte array comparison
pub fn ct_bytes_eq(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        return Choice::from(0u8);
    }
    
    let mut result = Choice::from(1u8);
    for i in 0..a.len() {
        result &= a[i].ct_eq(&b[i]);
    }
    result
}

/// Constant-time byte array copy
pub fn ct_bytes_copy(dest: &mut [u8], src: &[u8], choice: Choice) {
    assert_eq!(dest.len(), src.len());
    
    for i in 0..dest.len() {
        dest[i] = ct_select(src[i], dest[i], choice);
    }
}

/// Constant-time mask generation
/// Returns 0xFFFF if choice == 1, 0x0000 if choice == 0
#[inline(always)]
pub fn ct_mask_u16(choice: Choice) -> u16 {
    let mask = choice.unwrap_u8() as u16;
    mask.wrapping_neg()
}

/// Constant-time mask generation for i16
#[inline(always)]
pub fn ct_mask_i16(choice: Choice) -> i16 {
    ct_mask_u16(choice) as i16
}

/// Constant-time conditional negate
/// Returns -x if choice == 1, x if choice == 0
#[inline(always)]
pub fn ct_negate_i16(x: i16, choice: Choice) -> i16 {
    ct_select(-x, x, choice)
}

/// Constant-time minimum
#[inline(always)]
pub fn ct_min_i16(a: i16, b: i16) -> i16 {
    ct_select(a, b, ct_lt_i16(a, b))
}

/// Constant-time maximum
#[inline(always)]
pub fn ct_max_i16(a: i16, b: i16) -> i16 {
    ct_select(a, b, ct_gt_i16(a, b))
}

/// Clear sensitive data from memory
pub fn secure_zero(data: &mut [u8]) {
    // Use volatile writes to prevent optimization
    for byte in data.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    
    // Memory barrier to ensure writes complete
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// Clear sensitive polynomial from memory
pub fn secure_zero_poly(poly: &mut [i16; N]) {
    for coeff in poly.iter_mut() {
        unsafe {
            core::ptr::write_volatile(coeff, 0);
        }
    }
    
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// Constant-time maximum for u16
#[inline(always)]
pub fn ct_max_u16(a: u16, b: u16) -> u16 {
    ct_select(a, b, a.ct_gt(&b))
}

/// Constant-time infinity norm for i16 slices
pub fn ct_infinity_norm_i16(v: &[i16]) -> u16 {
    let mut max = 0u16;
    
    for &x in v {
        let abs_x = ct_abs_i16(x);
        max = ct_max_u16(max, abs_x);
    }
    
    max
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ct_select() {
        let a = 42i16;
        let b = 17i16;
        
        assert_eq!(ct_select(a, b, Choice::from(1u8)), a);
        assert_eq!(ct_select(a, b, Choice::from(0u8)), b);
    }
    
    #[test]
    fn test_ct_eq() {
        assert_eq!(ct_eq_i16(42, 42).unwrap_u8(), 1);
        assert_eq!(ct_eq_i16(42, 17).unwrap_u8(), 0);
        assert_eq!(ct_eq_i16(-42, -42).unwrap_u8(), 1);
        assert_eq!(ct_eq_i16(-42, 42).unwrap_u8(), 0);
    }
    
    #[test]
    fn test_ct_lt() {
        assert_eq!(ct_lt_i16(17, 42).unwrap_u8(), 1);
        assert_eq!(ct_lt_i16(42, 17).unwrap_u8(), 0);
        assert_eq!(ct_lt_i16(42, 42).unwrap_u8(), 0);
        assert_eq!(ct_lt_i16(-42, 17).unwrap_u8(), 1);
        assert_eq!(ct_lt_i16(17, -42).unwrap_u8(), 0);
    }
    
    #[test]
    fn test_ct_abs() {
        assert_eq!(ct_abs_i16(42), 42);
        assert_eq!(ct_abs_i16(-42), 42);
        assert_eq!(ct_abs_i16(0), 0);
        assert_eq!(ct_abs_i16(i16::MIN), 32768);
    }
    
    #[test]
    fn test_ct_mod_q() {
        assert_eq!(ct_mod_q(0), 0);
        assert_eq!(ct_mod_q(Q as i32), 0);
        assert_eq!(ct_mod_q(-1), Q - 1);
        assert_eq!(ct_mod_q(Q as i32 + 5), 5);
        assert_eq!(ct_mod_q(-(Q as i32) - 5), Q - 5);
    }
    
    #[test]
    fn test_ct_mod_q_centered() {
        assert_eq!(ct_mod_q_centered(0), 0);
        assert_eq!(ct_mod_q_centered(1), 1);
        assert_eq!(ct_mod_q_centered(Q as i32 / 2), Q as i16 / 2);
        assert_eq!(ct_mod_q_centered((Q as i32 / 2) + 1), -(Q as i16 / 2));
        assert_eq!(ct_mod_q_centered(Q as i32 - 1), -1);
    }
}