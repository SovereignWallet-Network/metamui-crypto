//! Constant-time operations for Dilithium
//!
//! This module provides constant-time implementations of critical operations
//! to prevent timing side-channel attacks. The full CT primitive set is
//! intentionally kept in the API surface for completeness — several helpers
//! are not yet consumed by the current signing path but are retained so
//! that audit/review tools can verify the CT guarantee holistically. The
//! module-level allow stops the dead-code lint from churning every build;
//! new helpers should still land with at least one call site.

#![allow(dead_code)]

use crate::params::Q;

/// Constant-time conditional move
/// Returns a if condition is true (1), b if condition is false (0)
#[inline(always)]
pub fn ct_select(a: i32, b: i32, condition: u32) -> i32 {
    // Ensure condition is 0 or 1
    debug_assert!(condition <= 1);
    
    // Create mask: all 1s if condition is 1, all 0s if condition is 0
    let mask = (condition as i32).wrapping_neg();
    
    // Constant-time selection
    b ^ ((a ^ b) & mask)
}

/// Constant-time conditional move for bytes
#[inline(always)]
pub fn ct_select_u8(a: u8, b: u8, condition: u32) -> u8 {
    debug_assert!(condition <= 1);
    let mask = (condition as i32).wrapping_neg() as u8;
    b ^ ((a ^ b) & mask)
}

/// Constant-time equality check
/// Returns 1 if a == b, 0 otherwise
#[inline(always)]
pub fn ct_eq(a: i32, b: i32) -> u32 {
    let diff = (a ^ b) as u32;
    // If diff is 0, this returns 1. Otherwise returns 0.
    (((diff | diff.wrapping_neg()) >> 31) ^ 1) & 1
}

/// Constant-time less-than comparison
/// Returns 1 if a < b, 0 otherwise
#[inline(always)]
pub fn ct_lt(a: i32, b: i32) -> u32 {
    // Compute a - b with overflow detection
    let diff = a.wrapping_sub(b);
    // Extract sign bit
    ((diff as u32) >> 31) & 1
}

/// Constant-time absolute value
#[inline(always)]
pub fn ct_abs(a: i32) -> i32 {
    let mask = a >> 31;  // All 1s if negative, all 0s if positive
    (a ^ mask).wrapping_sub(mask)
}

/// Constant-time modular reduction
/// Reduces a mod q without branching
#[inline(always)]
pub fn ct_mod_q(a: i32) -> i32 {
    let mut r = a % (Q as i32);
    
    // If r is negative, add Q
    let mask = (r >> 31) as u32;  // 1 if negative, 0 otherwise
    r += ct_select(Q as i32, 0, mask);
    
    r
}

/// Constant-time byte array comparison
/// Returns true if arrays are equal, false otherwise
#[inline(always)]
pub fn ct_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    
    diff == 0
}

/// Constant-time memory copy
/// Copies from src to dst without data-dependent branches
#[inline(always)]
pub fn ct_copy(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    
    for i in 0..dst.len() {
        dst[i] = src[i];
    }
}

/// Constant-time conditional copy
/// Copies from src to dst if condition is 1
#[inline(always)]
pub fn ct_conditional_copy(dst: &mut [u8], src: &[u8], condition: u32) {
    assert_eq!(dst.len(), src.len());
    debug_assert!(condition <= 1);
    
    for i in 0..dst.len() {
        dst[i] = ct_select_u8(src[i], dst[i], condition);
    }
}

/// Constant-time rejection sampling check
/// Returns 1 if value should be accepted, 0 if rejected
#[inline(always)]
pub fn ct_rejection_check(value: u32, bound: u32) -> u32 {
    // Check if value < bound without branching
    let diff = value.wrapping_sub(bound);
    // If value >= bound, diff has MSB = 0, otherwise MSB = 1
    (diff >> 31) & 1
}

/// Constant-time polynomial coefficient bounds check
/// Returns true if all coefficients are within bounds
pub fn ct_check_norm_bound(coeffs: &[i32], bound: i32) -> bool {
    let mut result = 1u32;
    
    for &coeff in coeffs {
        let abs_coeff = ct_abs(coeff);
        // Check if abs_coeff < bound
        result &= ct_lt(abs_coeff, bound);
    }
    
    result == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ct_select() {
        assert_eq!(ct_select(42, 13, 1), 42);
        assert_eq!(ct_select(42, 13, 0), 13);
    }
    
    #[test]
    fn test_ct_eq() {
        assert_eq!(ct_eq(42, 42), 1);
        assert_eq!(ct_eq(42, 13), 0);
        assert_eq!(ct_eq(-5, -5), 1);
        assert_eq!(ct_eq(-5, 5), 0);
    }
    
    #[test]
    fn test_ct_lt() {
        assert_eq!(ct_lt(5, 10), 1);
        assert_eq!(ct_lt(10, 5), 0);
        assert_eq!(ct_lt(5, 5), 0);
        assert_eq!(ct_lt(-10, -5), 1);
    }
    
    #[test]
    fn test_ct_abs() {
        assert_eq!(ct_abs(42), 42);
        assert_eq!(ct_abs(-42), 42);
        assert_eq!(ct_abs(0), 0);
        assert_eq!(ct_abs(i32::MIN + 1), i32::MAX);
    }
    
    #[test]
    fn test_ct_bytes_eq() {
        assert!(ct_bytes_eq(b"hello", b"hello"));
        assert!(!ct_bytes_eq(b"hello", b"world"));
        assert!(!ct_bytes_eq(b"hello", b"hello!"));
    }
    
    #[test]
    fn test_ct_rejection_check() {
        assert_eq!(ct_rejection_check(100, 200), 1);
        assert_eq!(ct_rejection_check(200, 200), 0);
        assert_eq!(ct_rejection_check(300, 200), 0);
    }
}