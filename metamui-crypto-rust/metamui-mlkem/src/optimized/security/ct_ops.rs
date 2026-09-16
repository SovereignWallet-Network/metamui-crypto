//! Core constant-time operations

use metamui_security_utils::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Constant-time byte array operations
pub struct CtBytes;

impl CtBytes {
    /// Constant-time comparison of byte arrays
    #[inline]
    pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }
    
    /// Constant-time conditional copy
    #[inline]
    pub fn ct_copy(dest: &mut [u8], src: &[u8], choice: Choice) {
        debug_assert_eq!(dest.len(), src.len());
        for (d, s) in dest.iter_mut().zip(src.iter()) {
            *d = u8::conditional_select(d, s, choice);
        }
    }
    
    /// Constant-time conditional swap
    #[inline]
    pub fn ct_swap(a: &mut [u8], b: &mut [u8], choice: Choice) {
        debug_assert_eq!(a.len(), b.len());
        for (x, y) in a.iter_mut().zip(b.iter_mut()) {
            let tmp = *x;
            *x = u8::conditional_select(x, y, choice);
            *y = u8::conditional_select(y, &tmp, choice);
        }
    }
    
    /// Constant-time XOR operation
    #[inline]
    pub fn ct_xor(dest: &mut [u8], src: &[u8]) {
        debug_assert_eq!(dest.len(), src.len());
        for (d, s) in dest.iter_mut().zip(src.iter()) {
            *d ^= s;
        }
    }
    
    /// Constant-time AND operation
    #[inline]
    pub fn ct_and(dest: &mut [u8], src: &[u8]) {
        debug_assert_eq!(dest.len(), src.len());
        for (d, s) in dest.iter_mut().zip(src.iter()) {
            *d &= s;
        }
    }
    
    /// Constant-time OR operation
    #[inline]
    pub fn ct_or(dest: &mut [u8], src: &[u8]) {
        debug_assert_eq!(dest.len(), src.len());
        for (d, s) in dest.iter_mut().zip(src.iter()) {
            *d |= s;
        }
    }
    
    /// Constant-time byte array zeroing
    #[inline]
    pub fn ct_zero(data: &mut [u8]) {
        for byte in data.iter_mut() {
            *byte = 0u8;
        }
        // Memory barrier to prevent optimization
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Constant-time integer operations
pub struct CtInt;

impl CtInt {
    /// Constant-time u16 comparison
    #[inline]
    pub fn ct_eq_u16(a: u16, b: u16) -> Choice {
        a.ct_eq(&b)
    }
    
    /// Constant-time u32 comparison
    #[inline]
    pub fn ct_eq_u32(a: u32, b: u32) -> Choice {
        a.ct_eq(&b)
    }
    
    /// Constant-time u64 comparison
    #[inline]
    pub fn ct_eq_u64(a: u64, b: u64) -> Choice {
        a.ct_eq(&b)
    }
    
    /// Constant-time u16 selection
    #[inline]
    pub fn ct_select_u16(a: u16, b: u16, choice: Choice) -> u16 {
        u16::conditional_select(&a, &b, choice)
    }
    
    /// Constant-time u32 selection
    #[inline]
    pub fn ct_select_u32(a: u32, b: u32, choice: Choice) -> u32 {
        u32::conditional_select(&a, &b, choice)
    }
    
    /// Constant-time u64 selection
    #[inline]
    pub fn ct_select_u64(a: u64, b: u64, choice: Choice) -> u64 {
        u64::conditional_select(&a, &b, choice)
    }
    
    /// Constant-time less than comparison for u16
    #[inline]
    pub fn ct_lt_u16(a: u16, b: u16) -> Choice {
        let diff = (b as i32) - (a as i32);
        Choice::from(((diff >> 31) & 1) as u8)
    }
    
    /// Constant-time less than or equal comparison for u16
    #[inline]
    pub fn ct_le_u16(a: u16, b: u16) -> Choice {
        Self::ct_lt_u16(a, b) | a.ct_eq(&b)
    }
    
    /// Constant-time greater than comparison for u16
    #[inline]
    pub fn ct_gt_u16(a: u16, b: u16) -> Choice {
        Self::ct_lt_u16(b, a)
    }
    
    /// Constant-time greater than or equal comparison for u16
    #[inline]
    pub fn ct_ge_u16(a: u16, b: u16) -> Choice {
        !Self::ct_lt_u16(a, b)
    }
}

/// Polynomial coefficient operations with constant-time guarantees
pub struct CtPoly;

impl CtPoly {
    /// ML-KEM modulus
    pub const Q: u16 = 3329;
    pub const Q_INV: u32 = 3327; // -q^{-1} mod 2^16
    pub const BARRETT_CONST: u32 = 20159; // floor(2^26 / q)
    pub const MONTGOMERY_R: u32 = 1353; // 2^16 mod q
    
    /// Constant-time Barrett reduction
    #[inline]
    pub fn ct_barrett_reduce(a: u32) -> u16 {
        let quotient = ((a as u64 * Self::BARRETT_CONST as u64) >> 26) as u32;
        let remainder = a - quotient * Self::Q as u32;
        
        // Conditional subtraction
        let reduced = remainder.wrapping_sub(Self::Q as u32);
        let choice = Choice::from((remainder >= Self::Q as u32) as u8);
        u16::conditional_select(&(remainder as u16), &(reduced as u16), choice)
    }
    
    /// Constant-time Montgomery reduction
    #[inline]
    pub fn ct_montgomery_reduce(a: u32) -> u16 {
        let q = ((a.wrapping_mul(Self::Q_INV)) & 0xFFFF) as u32;
        let t = a.wrapping_add(q.wrapping_mul(Self::Q as u32)) >> 16;
        
        // Conditional subtraction
        let reduced = t.wrapping_sub(Self::Q as u32);
        let choice = Choice::from((t >= Self::Q as u32) as u8);
        u16::conditional_select(&(t as u16), &(reduced as u16), choice)
    }
    
    /// Constant-time modular addition
    #[inline]
    pub fn ct_add_mod(a: u16, b: u16) -> u16 {
        let sum = a.wrapping_add(b);
        let reduced = sum.wrapping_sub(Self::Q);
        let choice = Choice::from((sum >= Self::Q) as u8);
        u16::conditional_select(&sum, &reduced, choice)
    }
    
    /// Constant-time modular subtraction
    #[inline]
    pub fn ct_sub_mod(a: u16, b: u16) -> u16 {
        let diff = a.wrapping_sub(b);
        let adjusted = diff.wrapping_add(Self::Q);
        let choice = Choice::from((a < b) as u8);
        u16::conditional_select(&diff, &adjusted, choice)
    }
    
    /// Constant-time modular multiplication using Barrett reduction
    #[inline]
    pub fn ct_mul_mod(a: u16, b: u16) -> u16 {
        Self::ct_barrett_reduce((a as u32) * (b as u32))
    }
    
    /// Constant-time coefficient comparison
    #[inline]
    pub fn ct_coeff_eq(a: u16, b: u16) -> bool {
        a.ct_eq(&b).into()
    }
    
    /// Constant-time coefficient selection
    #[inline]
    pub fn ct_coeff_select(a: u16, b: u16, choice: Choice) -> u16 {
        u16::conditional_select(&a, &b, choice)
    }
    
    /// Constant-time polynomial addition
    #[inline]
    pub fn ct_poly_add(dest: &mut [u16], a: &[u16], b: &[u16]) {
        debug_assert_eq!(dest.len(), a.len());
        debug_assert_eq!(dest.len(), b.len());
        
        for i in 0..dest.len() {
            dest[i] = Self::ct_add_mod(a[i], b[i]);
        }
    }
    
    /// Constant-time polynomial subtraction
    #[inline]
    pub fn ct_poly_sub(dest: &mut [u16], a: &[u16], b: &[u16]) {
        debug_assert_eq!(dest.len(), a.len());
        debug_assert_eq!(dest.len(), b.len());
        
        for i in 0..dest.len() {
            dest[i] = Self::ct_sub_mod(a[i], b[i]);
        }
    }
    
    /// Constant-time polynomial multiplication (pointwise)
    #[inline]
    pub fn ct_poly_mul_pointwise(dest: &mut [u16], a: &[u16], b: &[u16]) {
        debug_assert_eq!(dest.len(), a.len());
        debug_assert_eq!(dest.len(), b.len());
        
        for i in 0..dest.len() {
            dest[i] = Self::ct_mul_mod(a[i], b[i]);
        }
    }
    
    /// Constant-time centered reduction to [-q/2, q/2]
    #[inline]
    pub fn ct_center_reduce(a: u16) -> i16 {
        let half_q = (Self::Q + 1) / 2;
        let choice = Choice::from((a >= half_q) as u8);
        let reduced = a.wrapping_sub(Self::Q);
        let result = u16::conditional_select(&a, &reduced, choice);
        result as i16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ct_bytes_operations() {
        let mut a = [1u8, 2, 3, 4];
        let b = [5u8, 6, 7, 8];
        
        // Test equality
        assert!(!CtBytes::ct_eq(&a, &b));
        assert!(CtBytes::ct_eq(&a, &[1, 2, 3, 4]));
        
        // Test conditional copy
        let choice_true = Choice::from(1u8);
        let choice_false = Choice::from(0u8);
        
        let mut dest = [0u8; 4];
        CtBytes::ct_copy(&mut dest, &b, choice_true);
        assert_eq!(dest, b);
        
        CtBytes::ct_copy(&mut dest, &a, choice_false);
        assert_eq!(dest, b); // Should not change
        
        // Test swap
        let mut x = [1u8, 2];
        let mut y = [3u8, 4];
        CtBytes::ct_swap(&mut x, &mut y, choice_true);
        assert_eq!(x, [3, 4]);
        assert_eq!(y, [1, 2]);
    }
    
    #[test]
    fn test_ct_int_operations() {
        // Test comparisons
        assert_eq!(CtInt::ct_lt_u16(100, 200).unwrap_u8(), 1);
        assert_eq!(CtInt::ct_lt_u16(200, 100).unwrap_u8(), 0);
        assert_eq!(CtInt::ct_le_u16(100, 100).unwrap_u8(), 1);
        assert_eq!(CtInt::ct_gt_u16(200, 100).unwrap_u8(), 1);
        
        // Test selection
        let choice_true = Choice::from(1u8);
        let choice_false = Choice::from(0u8);
        
        assert_eq!(CtInt::ct_select_u16(100, 200, choice_true), 100);
        assert_eq!(CtInt::ct_select_u16(100, 200, choice_false), 200);
    }
    
    #[test]
    fn test_ct_poly_operations() {
        // Test Barrett reduction
        let a = 10000u32;
        let reduced = CtPoly::ct_barrett_reduce(a);
        assert!(reduced < CtPoly::Q);
        assert_eq!(reduced, (a % CtPoly::Q as u32) as u16);
        
        // Test modular arithmetic
        let x = 3000u16;
        let y = 500u16;
        
        let sum = CtPoly::ct_add_mod(x, y);
        assert!(sum < CtPoly::Q);
        assert_eq!(sum, ((x as u32 + y as u32) % CtPoly::Q as u32) as u16);
        
        let diff = CtPoly::ct_sub_mod(y, x);
        assert!(diff < CtPoly::Q);
        
        // Test polynomial operations
        let mut dest = [0u16; 4];
        let a = [100u16, 200, 300, 400];
        let b = [50u16, 100, 150, 200];
        
        CtPoly::ct_poly_add(&mut dest, &a, &b);
        for i in 0..4 {
            assert_eq!(dest[i], CtPoly::ct_add_mod(a[i], b[i]));
        }
    }
    
    #[test]
    fn test_ct_center_reduce() {
        let half_q = (CtPoly::Q + 1) / 2;
        
        // Test values below half_q
        assert_eq!(CtPoly::ct_center_reduce(100), 100);
        assert_eq!(CtPoly::ct_center_reduce(half_q - 1), (half_q - 1) as i16);
        
        // Test values at and above half_q
        assert_eq!(CtPoly::ct_center_reduce(half_q), 
                   (half_q as i32 - CtPoly::Q as i32) as i16);
        assert_eq!(CtPoly::ct_center_reduce(CtPoly::Q - 1), -1);
    }
}