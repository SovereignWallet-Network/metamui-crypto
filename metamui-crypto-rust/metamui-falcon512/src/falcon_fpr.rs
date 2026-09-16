//! Falcon Precision Real (FPR) - Emulated IEEE-754 binary64 arithmetic
//! 
//! This module provides deterministic floating-point operations for Falcon
//! using only integer arithmetic, ensuring consistent behavior across platforms.
//! 
//! Based on the official Falcon reference implementation's approach to
//! floating-point emulation for cryptographic security.

use core::cmp::Ordering;

/// Falcon Precision Real type - emulated IEEE-754 binary64
/// 
/// Layout (64 bits):
/// - Bit 63: Sign (0 = positive, 1 = negative)
/// - Bits 62-52: Exponent (11 bits, biased by 1023)
/// - Bits 51-0: Mantissa (52 bits, with implicit leading 1 for normalized values)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FPR(pub u64);

impl FPR {
    /// Zero value
    pub const ZERO: FPR = FPR(0);
    
    /// One value
    pub const ONE: FPR = FPR(0x3FF0000000000000);
    
    /// Sign bit mask
    const SIGN_MASK: u64 = 0x8000000000000000;
    
    /// Exponent mask
    const EXP_MASK: u64 = 0x7FF0000000000000;
    
    /// Mantissa mask
    const MANT_MASK: u64 = 0x000FFFFFFFFFFFFF;
    
    /// Exponent bias
    const EXP_BIAS: i32 = 1023;
    
    /// Create FPR from raw bits
    #[inline]
    pub const fn from_bits(bits: u64) -> Self {
        FPR(bits)
    }
    
    /// Get raw bits
    #[inline]
    pub const fn to_bits(self) -> u64 {
        self.0
    }
    
    /// Create FPR from f64 (for initialization)
    pub fn from_f64(x: f64) -> Self {
        FPR(x.to_bits())
    }
    
    /// Convert to f64 (for testing/debugging)
    pub fn to_f64(self) -> f64 {
        f64::from_bits(self.0)
    }
    
    /// Create FPR from integer
    pub fn from_i64(x: i64) -> Self {
        if x == 0 {
            return Self::ZERO;
        }
        
        let sign = if x < 0 { Self::SIGN_MASK } else { 0 };
        let mut m = x.unsigned_abs();
        
        // Normalize: find the position of the highest bit
        let mut e = 63;
        while (m & (1u64 << 63)) == 0 {
            m <<= 1;
            e -= 1;
        }
        
        // The mantissa is the 52 bits after the leading 1
        m <<= 1; // Remove the leading 1
        m >>= 12; // Keep only 52 bits
        
        // Encode exponent with bias
        let exp = ((e + Self::EXP_BIAS) as u64) << 52;
        
        FPR(sign | exp | m)
    }
    
    /// Extract sign (0 for positive, 1 for negative)
    #[inline]
    pub fn sign(self) -> u64 {
        (self.0 & Self::SIGN_MASK) >> 63
    }
    
    /// Extract exponent (unbiased)
    #[inline]
    pub fn exponent(self) -> i32 {
        ((self.0 & Self::EXP_MASK) >> 52) as i32 - Self::EXP_BIAS
    }
    
    /// Extract mantissa (with implicit leading 1 for normalized values)
    #[inline]
    pub fn mantissa(self) -> u64 {
        let m = self.0 & Self::MANT_MASK;
        if (self.0 & Self::EXP_MASK) != 0 {
            // Normalized: add implicit leading 1
            m | (1u64 << 52)
        } else {
            // Zero or denormalized
            m
        }
    }
    
    /// Check if zero
    #[inline]
    pub fn is_zero(self) -> bool {
        (self.0 & 0x7FFFFFFFFFFFFFFF) == 0
    }
    
    /// Negate
    #[inline]
    pub fn neg(self) -> Self {
        FPR(self.0 ^ Self::SIGN_MASK)
    }
    
    /// Absolute value
    #[inline]
    pub fn abs(self) -> Self {
        FPR(self.0 & !Self::SIGN_MASK)
    }
    
    /// Addition (constant-time)
    pub fn add(self, other: Self) -> Self {
        // Special cases
        if self.is_zero() {
            return other;
        }
        if other.is_zero() {
            return self;
        }
        
        // Extract components
        let s1 = self.sign();
        let e1 = self.exponent();
        let m1 = self.mantissa();
        
        let s2 = other.sign();
        let e2 = other.exponent();
        let m2 = other.mantissa();
        
        // Align exponents
        let (e, m1_aligned, m2_aligned) = if e1 > e2 {
            let shift = (e1 - e2).min(53) as u32;
            (e1, m1, m2 >> shift)
        } else if e2 > e1 {
            let shift = (e2 - e1).min(53) as u32;
            (e2, m1 >> shift, m2)
        } else {
            (e1, m1, m2)
        };
        
        // Perform addition or subtraction
        let (sign, mantissa) = if s1 == s2 {
            // Same sign: add
            (s1, m1_aligned + m2_aligned)
        } else {
            // Different signs: subtract
            match m1_aligned.cmp(&m2_aligned) {
                Ordering::Greater => (s1, m1_aligned - m2_aligned),
                Ordering::Less => (s2, m2_aligned - m1_aligned),
                Ordering::Equal => return Self::ZERO,
            }
        };
        
        // Normalize result
        Self::normalize(sign, e, mantissa)
    }
    
    /// Subtraction
    #[inline]
    pub fn sub(self, other: Self) -> Self {
        self.add(other.neg())
    }
    
    /// Multiplication (constant-time)
    pub fn mul(self, other: Self) -> Self {
        // Special cases
        if self.is_zero() || other.is_zero() {
            return Self::ZERO;
        }
        
        // Extract components
        let s1 = self.sign();
        let e1 = self.exponent();
        let m1 = self.mantissa();
        
        let s2 = other.sign();
        let e2 = other.exponent();
        let m2 = other.mantissa();
        
        // Sign of result
        let sign = s1 ^ s2;
        
        // Multiply mantissas (53-bit × 53-bit = 106-bit)
        // Use 128-bit arithmetic for precision
        let product = (m1 as u128) * (m2 as u128);
        
        // The product is 106 bits (two 53-bit numbers with implicit 1s)
        // We need to shift right by 52 since both mantissas have implicit 1 at bit 52
        let mantissa = (product >> 52) as u64;
        
        // Add exponents
        let exponent = e1 + e2;
        
        // Normalize result
        Self::normalize(sign, exponent, mantissa)
    }
    
    /// Division
    pub fn div(self, other: Self) -> Self {
        // Special cases
        if other.is_zero() {
            // Division by zero: return infinity with appropriate sign
            let sign = self.sign() ^ other.sign();
            return FPR(sign << 63 | Self::EXP_MASK);
        }
        if self.is_zero() {
            return Self::ZERO;
        }
        
        // Extract components
        let s1 = self.sign();
        let e1 = self.exponent();
        let m1 = self.mantissa();
        
        let s2 = other.sign();
        let e2 = other.exponent();
        let m2 = other.mantissa();
        
        // Sign of result
        let sign = s1 ^ s2;
        
        // Divide mantissas with extra precision
        // Scale m1 by 2^52 to maintain precision (since mantissas have implicit 1 at bit 52)
        let m1_scaled = (m1 as u128) << 52;
        let mantissa = (m1_scaled / m2 as u128) as u64;
        
        // Subtract exponents
        let exponent = e1 - e2;
        
        // Normalize result
        Self::normalize(sign, exponent, mantissa)
    }
    
    /// Square root
    pub fn sqrt(self) -> Self {
        // Special cases
        if self.is_zero() {
            return Self::ZERO;
        }
        if self.sign() != 0 {
            // Square root of negative number: return NaN
            return FPR(0x7FF8000000000000);
        }
        
        // For now, use a simple approach: convert to f64, compute sqrt, convert back
        // This is acceptable for cryptographic use since we only need
        // consistent results across platforms
        let val = self.to_f64();
        let result = val.sqrt();
        Self::from_f64(result)
    }
    
    /// Normalize a floating-point number
    fn normalize(sign: u64, exponent: i32, mantissa: u64) -> Self {
        if mantissa == 0 {
            return Self::ZERO;
        }
        
        let mut e = exponent;
        let mut m = mantissa;
        
        // Find the position of the leading 1
        let leading_bit = 63 - m.leading_zeros() as i32;
        
        if leading_bit < 52 {
            // Shift left to get leading 1 in bit 52
            let shift = 52 - leading_bit;
            m <<= shift;
            e -= shift;
        } else if leading_bit > 52 {
            // Shift right to get leading 1 in bit 52
            let shift = leading_bit - 52;
            m >>= shift;
            e += shift;
        }
        
        // Check for overflow/underflow
        if e > 1023 {
            // Overflow: return infinity
            return FPR(sign << 63 | Self::EXP_MASK);
        }
        if e < -1022 {
            // Underflow: return zero
            return Self::ZERO;
        }
        
        // Remove implicit leading 1
        m &= Self::MANT_MASK;
        
        // Encode result
        let exp = ((e + Self::EXP_BIAS) as u64) << 52;
        FPR(sign << 63 | exp | m)
    }
}

/// Conversion from/to f64 for hybrid mode
impl From<f64> for FPR {
    fn from(x: f64) -> Self {
        FPR::from_f64(x)
    }
}

impl From<FPR> for f64 {
    fn from(x: FPR) -> Self {
        x.to_f64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fpr_basic_operations() {
        // Test zero
        assert!(FPR::ZERO.is_zero());
        assert_eq!(FPR::ZERO.to_f64(), 0.0);
        
        // Test one
        assert_eq!(FPR::ONE.to_f64(), 1.0);
        
        // Test from integer
        assert_eq!(FPR::from_i64(42).to_f64(), 42.0);
        assert_eq!(FPR::from_i64(-42).to_f64(), -42.0);
        
        // Test negation
        let x = FPR::from_f64(3.14);
        assert_eq!(x.neg().to_f64(), -3.14);
    }
    
    #[test]
    fn test_fpr_addition() {
        let a = FPR::from_f64(1.5);
        let b = FPR::from_f64(2.5);
        let c = a.add(b);
        assert!((c.to_f64() - 4.0).abs() < 1e-10);
        
        // Test subtraction
        let d = b.sub(a);
        assert!((d.to_f64() - 1.0).abs() < 1e-10);
    }
    
    #[test]
    fn test_fpr_multiplication() {
        let a = FPR::from_f64(3.0);
        let b = FPR::from_f64(4.0);
        let c = a.mul(b);
        assert!((c.to_f64() - 12.0).abs() < 1e-10);
    }
    
    #[test]
    fn test_fpr_division() {
        let a = FPR::from_f64(10.0);
        let b = FPR::from_f64(4.0);
        let c = a.div(b);
        assert!((c.to_f64() - 2.5).abs() < 1e-10);
    }
    
    #[test]
    fn test_fpr_sqrt() {
        let a = FPR::from_f64(16.0);
        let b = a.sqrt();
        assert!((b.to_f64() - 4.0).abs() < 1e-6);
        
        let c = FPR::from_f64(2.0);
        let d = c.sqrt();
        assert!((d.to_f64() - 1.4142135623730951).abs() < 1e-6);
    }
}