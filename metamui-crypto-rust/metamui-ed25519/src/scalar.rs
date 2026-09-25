//! Scalar arithmetic modulo curve order l = 2^252 + 27742317777372353535851937790883648493
//! 
//! This module implements arithmetic operations on 256-bit scalars modulo the Ed25519 curve order.
//! Based on the ref10 implementation.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use core::ops::{Add, Sub, Mul, Neg};

/// Ed25519 curve order l = 2^252 + 27742317777372353535851937790883648493
/// In little-endian bytes
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// A scalar in the range [0, L)
#[derive(Copy, Clone, Debug)]
pub struct Scalar {
    /// Internal representation as bytes
    bytes: [u8; 32],
}

impl Scalar {
    /// The scalar zero
    pub const ZERO: Scalar = Scalar { bytes: [0; 32] };
    
    /// The scalar one  
    pub const ONE: Scalar = Scalar { 
        bytes: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    };
    
    /// Create a scalar from bytes (little-endian), ensuring it's in range [0, L)
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
        // Check if bytes represent a scalar less than L
        if is_less_than_l(bytes) {
            Some(Scalar { bytes: *bytes })
        } else {
            None
        }
    }
    
    /// Create a scalar from bytes, reducing modulo L
    pub fn from_bytes_mod_order(bytes: &[u8]) -> Scalar {
        if bytes.len() == 32 {
            // First try without reduction if possible
            let mut bytes_32 = [0u8; 32];
            bytes_32.copy_from_slice(&bytes[..32]);
            if let Some(scalar) = Scalar::from_bytes(&bytes_32) {
                return scalar;
            }
        }
        
        // Otherwise reduce modulo L
        let mut temp = [0u8; 64];
        let len = bytes.len().min(64);
        temp[..len].copy_from_slice(&bytes[..len]);
        
        sc_reduce(&mut temp);
        
        let mut result_bytes = [0u8; 32];
        result_bytes.copy_from_slice(&temp[..32]);
        Scalar { bytes: result_bytes }
    }
    
    /// Convert scalar to bytes (little-endian)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }
    
    /// Returns the scalar zero
    pub fn zero() -> Scalar {
        Self::ZERO
    }
    
    /// Returns the scalar one
    pub fn one() -> Scalar {
        Self::ONE
    }
    
    /// Check if the scalar is zero
    pub fn is_zero(&self) -> bool {
        self.ct_eq(&Self::ZERO).into()
    }
    
    /// Check if the scalar is canonical (always true for our representation)
    pub fn is_canonical(&self) -> bool {
        is_less_than_l(&self.bytes)
    }
    
    /// Get bit at position i (0 = LSB, 255 = MSB)
    pub fn bit(&self, i: usize) -> Choice {
        if i >= 256 {
            return Choice::from(0);
        }
        
        let byte_index = i / 8;
        let bit_index = i % 8;
        
        Choice::from((self.bytes[byte_index] >> bit_index) & 1)
    }
    
    /// Multiply two scalars modulo L
    pub fn multiply(&self, other: &Scalar) -> Scalar {
        let mut result = [0u8; 32];
        sc_muladd(&mut result, &self.bytes, &other.bytes, &[0u8; 32]);
        Scalar { bytes: result }
    }
    
    /// Add two scalars modulo L
    pub fn add(&self, other: &Scalar) -> Scalar {
        // We'll use sc_muladd with a=1, b=self, c=other
        // So result = 1*self + other = self + other
        let one = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut result = [0u8; 32];
        sc_muladd(&mut result, &one, &self.bytes, &other.bytes);
        Scalar { bytes: result }
    }
    
    /// Subtract two scalars modulo L
    pub fn subtract(&self, other: &Scalar) -> Scalar {
        // Compute self - other = self + (-other)
        let neg_other = other.negate();
        self.add(&neg_other)
    }
    
    /// Negate a scalar modulo L
    pub fn negate(&self) -> Scalar {
        // -x mod L = L - x
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&L);
        
        // Subtract self from L using borrow propagation
        let mut borrow = 0i32;
        for i in 0..32 {
            let diff = (result[i] as i32) - (self.bytes[i] as i32) - borrow;
            if diff < 0 {
                result[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                result[i] = diff as u8;
                borrow = 0;
            }
        }
        
        // Result is already reduced since L - x < L for any x < L
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&result[..32]);
        Scalar { bytes: scalar_bytes }
    }
    
    /// Compute a * b + c mod L
    pub fn multiply_add(&a: &Scalar, &b: &Scalar, &c: &Scalar) -> Scalar {
        let mut result = [0u8; 32];
        sc_muladd(&mut result, &a.bytes, &b.bytes, &c.bytes);
        Scalar { bytes: result }
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::conditional_select(&a.bytes[i], &b.bytes[i], choice);
        }
        Scalar { bytes }
    }
}

impl Add for Scalar {
    type Output = Scalar;
    
    fn add(self, other: Self) -> Scalar {
        (&self).add(&other)
    }
}

impl Add for &Scalar {
    type Output = Scalar;
    
    fn add(self, other: Self) -> Scalar {
        self.add(other)
    }
}

impl Sub for Scalar {
    type Output = Scalar;
    
    fn sub(self, other: Self) -> Scalar {
        (&self).subtract(&other)
    }
}

impl Sub for &Scalar {
    type Output = Scalar;
    
    fn sub(self, other: Self) -> Scalar {
        self.subtract(other)
    }
}

impl Mul for Scalar {
    type Output = Scalar;
    
    fn mul(self, other: Self) -> Scalar {
        (&self).multiply(&other)
    }
}

impl Mul for &Scalar {
    type Output = Scalar;
    
    fn mul(self, other: Self) -> Scalar {
        self.multiply(other)
    }
}

impl Neg for Scalar {
    type Output = Scalar;
    
    fn neg(self) -> Scalar {
        self.negate()
    }
}

impl Neg for &Scalar {
    type Output = Scalar;
    
    fn neg(self) -> Scalar {
        self.negate()
    }
}

/// Check if scalar bytes are less than L
fn is_less_than_l(s: &[u8; 32]) -> bool {
    // Compare bytes in little-endian order
    for i in (0..32).rev() {
        match s[i].cmp(&L[i]) {
            core::cmp::Ordering::Less => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal => continue,
        }
    }
    // If all bytes are equal, it's not less than L
    false
}

/// Load 3 bytes as a 64-bit integer (little-endian)
fn load_3(input: &[u8]) -> u64 {
    let mut result = 0u64;
    result |= input[0] as u64;
    result |= (input[1] as u64) << 8;
    result |= (input[2] as u64) << 16;
    result
}

/// Load 4 bytes as a 64-bit integer (little-endian)
fn load_4(input: &[u8]) -> u64 {
    let mut result = 0u64;
    result |= input[0] as u64;
    result |= (input[1] as u64) << 8;
    result |= (input[2] as u64) << 16;
    result |= (input[3] as u64) << 24;
    result
}

/// Reduce a 512-bit scalar to 256-bit scalar modulo l
/// Based on ref10 sc_reduce
fn sc_reduce(s: &mut [u8; 64]) {
    let mut s0 = (2097151 & load_3(&s[0..])) as i64;
    let mut s1 = (2097151 & (load_4(&s[2..]) >> 5)) as i64;
    let mut s2 = (2097151 & (load_3(&s[5..]) >> 2)) as i64;
    let mut s3 = (2097151 & (load_4(&s[7..]) >> 7)) as i64;
    let mut s4 = (2097151 & (load_4(&s[10..]) >> 4)) as i64;
    let mut s5 = (2097151 & (load_3(&s[13..]) >> 1)) as i64;
    let mut s6 = (2097151 & (load_4(&s[15..]) >> 6)) as i64;
    let mut s7 = (2097151 & (load_3(&s[18..]) >> 3)) as i64;
    let mut s8 = (2097151 & load_3(&s[21..])) as i64;
    let mut s9 = (2097151 & (load_4(&s[23..]) >> 5)) as i64;
    let mut s10 = (2097151 & (load_3(&s[26..]) >> 2)) as i64;
    let mut s11 = (2097151 & (load_4(&s[28..]) >> 7)) as i64;
    let mut s12 = (2097151 & (load_4(&s[31..]) >> 4)) as i64;
    let mut s13 = (2097151 & (load_3(&s[34..]) >> 1)) as i64;
    let mut s14 = (2097151 & (load_4(&s[36..]) >> 6)) as i64;
    let mut s15 = (2097151 & (load_3(&s[39..]) >> 3)) as i64;
    let mut s16 = (2097151 & load_3(&s[42..])) as i64;
    let mut s17 = (2097151 & (load_4(&s[44..]) >> 5)) as i64;
    let s18 = (2097151 & (load_3(&s[47..]) >> 2)) as i64;
    let s19 = (2097151 & (load_4(&s[49..]) >> 7)) as i64;
    let s20 = (2097151 & (load_4(&s[52..]) >> 4)) as i64;
    let s21 = (2097151 & (load_3(&s[55..]) >> 1)) as i64;
    let s22 = (2097151 & (load_4(&s[57..]) >> 6)) as i64;
    let s23 = (load_4(&s[60..]) >> 3) as i64;

    let mut carry: i128;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;

    // First carry chain
    carry = ((s6 as i128) + (1i128<<20)) >> 21; s7 += carry as i64; s6 -= (carry << 21) as i64;
    carry = ((s8 as i128) + (1i128<<20)) >> 21; s9 += carry as i64; s8 -= (carry << 21) as i64;
    carry = ((s10 as i128) + (1i128<<20)) >> 21; s11 += carry as i64; s10 -= (carry << 21) as i64;
    carry = ((s12 as i128) + (1i128<<20)) >> 21; s13 += carry as i64; s12 -= (carry << 21) as i64;
    carry = ((s14 as i128) + (1i128<<20)) >> 21; s15 += carry as i64; s14 -= (carry << 21) as i64;
    carry = ((s16 as i128) + (1i128<<20)) >> 21; s17 += carry as i64; s16 -= (carry << 21) as i64;

    carry = ((s7 as i128) + (1i128<<20)) >> 21; s8 += carry as i64; s7 -= (carry << 21) as i64;
    carry = ((s9 as i128) + (1i128<<20)) >> 21; s10 += carry as i64; s9 -= (carry << 21) as i64;
    carry = ((s11 as i128) + (1i128<<20)) >> 21; s12 += carry as i64; s11 -= (carry << 21) as i64;
    carry = ((s13 as i128) + (1i128<<20)) >> 21; s14 += carry as i64; s13 -= (carry << 21) as i64;
    carry = ((s15 as i128) + (1i128<<20)) >> 21; s16 += carry as i64; s15 -= (carry << 21) as i64;

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    // Second carry chain
    carry = ((s0 as i128) + (1i128<<20)) >> 21; s1 += carry as i64; s0 -= (carry << 21) as i64;
    carry = ((s2 as i128) + (1i128<<20)) >> 21; s3 += carry as i64; s2 -= (carry << 21) as i64;
    carry = ((s4 as i128) + (1i128<<20)) >> 21; s5 += carry as i64; s4 -= (carry << 21) as i64;
    carry = ((s6 as i128) + (1i128<<20)) >> 21; s7 += carry as i64; s6 -= (carry << 21) as i64;
    carry = ((s8 as i128) + (1i128<<20)) >> 21; s9 += carry as i64; s8 -= (carry << 21) as i64;
    carry = ((s10 as i128) + (1i128<<20)) >> 21; s11 += carry as i64; s10 -= (carry << 21) as i64;

    carry = ((s1 as i128) + (1i128<<20)) >> 21; s2 += carry as i64; s1 -= (carry << 21) as i64;
    carry = ((s3 as i128) + (1i128<<20)) >> 21; s4 += carry as i64; s3 -= (carry << 21) as i64;
    carry = ((s5 as i128) + (1i128<<20)) >> 21; s6 += carry as i64; s5 -= (carry << 21) as i64;
    carry = ((s7 as i128) + (1i128<<20)) >> 21; s8 += carry as i64; s7 -= (carry << 21) as i64;
    carry = ((s9 as i128) + (1i128<<20)) >> 21; s10 += carry as i64; s9 -= (carry << 21) as i64;
    carry = ((s11 as i128) + (1i128<<20)) >> 21; s12 += carry as i64; s11 -= (carry << 21) as i64;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    // Final carry
    carry = (s0 as i128) >> 21; s1 += carry as i64; s0 -= (carry << 21) as i64;
    carry = (s1 as i128) >> 21; s2 += carry as i64; s1 -= (carry << 21) as i64;
    carry = (s2 as i128) >> 21; s3 += carry as i64; s2 -= (carry << 21) as i64;
    carry = (s3 as i128) >> 21; s4 += carry as i64; s3 -= (carry << 21) as i64;
    carry = (s4 as i128) >> 21; s5 += carry as i64; s4 -= (carry << 21) as i64;
    carry = (s5 as i128) >> 21; s6 += carry as i64; s5 -= (carry << 21) as i64;
    carry = (s6 as i128) >> 21; s7 += carry as i64; s6 -= (carry << 21) as i64;
    carry = (s7 as i128) >> 21; s8 += carry as i64; s7 -= (carry << 21) as i64;
    carry = (s8 as i128) >> 21; s9 += carry as i64; s8 -= (carry << 21) as i64;
    carry = (s9 as i128) >> 21; s10 += carry as i64; s9 -= (carry << 21) as i64;
    carry = (s10 as i128) >> 21; s11 += carry as i64; s10 -= (carry << 21) as i64;
    carry = (s11 as i128) >> 21; s12 += carry as i64; s11 -= (carry << 21) as i64;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;

    // Final carries to ensure result fits in 21 bits per limb
    carry = (s0 as i128) >> 21; s1 += carry as i64; s0 -= (carry << 21) as i64;
    carry = (s1 as i128) >> 21; s2 += carry as i64; s1 -= (carry << 21) as i64;
    carry = (s2 as i128) >> 21; s3 += carry as i64; s2 -= (carry << 21) as i64;
    carry = (s3 as i128) >> 21; s4 += carry as i64; s3 -= (carry << 21) as i64;
    carry = (s4 as i128) >> 21; s5 += carry as i64; s4 -= (carry << 21) as i64;
    carry = (s5 as i128) >> 21; s6 += carry as i64; s5 -= (carry << 21) as i64;
    carry = (s6 as i128) >> 21; s7 += carry as i64; s6 -= (carry << 21) as i64;
    carry = (s7 as i128) >> 21; s8 += carry as i64; s7 -= (carry << 21) as i64;
    carry = (s8 as i128) >> 21; s9 += carry as i64; s8 -= (carry << 21) as i64;
    carry = (s9 as i128) >> 21; s10 += carry as i64; s9 -= (carry << 21) as i64;
    carry = (s10 as i128) >> 21; s11 += carry as i64; s10 -= (carry << 21) as i64;

    // Pack into bytes
    s[0] = s0 as u8;
    s[1] = (s0 >> 8) as u8;
    s[2] = ((s0 >> 16) | (s1 << 5)) as u8;
    s[3] = (s1 >> 3) as u8;
    s[4] = (s1 >> 11) as u8;
    s[5] = ((s1 >> 19) | (s2 << 2)) as u8;
    s[6] = (s2 >> 6) as u8;
    s[7] = ((s2 >> 14) | (s3 << 7)) as u8;
    s[8] = (s3 >> 1) as u8;
    s[9] = (s3 >> 9) as u8;
    s[10] = ((s3 >> 17) | (s4 << 4)) as u8;
    s[11] = (s4 >> 4) as u8;
    s[12] = (s4 >> 12) as u8;
    s[13] = ((s4 >> 20) | (s5 << 1)) as u8;
    s[14] = (s5 >> 7) as u8;
    s[15] = ((s5 >> 15) | (s6 << 6)) as u8;
    s[16] = (s6 >> 2) as u8;
    s[17] = (s6 >> 10) as u8;
    s[18] = ((s6 >> 18) | (s7 << 3)) as u8;
    s[19] = (s7 >> 5) as u8;
    s[20] = (s7 >> 13) as u8;
    s[21] = s8 as u8;
    s[22] = (s8 >> 8) as u8;
    s[23] = ((s8 >> 16) | (s9 << 5)) as u8;
    s[24] = (s9 >> 3) as u8;
    s[25] = (s9 >> 11) as u8;
    s[26] = ((s9 >> 19) | (s10 << 2)) as u8;
    s[27] = (s10 >> 6) as u8;
    s[28] = ((s10 >> 14) | (s11 << 7)) as u8;
    s[29] = (s11 >> 1) as u8;
    s[30] = (s11 >> 9) as u8;
    s[31] = (s11 >> 17) as u8;

    // Clear upper bytes
    for i in 32..64 {
        s[i] = 0;
    }
}

/// Scalar multiplication and addition: s = (a * b + c) mod l
/// Based on ref10 sc_muladd
fn sc_muladd(s: &mut [u8; 32], a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) {
    let a0 = (2097151 & load_3(&a[0..])) as i64;
    let a1 = (2097151 & (load_4(&a[2..]) >> 5)) as i64;
    let a2 = (2097151 & (load_3(&a[5..]) >> 2)) as i64;
    let a3 = (2097151 & (load_4(&a[7..]) >> 7)) as i64;
    let a4 = (2097151 & (load_4(&a[10..]) >> 4)) as i64;
    let a5 = (2097151 & (load_3(&a[13..]) >> 1)) as i64;
    let a6 = (2097151 & (load_4(&a[15..]) >> 6)) as i64;
    let a7 = (2097151 & (load_3(&a[18..]) >> 3)) as i64;
    let a8 = (2097151 & load_3(&a[21..])) as i64;
    let a9 = (2097151 & (load_4(&a[23..]) >> 5)) as i64;
    let a10 = (2097151 & (load_3(&a[26..]) >> 2)) as i64;
    let a11 = (load_4(&a[28..]) >> 7) as i64;

    let b0 = (2097151 & load_3(&b[0..])) as i64;
    let b1 = (2097151 & (load_4(&b[2..]) >> 5)) as i64;
    let b2 = (2097151 & (load_3(&b[5..]) >> 2)) as i64;
    let b3 = (2097151 & (load_4(&b[7..]) >> 7)) as i64;
    let b4 = (2097151 & (load_4(&b[10..]) >> 4)) as i64;
    let b5 = (2097151 & (load_3(&b[13..]) >> 1)) as i64;
    let b6 = (2097151 & (load_4(&b[15..]) >> 6)) as i64;
    let b7 = (2097151 & (load_3(&b[18..]) >> 3)) as i64;
    let b8 = (2097151 & load_3(&b[21..])) as i64;
    let b9 = (2097151 & (load_4(&b[23..]) >> 5)) as i64;
    let b10 = (2097151 & (load_3(&b[26..]) >> 2)) as i64;
    let b11 = (load_4(&b[28..]) >> 7) as i64;

    let c0 = (2097151 & load_3(&c[0..])) as i64;
    let c1 = (2097151 & (load_4(&c[2..]) >> 5)) as i64;
    let c2 = (2097151 & (load_3(&c[5..]) >> 2)) as i64;
    let c3 = (2097151 & (load_4(&c[7..]) >> 7)) as i64;
    let c4 = (2097151 & (load_4(&c[10..]) >> 4)) as i64;
    let c5 = (2097151 & (load_3(&c[13..]) >> 1)) as i64;
    let c6 = (2097151 & (load_4(&c[15..]) >> 6)) as i64;
    let c7 = (2097151 & (load_3(&c[18..]) >> 3)) as i64;
    let c8 = (2097151 & load_3(&c[21..])) as i64;
    let c9 = (2097151 & (load_4(&c[23..]) >> 5)) as i64;
    let c10 = (2097151 & (load_3(&c[26..]) >> 2)) as i64;
    let c11 = (load_4(&c[28..]) >> 7) as i64;

    // Compute a * b using 128-bit intermediate values to avoid overflow
    let mut s0 = c0 as i128 + (a0 as i128)*(b0 as i128);
    let mut s1 = c1 as i128 + (a0 as i128)*(b1 as i128) + (a1 as i128)*(b0 as i128);
    let mut s2 = c2 as i128 + (a0 as i128)*(b2 as i128) + (a1 as i128)*(b1 as i128) + (a2 as i128)*(b0 as i128);
    let mut s3 = c3 as i128 + (a0 as i128)*(b3 as i128) + (a1 as i128)*(b2 as i128) + (a2 as i128)*(b1 as i128) + (a3 as i128)*(b0 as i128);
    let mut s4 = c4 as i128 + (a0 as i128)*(b4 as i128) + (a1 as i128)*(b3 as i128) + (a2 as i128)*(b2 as i128) + (a3 as i128)*(b1 as i128) + (a4 as i128)*(b0 as i128);
    let mut s5 = c5 as i128 + (a0 as i128)*(b5 as i128) + (a1 as i128)*(b4 as i128) + (a2 as i128)*(b3 as i128) + (a3 as i128)*(b2 as i128) + (a4 as i128)*(b1 as i128) + (a5 as i128)*(b0 as i128);
    let mut s6 = c6 as i128 + (a0 as i128)*(b6 as i128) + (a1 as i128)*(b5 as i128) + (a2 as i128)*(b4 as i128) + (a3 as i128)*(b3 as i128) + (a4 as i128)*(b2 as i128) + (a5 as i128)*(b1 as i128) + (a6 as i128)*(b0 as i128);
    let mut s7 = c7 as i128 + (a0 as i128)*(b7 as i128) + (a1 as i128)*(b6 as i128) + (a2 as i128)*(b5 as i128) + (a3 as i128)*(b4 as i128) + (a4 as i128)*(b3 as i128) + (a5 as i128)*(b2 as i128) + (a6 as i128)*(b1 as i128) + (a7 as i128)*(b0 as i128);
    let mut s8 = c8 as i128 + (a0 as i128)*(b8 as i128) + (a1 as i128)*(b7 as i128) + (a2 as i128)*(b6 as i128) + (a3 as i128)*(b5 as i128) + (a4 as i128)*(b4 as i128) + (a5 as i128)*(b3 as i128) + (a6 as i128)*(b2 as i128) + (a7 as i128)*(b1 as i128) + (a8 as i128)*(b0 as i128);
    let mut s9 = c9 as i128 + (a0 as i128)*(b9 as i128) + (a1 as i128)*(b8 as i128) + (a2 as i128)*(b7 as i128) + (a3 as i128)*(b6 as i128) + (a4 as i128)*(b5 as i128) + (a5 as i128)*(b4 as i128) + (a6 as i128)*(b3 as i128) + (a7 as i128)*(b2 as i128) + (a8 as i128)*(b1 as i128) + (a9 as i128)*(b0 as i128);
    let mut s10 = c10 as i128 + (a0 as i128)*(b10 as i128) + (a1 as i128)*(b9 as i128) + (a2 as i128)*(b8 as i128) + (a3 as i128)*(b7 as i128) + (a4 as i128)*(b6 as i128) + (a5 as i128)*(b5 as i128) + (a6 as i128)*(b4 as i128) + (a7 as i128)*(b3 as i128) + (a8 as i128)*(b2 as i128) + (a9 as i128)*(b1 as i128) + (a10 as i128)*(b0 as i128);
    let mut s11 = c11 as i128 + (a0 as i128)*(b11 as i128) + (a1 as i128)*(b10 as i128) + (a2 as i128)*(b9 as i128) + (a3 as i128)*(b8 as i128) + (a4 as i128)*(b7 as i128) + (a5 as i128)*(b6 as i128) + (a6 as i128)*(b5 as i128) + (a7 as i128)*(b4 as i128) + (a8 as i128)*(b3 as i128) + (a9 as i128)*(b2 as i128) + (a10 as i128)*(b1 as i128) + (a11 as i128)*(b0 as i128);
    let mut s12 = (a1 as i128)*(b11 as i128) + (a2 as i128)*(b10 as i128) + (a3 as i128)*(b9 as i128) + (a4 as i128)*(b8 as i128) + (a5 as i128)*(b7 as i128) + (a6 as i128)*(b6 as i128) + (a7 as i128)*(b5 as i128) + (a8 as i128)*(b4 as i128) + (a9 as i128)*(b3 as i128) + (a10 as i128)*(b2 as i128) + (a11 as i128)*(b1 as i128);
    let mut s13 = (a2 as i128)*(b11 as i128) + (a3 as i128)*(b10 as i128) + (a4 as i128)*(b9 as i128) + (a5 as i128)*(b8 as i128) + (a6 as i128)*(b7 as i128) + (a7 as i128)*(b6 as i128) + (a8 as i128)*(b5 as i128) + (a9 as i128)*(b4 as i128) + (a10 as i128)*(b3 as i128) + (a11 as i128)*(b2 as i128);
    let mut s14 = (a3 as i128)*(b11 as i128) + (a4 as i128)*(b10 as i128) + (a5 as i128)*(b9 as i128) + (a6 as i128)*(b8 as i128) + (a7 as i128)*(b7 as i128) + (a8 as i128)*(b6 as i128) + (a9 as i128)*(b5 as i128) + (a10 as i128)*(b4 as i128) + (a11 as i128)*(b3 as i128);
    let mut s15 = (a4 as i128)*(b11 as i128) + (a5 as i128)*(b10 as i128) + (a6 as i128)*(b9 as i128) + (a7 as i128)*(b8 as i128) + (a8 as i128)*(b7 as i128) + (a9 as i128)*(b6 as i128) + (a10 as i128)*(b5 as i128) + (a11 as i128)*(b4 as i128);
    let mut s16 = (a5 as i128)*(b11 as i128) + (a6 as i128)*(b10 as i128) + (a7 as i128)*(b9 as i128) + (a8 as i128)*(b8 as i128) + (a9 as i128)*(b7 as i128) + (a10 as i128)*(b6 as i128) + (a11 as i128)*(b5 as i128);
    let mut s17 = (a6 as i128)*(b11 as i128) + (a7 as i128)*(b10 as i128) + (a8 as i128)*(b9 as i128) + (a9 as i128)*(b8 as i128) + (a10 as i128)*(b7 as i128) + (a11 as i128)*(b6 as i128);
    let s18 = (a7 as i128)*(b11 as i128) + (a8 as i128)*(b10 as i128) + (a9 as i128)*(b9 as i128) + (a10 as i128)*(b8 as i128) + (a11 as i128)*(b7 as i128);
    let s19 = (a8 as i128)*(b11 as i128) + (a9 as i128)*(b10 as i128) + (a10 as i128)*(b9 as i128) + (a11 as i128)*(b8 as i128);
    let s20 = (a9 as i128)*(b11 as i128) + (a10 as i128)*(b10 as i128) + (a11 as i128)*(b9 as i128);
    let s21 = (a10 as i128)*(b11 as i128) + (a11 as i128)*(b10 as i128);
    let s22 = (a11 as i128)*(b11 as i128);
    let s23 = 0i128;

    // Reduce modulo l
    let mut carry: i128;

    // First reduction
    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;

    // First carry chain
    carry = (s6 + (1i128<<20)) >> 21; s7 += carry; s6 -= carry << 21;
    carry = (s8 + (1i128<<20)) >> 21; s9 += carry; s8 -= carry << 21;
    carry = (s10 + (1i128<<20)) >> 21; s11 += carry; s10 -= carry << 21;
    carry = (s12 + (1i128<<20)) >> 21; s13 += carry; s12 -= carry << 21;
    carry = (s14 + (1i128<<20)) >> 21; s15 += carry; s14 -= carry << 21;
    carry = (s16 + (1i128<<20)) >> 21; s17 += carry; s16 -= carry << 21;

    carry = (s7 + (1i128<<20)) >> 21; s8 += carry; s7 -= carry << 21;
    carry = (s9 + (1i128<<20)) >> 21; s10 += carry; s9 -= carry << 21;
    carry = (s11 + (1i128<<20)) >> 21; s12 += carry; s11 -= carry << 21;
    carry = (s13 + (1i128<<20)) >> 21; s14 += carry; s13 -= carry << 21;
    carry = (s15 + (1i128<<20)) >> 21; s16 += carry; s15 -= carry << 21;

    // Second reduction
    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    // Second carry chain
    carry = (s0 + (1i128<<20)) >> 21; s1 += carry; s0 -= carry << 21;
    carry = (s2 + (1i128<<20)) >> 21; s3 += carry; s2 -= carry << 21;
    carry = (s4 + (1i128<<20)) >> 21; s5 += carry; s4 -= carry << 21;
    carry = (s6 + (1i128<<20)) >> 21; s7 += carry; s6 -= carry << 21;
    carry = (s8 + (1i128<<20)) >> 21; s9 += carry; s8 -= carry << 21;
    carry = (s10 + (1i128<<20)) >> 21; s11 += carry; s10 -= carry << 21;

    carry = (s1 + (1i128<<20)) >> 21; s2 += carry; s1 -= carry << 21;
    carry = (s3 + (1i128<<20)) >> 21; s4 += carry; s3 -= carry << 21;
    carry = (s5 + (1i128<<20)) >> 21; s6 += carry; s5 -= carry << 21;
    carry = (s7 + (1i128<<20)) >> 21; s8 += carry; s7 -= carry << 21;
    carry = (s9 + (1i128<<20)) >> 21; s10 += carry; s9 -= carry << 21;
    carry = (s11 + (1i128<<20)) >> 21; s12 += carry; s11 -= carry << 21;

    // Final reduction
    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    // Final carries
    carry = s0 >> 21; s1 += carry; s0 -= carry << 21;
    carry = s1 >> 21; s2 += carry; s1 -= carry << 21;
    carry = s2 >> 21; s3 += carry; s2 -= carry << 21;
    carry = s3 >> 21; s4 += carry; s3 -= carry << 21;
    carry = s4 >> 21; s5 += carry; s4 -= carry << 21;
    carry = s5 >> 21; s6 += carry; s5 -= carry << 21;
    carry = s6 >> 21; s7 += carry; s6 -= carry << 21;
    carry = s7 >> 21; s8 += carry; s7 -= carry << 21;
    carry = s8 >> 21; s9 += carry; s8 -= carry << 21;
    carry = s9 >> 21; s10 += carry; s9 -= carry << 21;
    carry = s10 >> 21; s11 += carry; s10 -= carry << 21;
    carry = s11 >> 21; s12 += carry; s11 -= carry << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;

    // Final carries to ensure reduced form
    carry = s0 >> 21; s1 += carry; s0 -= carry << 21;
    carry = s1 >> 21; s2 += carry; s1 -= carry << 21;
    carry = s2 >> 21; s3 += carry; s2 -= carry << 21;
    carry = s3 >> 21; s4 += carry; s3 -= carry << 21;
    carry = s4 >> 21; s5 += carry; s4 -= carry << 21;
    carry = s5 >> 21; s6 += carry; s5 -= carry << 21;
    carry = s6 >> 21; s7 += carry; s6 -= carry << 21;
    carry = s7 >> 21; s8 += carry; s7 -= carry << 21;
    carry = s8 >> 21; s9 += carry; s8 -= carry << 21;
    carry = s9 >> 21; s10 += carry; s9 -= carry << 21;
    carry = s10 >> 21; s11 += carry; s10 -= carry << 21;

    // Pack result
    s[0] = s0 as u8;
    s[1] = (s0 >> 8) as u8;
    s[2] = ((s0 >> 16) | (s1 << 5)) as u8;
    s[3] = (s1 >> 3) as u8;
    s[4] = (s1 >> 11) as u8;
    s[5] = ((s1 >> 19) | (s2 << 2)) as u8;
    s[6] = (s2 >> 6) as u8;
    s[7] = ((s2 >> 14) | (s3 << 7)) as u8;
    s[8] = (s3 >> 1) as u8;
    s[9] = (s3 >> 9) as u8;
    s[10] = ((s3 >> 17) | (s4 << 4)) as u8;
    s[11] = (s4 >> 4) as u8;
    s[12] = (s4 >> 12) as u8;
    s[13] = ((s4 >> 20) | (s5 << 1)) as u8;
    s[14] = (s5 >> 7) as u8;
    s[15] = ((s5 >> 15) | (s6 << 6)) as u8;
    s[16] = (s6 >> 2) as u8;
    s[17] = (s6 >> 10) as u8;
    s[18] = ((s6 >> 18) | (s7 << 3)) as u8;
    s[19] = (s7 >> 5) as u8;
    s[20] = (s7 >> 13) as u8;
    s[21] = s8 as u8;
    s[22] = (s8 >> 8) as u8;
    s[23] = ((s8 >> 16) | (s9 << 5)) as u8;
    s[24] = (s9 >> 3) as u8;
    s[25] = (s9 >> 11) as u8;
    s[26] = ((s9 >> 19) | (s10 << 2)) as u8;
    s[27] = (s10 >> 6) as u8;
    s[28] = ((s10 >> 14) | (s11 << 7)) as u8;
    s[29] = (s11 >> 1) as u8;
    s[30] = (s11 >> 9) as u8;
    s[31] = (s11 >> 17) as u8;
}

/// Reduce a 64-byte hash to a 32-byte scalar
pub fn reduce_scalar(hash: &[u8; 64]) -> [u8; 32] {
    let mut temp = *hash;
    sc_reduce(&mut temp);
    let mut result = [0u8; 32];
    result.copy_from_slice(&temp[..32]);
    result
}

/// Compute s = (a * b + c) mod l and return result
pub fn scalar_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    sc_muladd(&mut result, a, b, c);
    result
}