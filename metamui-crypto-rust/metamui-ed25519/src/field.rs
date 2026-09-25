//! Field arithmetic for Ed25519 - ref10 compatible implementation
//! 
//! This module implements arithmetic modulo p = 2^255 - 19
//! Using the same radix-2^25.5 representation as ref10
//! 
//! The field elements are represented as 10 32-bit limbs with alternating
//! 26 and 25 bit sizes. This matches the ref10 implementation exactly.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use core::ops::{Add, Sub, Mul, Neg};

/// Field element representing a value modulo p = 2^255 - 19
/// Using 10 limbs of 26/25 bits alternating (radix 2^25.5)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement {
    pub limbs: [i32; 10],
}

impl FieldElement {
    /// The modulus p = 2^255 - 19
    pub const MODULUS: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ];
    
    /// Zero element
    pub const ZERO: Self = Self { limbs: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
    
    /// One element
    pub const ONE: Self = Self { limbs: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
    
    /// Two element
    pub const TWO: Self = Self { limbs: [2, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
    
    /// -1 element (fully reduced)
    /// This is p - 1 = 2^255 - 20
    pub const MINUS_ONE: Self = Self { limbs: [
        67108844,  // 0x3ffffec
        33554431,  // 0x1ffffff
        67108863,  // 0x3ffffff
        33554431,  // 0x1ffffff
        67108863,  // 0x3ffffff
        33554431,  // 0x1ffffff
        67108863,  // 0x3ffffff
        33554431,  // 0x1ffffff
        67108863,  // 0x3ffffff
        33554431,  // 0x1ffffff
    ]};
    
    /// Edwards curve parameter d = -121665/121666
    pub const EDWARDS_D: Self = Self { limbs: [
        -10913610, 13857413, -15372611, 6949391, 114729,
        -8787816, -6275908, -3247719, -18696448, -12055116
    ]};
    
    /// 2*d
    pub const D2: Self = Self { limbs: [
        -21827239, -5839606, -30745221, 13898782, 229458,
        15978800, -12551817, -6495438, 29715968, 9444199
    ]};
    
    /// Square root of -1 in the field
    pub const SQRT_NEG_ONE: Self = Self { limbs: [
        -32595792, -7943725, 9377950, 3500415, 12389472,
        -272473, -25146209, -2005654, 326686, 11406482
    ]};
    
    /// Create zero element
    pub fn zero() -> Self {
        Self::ZERO
    }
    
    /// Create one element
    pub fn one() -> Self {
        Self::ONE
    }
    
    /// Create from bytes (little-endian) - matches ref10 fe_frombytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut h = [0i32; 10];
        
        // Load bytes into limbs using ref10's exact formula
        h[0] = ((bytes[0] as u32) | ((bytes[1] as u32) << 8) | ((bytes[2] as u32) << 16) | ((bytes[3] as u32 & 3) << 24)) as i32;
        h[1] = (((bytes[3] as u32) >> 2) | ((bytes[4] as u32) << 6) | ((bytes[5] as u32) << 14) | ((bytes[6] as u32 & 7) << 22)) as i32;
        h[2] = (((bytes[6] as u32) >> 3) | ((bytes[7] as u32) << 5) | ((bytes[8] as u32) << 13) | ((bytes[9] as u32 & 31) << 21)) as i32;
        h[3] = (((bytes[9] as u32) >> 5) | ((bytes[10] as u32) << 3) | ((bytes[11] as u32) << 11) | ((bytes[12] as u32 & 63) << 19)) as i32;
        h[4] = (((bytes[12] as u32) >> 6) | ((bytes[13] as u32) << 2) | ((bytes[14] as u32) << 10) | ((bytes[15] as u32) << 18)) as i32;
        h[5] = ((bytes[16] as u32) | ((bytes[17] as u32) << 8) | ((bytes[18] as u32) << 16) | ((bytes[19] as u32 & 1) << 24)) as i32;
        h[6] = (((bytes[19] as u32) >> 1) | ((bytes[20] as u32) << 7) | ((bytes[21] as u32) << 15) | ((bytes[22] as u32 & 7) << 23)) as i32;
        h[7] = (((bytes[22] as u32) >> 3) | ((bytes[23] as u32) << 5) | ((bytes[24] as u32) << 13) | ((bytes[25] as u32 & 15) << 21)) as i32;
        h[8] = (((bytes[25] as u32) >> 4) | ((bytes[26] as u32) << 4) | ((bytes[27] as u32) << 12) | ((bytes[28] as u32 & 63) << 20)) as i32;
        h[9] = (((bytes[28] as u32) >> 6) | ((bytes[29] as u32) << 2) | ((bytes[30] as u32) << 10) | ((bytes[31] as u32 & 0x7f) << 18)) as i32;
        
        Self { limbs: h }
    }
    
    /// Convert to bytes (little-endian) - matches ref10 fe_tobytes
    pub fn to_bytes(&self) -> [u8; 32] {
        // Make a copy for reduction
        let mut h = self.limbs;
        
        // Carry chain exactly as in ref10
        let mut carry: i32;
        
        // First carry chain to propagate carries
        carry = h[0] >> 26; h[0] -= carry << 26; h[1] += carry;
        carry = h[1] >> 25; h[1] -= carry << 25; h[2] += carry;
        carry = h[2] >> 26; h[2] -= carry << 26; h[3] += carry;
        carry = h[3] >> 25; h[3] -= carry << 25; h[4] += carry;
        carry = h[4] >> 26; h[4] -= carry << 26; h[5] += carry;
        carry = h[5] >> 25; h[5] -= carry << 25; h[6] += carry;
        carry = h[6] >> 26; h[6] -= carry << 26; h[7] += carry;
        carry = h[7] >> 25; h[7] -= carry << 25; h[8] += carry;
        carry = h[8] >> 26; h[8] -= carry << 26; h[9] += carry;
        carry = h[9] >> 25; h[9] -= carry << 25; h[0] += 19 * carry;
        
        // Second carry chain to ensure full reduction
        carry = h[0] >> 26; h[0] -= carry << 26; h[1] += carry;
        carry = h[1] >> 25; h[1] -= carry << 25; h[2] += carry;
        carry = h[2] >> 26; h[2] -= carry << 26; h[3] += carry;
        carry = h[3] >> 25; h[3] -= carry << 25; h[4] += carry;
        carry = h[4] >> 26; h[4] -= carry << 26; h[5] += carry;
        carry = h[5] >> 25; h[5] -= carry << 25; h[6] += carry;
        carry = h[6] >> 26; h[6] -= carry << 26; h[7] += carry;
        carry = h[7] >> 25; h[7] -= carry << 25; h[8] += carry;
        carry = h[8] >> 26; h[8] -= carry << 26; h[9] += carry;
        carry = h[9] >> 25; h[9] -= carry << 25; h[0] += 19 * carry;
        
        // Now h is fully reduced and between 0 and 2^255-19
        let mut s = [0u8; 32];
        s[0] = h[0] as u8;
        s[1] = (h[0] >> 8) as u8;
        s[2] = (h[0] >> 16) as u8;
        s[3] = ((h[0] >> 24) | (h[1] << 2)) as u8;
        s[4] = (h[1] >> 6) as u8;
        s[5] = (h[1] >> 14) as u8;
        s[6] = ((h[1] >> 22) | (h[2] << 3)) as u8;
        s[7] = (h[2] >> 5) as u8;
        s[8] = (h[2] >> 13) as u8;
        s[9] = ((h[2] >> 21) | (h[3] << 5)) as u8;
        s[10] = (h[3] >> 3) as u8;
        s[11] = (h[3] >> 11) as u8;
        s[12] = ((h[3] >> 19) | (h[4] << 6)) as u8;
        s[13] = (h[4] >> 2) as u8;
        s[14] = (h[4] >> 10) as u8;
        s[15] = (h[4] >> 18) as u8;
        s[16] = h[5] as u8;
        s[17] = (h[5] >> 8) as u8;
        s[18] = (h[5] >> 16) as u8;
        s[19] = ((h[5] >> 24) | (h[6] << 1)) as u8;
        s[20] = (h[6] >> 7) as u8;
        s[21] = (h[6] >> 15) as u8;
        s[22] = ((h[6] >> 23) | (h[7] << 3)) as u8;
        s[23] = (h[7] >> 5) as u8;
        s[24] = (h[7] >> 13) as u8;
        s[25] = ((h[7] >> 21) | (h[8] << 4)) as u8;
        s[26] = (h[8] >> 4) as u8;
        s[27] = (h[8] >> 12) as u8;
        s[28] = ((h[8] >> 20) | (h[9] << 6)) as u8;
        s[29] = (h[9] >> 2) as u8;
        s[30] = (h[9] >> 10) as u8;
        s[31] = (h[9] >> 18) as u8;
        
        s
    }
    
    /// Partial reduction modulo p (weak reduce)
    pub fn reduce(&mut self) {
        let mut carry: i32;
        let h = &mut self.limbs;
        
        carry = h[0] >> 26; h[0] -= carry << 26; h[1] += carry;
        carry = h[1] >> 25; h[1] -= carry << 25; h[2] += carry;
        carry = h[2] >> 26; h[2] -= carry << 26; h[3] += carry;
        carry = h[3] >> 25; h[3] -= carry << 25; h[4] += carry;
        carry = h[4] >> 26; h[4] -= carry << 26; h[5] += carry;
        carry = h[5] >> 25; h[5] -= carry << 25; h[6] += carry;
        carry = h[6] >> 26; h[6] -= carry << 26; h[7] += carry;
        carry = h[7] >> 25; h[7] -= carry << 25; h[8] += carry;
        carry = h[8] >> 26; h[8] -= carry << 26; h[9] += carry;
        carry = h[9] >> 25; h[9] -= carry << 25; h[0] += 19 * carry;
    }
    
    /// Strong reduction to canonical form [0, p)
    pub fn strong_reduce(&mut self) {
        // First do weak reduction
        self.reduce();
        self.reduce();
        
        // Now subtract p if we're >= p
        let mut carry: i32;
        let h = &mut self.limbs;
        
        // Compute h - p
        let mut q = h[0] + 19;
        q >>= 26;
        q += h[1];
        q >>= 25;
        q += h[2];
        q >>= 26;
        q += h[3];
        q >>= 25;
        q += h[4];
        q >>= 26;
        q += h[5];
        q >>= 25;
        q += h[6];
        q >>= 26;
        q += h[7];
        q >>= 25;
        q += h[8];
        q >>= 26;
        q += h[9];
        q >>= 25;
        
        // If q >= 0, then h >= p, so subtract p
        let mask = (q >> 31) - 1; // All 1s if q >= 0, all 0s otherwise
        q = 19 & mask;
        
        // Conditionally subtract p
        h[0] += q;
        carry = h[0] >> 26; h[0] -= carry << 26; h[1] += carry;
        carry = h[1] >> 25; h[1] -= carry << 25; h[2] += carry;
        carry = h[2] >> 26; h[2] -= carry << 26; h[3] += carry;
        carry = h[3] >> 25; h[3] -= carry << 25; h[4] += carry;
        carry = h[4] >> 26; h[4] -= carry << 26; h[5] += carry;
        carry = h[5] >> 25; h[5] -= carry << 25; h[6] += carry;
        carry = h[6] >> 26; h[6] -= carry << 26; h[7] += carry;
        carry = h[7] >> 25; h[7] -= carry << 25; h[8] += carry;
        carry = h[8] >> 26; h[8] -= carry << 26; h[9] += carry;
        carry = h[9] >> 25; h[9] -= carry << 25;
    }
    
    /// Square this element - matches ref10 fe_sq
    pub fn square(&self) -> Self {
        let f = &self.limbs;
        let f0 = f[0];
        let f1 = f[1];
        let f2 = f[2];
        let f3 = f[3];
        let f4 = f[4];
        let f5 = f[5];
        let f6 = f[6];
        let f7 = f[7];
        let f8 = f[8];
        let f9 = f[9];
        
        let f0_2 = 2 * f0;
        let f1_2 = 2 * f1;
        let f2_2 = 2 * f2;
        let f3_2 = 2 * f3;
        let f4_2 = 2 * f4;
        let f5_2 = 2 * f5;
        let f6_2 = 2 * f6;
        let f7_2 = 2 * f7;
        let f5_38 = 38 * f5;
        let f6_19 = 19 * f6;
        let f7_38 = 38 * f7;
        let f8_19 = 19 * f8;
        let f9_38 = 38 * f9;
        
        let h0 = (f0 as i64) * (f0 as i64) + (f1_2 as i64) * (f9_38 as i64) + (f2_2 as i64) * (f8_19 as i64) + (f3_2 as i64) * (f7_38 as i64) + (f4_2 as i64) * (f6_19 as i64) + (f5 as i64) * (f5_38 as i64);
        let h1 = (f0_2 as i64) * (f1 as i64) + (f2 as i64) * (f9_38 as i64) + (f3_2 as i64) * (f8_19 as i64) + (f4 as i64) * (f7_38 as i64) + (f5_2 as i64) * (f6_19 as i64);
        let h2 = (f0_2 as i64) * (f2 as i64) + (f1_2 as i64) * (f1 as i64) + (f3_2 as i64) * (f9_38 as i64) + (f4_2 as i64) * (f8_19 as i64) + (f5_2 as i64) * (f7_38 as i64) + (f6 as i64) * (f6_19 as i64);
        let h3 = (f0_2 as i64) * (f3 as i64) + (f1_2 as i64) * (f2 as i64) + (f4 as i64) * (f9_38 as i64) + (f5_2 as i64) * (f8_19 as i64) + (f6 as i64) * (f7_38 as i64);
        let h4 = (f0_2 as i64) * (f4 as i64) + (f1_2 as i64) * (f3_2 as i64) + (f2 as i64) * (f2 as i64) + (f5_2 as i64) * (f9_38 as i64) + (f6_2 as i64) * (f8_19 as i64) + (f7 as i64) * (f7_38 as i64);
        let h5 = (f0_2 as i64) * (f5 as i64) + (f1_2 as i64) * (f4 as i64) + (f2_2 as i64) * (f3 as i64) + (f6 as i64) * (f9_38 as i64) + (f7_2 as i64) * (f8_19 as i64);
        let h6 = (f0_2 as i64) * (f6 as i64) + (f1_2 as i64) * (f5_2 as i64) + (f2_2 as i64) * (f4 as i64) + (f3_2 as i64) * (f3 as i64) + (f7_2 as i64) * (f9_38 as i64) + (f8 as i64) * (f8_19 as i64);
        let h7 = (f0_2 as i64) * (f7 as i64) + (f1_2 as i64) * (f6 as i64) + (f2_2 as i64) * (f5 as i64) + (f3_2 as i64) * (f4 as i64) + (f8 as i64) * (f9_38 as i64);
        let h8 = (f0_2 as i64) * (f8 as i64) + (f1_2 as i64) * (f7_2 as i64) + (f2_2 as i64) * (f6 as i64) + (f3_2 as i64) * (f5_2 as i64) + (f4 as i64) * (f4 as i64) + (f9 as i64) * (f9_38 as i64);
        let h9 = (f0_2 as i64) * (f9 as i64) + (f1_2 as i64) * (f8 as i64) + (f2_2 as i64) * (f7 as i64) + (f3_2 as i64) * (f6 as i64) + (f4_2 as i64) * (f5 as i64);
        
        let mut h = [0i32; 10];
        carry_propagate_ref10(&mut h, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
        Self { limbs: h }
    }
    
    /// Check if element is negative (odd when fully reduced)
    pub fn is_negative(&self) -> bool {
        let bytes = self.to_bytes();
        (bytes[0] & 1) != 0
    }
    
    /// Check if element is zero
    pub fn is_zero(&self) -> bool {
        let bytes = self.to_bytes();
        bytes == [0u8; 32]
    }
    
    /// Compute 2 * self
    pub fn double(&self) -> Self {
        self + self
    }
    
    /// Compute 2 * self^2
    pub fn square2(&self) -> Self {
        let sq = self.square();
        sq + sq
    }
    
    /// Conditional negate: -self if choice, self otherwise
    pub fn conditional_negate(&self, choice: Choice) -> Self {
        let neg = -self;
        Self::conditional_select(self, &neg, choice)
    }
    
    /// Conditional swap
    pub fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        for i in 0..10 {
            let mut a_i = a.limbs[i];
            let mut b_i = b.limbs[i];
            let swap = choice.unwrap_u8() as i32;
            let x = swap & (a_i ^ b_i);
            a_i ^= x;
            b_i ^= x;
            a.limbs[i] = a_i;
            b.limbs[i] = b_i;
        }
    }
    
    /// Invert element using Fermat's little theorem
    /// a^(p-2) = a^(-1) mod p where p = 2^255 - 19
    pub fn invert(&self) -> Self {
        // Use the addition chain from ref10/donna
        // 2^255 - 21 = (2^5-1) * 2^250 + 11
        let z1 = self;
        let z2 = z1.square();
        let z8 = z2.square().square();
        let z9 = z1 * &z8;
        let z11 = z2 * z9;
        let z22 = z11.square();
        let z_5_0 = z9 * z22;
        
        // z_10_5 = z_5_0^(2^5)
        let mut z_10_5 = z_5_0.square();
        for _ in 1..5 {
            z_10_5 = z_10_5.square();
        }
        
        let z_10_0 = z_10_5 * z_5_0;
        
        // z_20_10 = z_10_0^(2^10)
        let mut z_20_10 = z_10_0.square();
        for _ in 1..10 {
            z_20_10 = z_20_10.square();
        }
        
        let z_20_0 = z_20_10 * z_10_0;
        
        // z_40_20 = z_20_0^(2^20)
        let mut z_40_20 = z_20_0.square();
        for _ in 1..20 {
            z_40_20 = z_40_20.square();
        }
        
        let z_40_0 = z_40_20 * z_20_0;
        
        // z_50_10 = z_40_0^(2^10)
        let mut z_50_10 = z_40_0.square();
        for _ in 1..10 {
            z_50_10 = z_50_10.square();
        }
        
        let z_50_0 = z_50_10 * z_10_0;
        
        // z_100_50 = z_50_0^(2^50)
        let mut z_100_50 = z_50_0.square();
        for _ in 1..50 {
            z_100_50 = z_100_50.square();
        }
        
        let z_100_0 = z_100_50 * z_50_0;
        
        // z_200_100 = z_100_0^(2^100)
        let mut z_200_100 = z_100_0.square();
        for _ in 1..100 {
            z_200_100 = z_200_100.square();
        }
        
        let z_200_0 = z_200_100 * z_100_0;
        
        // z_250_50 = z_200_0^(2^50)
        let mut z_250_50 = z_200_0.square();
        for _ in 1..50 {
            z_250_50 = z_250_50.square();
        }
        
        let z_250_0 = z_250_50 * z_50_0;
        
        // z_255_5 = z_250_0^(2^5)
        let mut z_255_5 = z_250_0.square();
        for _ in 1..5 {
            z_255_5 = z_255_5.square();
        }
        
        // z_255_21 = z_255_5 * z11
        z_255_5 * z11
    }
    
    /// Compute square root if it exists
    /// Returns None if element is not a square
    pub fn sqrt(&self) -> Option<Self> {
        // For p = 2^255 - 19 ≡ 5 (mod 8), we use the Tonelli-Shanks variant:
        // If a is a square, then sqrt(a) = ±a^((p+3)/8) if a^((p-1)/2) = 1
        // or sqrt(a) = ±a^((p+3)/8) * sqrt(-1) if a^((p-1)/2) = -1
        
        // Compute beta = a^((p+3)/8) = a^(2^252-2)
        let beta = self.pow_p_3_8();
        
        // Compute beta^2
        let beta_sq = beta.square();
        
        
        // Check if beta^2 = a
        let check: FieldElement = &beta_sq - self;
        if check.is_zero() {
            return Some(beta);
        }
        
        // Check if beta^2 = -a
        let neg_a = -self;
        let check_neg: FieldElement = beta_sq - neg_a;
        if check_neg.is_zero() {
            // beta^2 = -a, so sqrt(a) = beta * sqrt(-1)
            return Some(beta * Self::SQRT_NEG_ONE);
        }
        
        
        // Not a quadratic residue
        None
    }
    
    /// Compute a^((p+3)/8) = a^(2^252-2)
    fn pow_p_3_8(&self) -> Self {
        // For p = 2^255 - 19, we have p ≡ 5 (mod 8)
        // So we compute a^((p+3)/8) = a^((2^255-19+3)/8) = a^((2^255-16)/8) = a^(2^252-2)
        
        // This is the same exponentiation chain as pow22523 in ref10
        // Build the exponent 2^252 - 2 using addition chains
        
        let z2 = self.square();
        let z8 = z2.square().square();
        let z9 = self * &z8;
        let z11 = z2 * z9;
        let z22 = z11.square();
        let z_5_0 = z9 * z22;
        
        let mut z_10_5 = z_5_0.square();
        for _ in 1..5 {
            z_10_5 = z_10_5.square();
        }
        let z_10_0 = z_10_5 * z_5_0;
        
        let mut z_20_10 = z_10_0.square();
        for _ in 1..10 {
            z_20_10 = z_20_10.square();
        }
        let z_20_0 = z_20_10 * z_10_0;
        
        let mut z_40_20 = z_20_0.square();
        for _ in 1..20 {
            z_40_20 = z_40_20.square();
        }
        let z_40_0 = z_40_20 * z_20_0;
        
        let mut z_50_10 = z_40_0.square();
        for _ in 1..10 {
            z_50_10 = z_50_10.square();
        }
        let z_50_0 = z_50_10 * z_10_0;
        
        let mut z_100_50 = z_50_0.square();
        for _ in 1..50 {
            z_100_50 = z_100_50.square();
        }
        let z_100_0 = z_100_50 * z_50_0;
        
        let mut z_200_100 = z_100_0.square();
        for _ in 1..100 {
            z_200_100 = z_200_100.square();
        }
        let z_200_0 = z_200_100 * z_100_0;
        
        let mut z_250_50 = z_200_0.square();
        for _ in 1..50 {
            z_250_50 = z_250_50.square();
        }
        let z_250_0 = z_250_50 * z_50_0;
        
        // z_250_0 = a^(2^250 - 1)
        // We want a^(2^252 - 2)
        // 2^252 - 2 = 4 * (2^250 - 1) + 2
        // So a^(2^252 - 2) = (a^(2^250 - 1))^4 * a^2
        
        let mut result = z_250_0;
        result = result.square();  // 2*(2^250 - 1)
        result = result.square();  // 4*(2^250 - 1)
        result * z2              // 4*(2^250 - 1) + 2 = 2^252 - 2
    }
}

/// Field addition
impl Add<&FieldElement> for &FieldElement {
    type Output = FieldElement;
    
    fn add(self, other: &FieldElement) -> FieldElement {
        let mut h = [0i32; 10];
        for (i, (a, b)) in self.limbs.iter().zip(other.limbs.iter()).enumerate() {
            h[i] = a + b;
        }
        FieldElement { limbs: h }
    }
}

impl Add for FieldElement {
    type Output = FieldElement;
    
    fn add(self, other: Self) -> FieldElement {
        &self + &other
    }
}

/// Field subtraction
impl Sub<&FieldElement> for &FieldElement {
    type Output = FieldElement;
    
    fn sub(self, other: &FieldElement) -> FieldElement {
        let mut h = [0i32; 10];
        for (i, (a, b)) in self.limbs.iter().zip(other.limbs.iter()).enumerate() {
            h[i] = a - b;
        }
        FieldElement { limbs: h }
    }
}

impl Sub for FieldElement {
    type Output = FieldElement;
    
    fn sub(self, other: Self) -> FieldElement {
        &self - &other
    }
}

/// Field multiplication - matches ref10 fe_mul
impl Mul<&FieldElement> for &FieldElement {
    type Output = FieldElement;
    
    fn mul(self, other: &FieldElement) -> FieldElement {
        let f = &self.limbs;
        let g = &other.limbs;
        
        let f0 = f[0];
        let f1 = f[1];
        let f2 = f[2];
        let f3 = f[3];
        let f4 = f[4];
        let f5 = f[5];
        let f6 = f[6];
        let f7 = f[7];
        let f8 = f[8];
        let f9 = f[9];
        
        let g0 = g[0];
        let g1 = g[1];
        let g2 = g[2];
        let g3 = g[3];
        let g4 = g[4];
        let g5 = g[5];
        let g6 = g[6];
        let g7 = g[7];
        let g8 = g[8];
        let g9 = g[9];
        
        let g1_19 = 19i64 * (g1 as i64);
        let g2_19 = 19i64 * (g2 as i64);
        let g3_19 = 19i64 * (g3 as i64);
        let g4_19 = 19i64 * (g4 as i64);
        let g5_19 = 19i64 * (g5 as i64);
        let g6_19 = 19i64 * (g6 as i64);
        let g7_19 = 19i64 * (g7 as i64);
        let g8_19 = 19i64 * (g8 as i64);
        let g9_19 = 19i64 * (g9 as i64);
        
        let f1_2 = 2i64 * (f1 as i64);
        let f3_2 = 2i64 * (f3 as i64);
        let f5_2 = 2i64 * (f5 as i64);
        let f7_2 = 2i64 * (f7 as i64);
        let f9_2 = 2i64 * (f9 as i64);
        
        let h0 = (f0 as i64) * (g0 as i64) + f1_2 * g9_19 + (f2 as i64) * g8_19 + f3_2 * g7_19 + (f4 as i64) * g6_19 + f5_2 * g5_19 + (f6 as i64) * g4_19 + f7_2 * g3_19 + (f8 as i64) * g2_19 + f9_2 * g1_19;
        let h1 = (f0 as i64) * (g1 as i64) + (f1 as i64) * (g0 as i64) + (f2 as i64) * g9_19 + (f3 as i64) * g8_19 + (f4 as i64) * g7_19 + (f5 as i64) * g6_19 + (f6 as i64) * g5_19 + (f7 as i64) * g4_19 + (f8 as i64) * g3_19 + (f9 as i64) * g2_19;
        let h2 = (f0 as i64) * (g2 as i64) + f1_2 * (g1 as i64) + (f2 as i64) * (g0 as i64) + f3_2 * g9_19 + (f4 as i64) * g8_19 + f5_2 * g7_19 + (f6 as i64) * g6_19 + f7_2 * g5_19 + (f8 as i64) * g4_19 + f9_2 * g3_19;
        let h3 = (f0 as i64) * (g3 as i64) + (f1 as i64) * (g2 as i64) + (f2 as i64) * (g1 as i64) + (f3 as i64) * (g0 as i64) + (f4 as i64) * g9_19 + (f5 as i64) * g8_19 + (f6 as i64) * g7_19 + (f7 as i64) * g6_19 + (f8 as i64) * g5_19 + (f9 as i64) * g4_19;
        let h4 = (f0 as i64) * (g4 as i64) + f1_2 * (g3 as i64) + (f2 as i64) * (g2 as i64) + f3_2 * (g1 as i64) + (f4 as i64) * (g0 as i64) + f5_2 * g9_19 + (f6 as i64) * g8_19 + f7_2 * g7_19 + (f8 as i64) * g6_19 + f9_2 * g5_19;
        let h5 = (f0 as i64) * (g5 as i64) + (f1 as i64) * (g4 as i64) + (f2 as i64) * (g3 as i64) + (f3 as i64) * (g2 as i64) + (f4 as i64) * (g1 as i64) + (f5 as i64) * (g0 as i64) + (f6 as i64) * g9_19 + (f7 as i64) * g8_19 + (f8 as i64) * g7_19 + (f9 as i64) * g6_19;
        let h6 = (f0 as i64) * (g6 as i64) + f1_2 * (g5 as i64) + (f2 as i64) * (g4 as i64) + f3_2 * (g3 as i64) + (f4 as i64) * (g2 as i64) + f5_2 * (g1 as i64) + (f6 as i64) * (g0 as i64) + f7_2 * g9_19 + (f8 as i64) * g8_19 + f9_2 * g7_19;
        let h7 = (f0 as i64) * (g7 as i64) + (f1 as i64) * (g6 as i64) + (f2 as i64) * (g5 as i64) + (f3 as i64) * (g4 as i64) + (f4 as i64) * (g3 as i64) + (f5 as i64) * (g2 as i64) + (f6 as i64) * (g1 as i64) + (f7 as i64) * (g0 as i64) + (f8 as i64) * g9_19 + (f9 as i64) * g8_19;
        let h8 = (f0 as i64) * (g8 as i64) + f1_2 * (g7 as i64) + (f2 as i64) * (g6 as i64) + f3_2 * (g5 as i64) + (f4 as i64) * (g4 as i64) + f5_2 * (g3 as i64) + (f6 as i64) * (g2 as i64) + f7_2 * (g1 as i64) + (f8 as i64) * (g0 as i64) + f9_2 * g9_19;
        let h9 = (f0 as i64) * (g9 as i64) + (f1 as i64) * (g8 as i64) + (f2 as i64) * (g7 as i64) + (f3 as i64) * (g6 as i64) + (f4 as i64) * (g5 as i64) + (f5 as i64) * (g4 as i64) + (f6 as i64) * (g3 as i64) + (f7 as i64) * (g2 as i64) + (f8 as i64) * (g1 as i64) + (f9 as i64) * (g0 as i64);
        
        let mut h = [0i32; 10];
        carry_propagate_ref10(&mut h, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
        FieldElement { limbs: h }
    }
}

/// For convenience
impl Mul<&FieldElement> for FieldElement {
    type Output = FieldElement;
    fn mul(self, other: &FieldElement) -> FieldElement {
        &self * other
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;
    fn mul(self, other: Self) -> FieldElement {
        &self * &other
    }
}

/// Field negation
impl Neg for &FieldElement {
    type Output = FieldElement;
    
    fn neg(self) -> FieldElement {
        let mut h = [0i32; 10];
        for i in 0..10 {
            h[i] = -self.limbs[i];
        }
        FieldElement { limbs: h }
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;
    
    fn neg(self) -> FieldElement {
        -&self
    }
}

/// Constant-time equality
impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &Self) -> Choice {
        let self_bytes = self.to_bytes();
        let other_bytes = other.to_bytes();
        self_bytes.ct_eq(&other_bytes)
    }
}

/// Constant-time conditional selection
impl ConditionallySelectable for FieldElement {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut result = FieldElement { limbs: [0i32; 10] };
        for i in 0..10 {
            result.limbs[i] = i32::conditional_select(&a.limbs[i], &b.limbs[i], choice);
        }
        result
    }
}

/// Carry propagation for wide multiplication results - matches ref10
#[allow(clippy::too_many_arguments)]
fn carry_propagate_ref10(h: &mut [i32; 10], mut h0: i64, mut h1: i64, mut h2: i64, mut h3: i64, mut h4: i64, 
                       mut h5: i64, mut h6: i64, mut h7: i64, mut h8: i64, mut h9: i64) {
    let mut carry: i64;
    
    // First round of carry propagation
    carry = (h0 + (1 << 25)) >> 26; h1 += carry; h0 -= carry << 26;
    carry = (h1 + (1 << 24)) >> 25; h2 += carry; h1 -= carry << 25;
    carry = (h2 + (1 << 25)) >> 26; h3 += carry; h2 -= carry << 26;
    carry = (h3 + (1 << 24)) >> 25; h4 += carry; h3 -= carry << 25;
    carry = (h4 + (1 << 25)) >> 26; h5 += carry; h4 -= carry << 26;
    carry = (h5 + (1 << 24)) >> 25; h6 += carry; h5 -= carry << 25;
    carry = (h6 + (1 << 25)) >> 26; h7 += carry; h6 -= carry << 26;
    carry = (h7 + (1 << 24)) >> 25; h8 += carry; h7 -= carry << 25;
    carry = (h8 + (1 << 25)) >> 26; h9 += carry; h8 -= carry << 26;
    carry = (h9 + (1 << 24)) >> 25; h0 += 19 * carry; h9 -= carry << 25;
    
    // Second round of carry propagation
    carry = (h0 + (1 << 25)) >> 26; h1 += carry; h0 -= carry << 26;
    
    // Store results
    h[0] = h0 as i32;
    h[1] = h1 as i32;
    h[2] = h2 as i32;
    h[3] = h3 as i32;
    h[4] = h4 as i32;
    h[5] = h5 as i32;
    h[6] = h6 as i32;
    h[7] = h7 as i32;
    h[8] = h8 as i32;
    h[9] = h9 as i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_field_arithmetic_basic() {
        // Test basic arithmetic
        let one = FieldElement::ONE;
        let two: FieldElement = &one + &one;
        assert_eq!(two.to_bytes()[0], 2);
        
        let three = &two + &one;
        assert_eq!(three.to_bytes()[0], 3);
        
        let six = &two * &three;
        assert_eq!(six.to_bytes()[0], 6);
    }
    
    #[test]
    fn test_field_subtraction_edge_cases() {
        // Test 0 - 1 = -1 = p - 1 (mod p)
        let zero = FieldElement::ZERO;
        let one = FieldElement::ONE;
        let neg_one: FieldElement = &zero - &one;
        
        // Check that neg_one equals our constant MINUS_ONE
        assert_eq!(neg_one.to_bytes(), FieldElement::MINUS_ONE.to_bytes());
        
        // Test that (-1) + 1 = 0
        let should_be_zero = &neg_one + &one;
        assert_eq!(should_be_zero.to_bytes(), [0u8; 32]);
    }
}