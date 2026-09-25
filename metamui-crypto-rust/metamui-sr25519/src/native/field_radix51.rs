#![allow(dead_code, unused_imports)]
/// Field arithmetic modulo p = 2^255 - 19 using radix-51 representation
/// Based on the curve25519-dalek implementation

/// Type alias for compatibility
pub type FieldElement = FieldElement51;

/// A field element in radix-51 representation
#[derive(Clone, Copy, Debug)]
pub struct FieldElement51 {
    pub limbs: [u64; 5],
}

impl FieldElement51 {
    /// The field element 0
    pub const ZERO: FieldElement51 = FieldElement51 { limbs: [0, 0, 0, 0, 0] };
    
    /// The field element 1
    pub const ONE: FieldElement51 = FieldElement51 { limbs: [1, 0, 0, 0, 0] };
    
    /// The field element 2
    pub const TWO: FieldElement51 = FieldElement51 { limbs: [2, 0, 0, 0, 0] };
    
    /// The field element -1
    pub const MINUS_ONE: FieldElement51 = FieldElement51 {
        limbs: [
            2251799813685228,
            2251799813685247,
            2251799813685247,
            2251799813685247,
            2251799813685247,
        ],
    };
    
    /// Mask for the low 51 bits
    const LOW_51_BIT_MASK: u64 = (1u64 << 51) - 1;
    
    /// Load a field element from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> FieldElement51 {
        // Load bytes as little-endian integers
        let mut t = [0u64; 5];
        
        // Load 64-bit chunks
        t[0] = u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]);
        t[1] = u64::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]]);
        t[2] = u64::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23]]);
        t[3] = u64::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31]]);
        
        // Convert to radix-51 representation
        // bits 0-50
        let h0 = t[0] & Self::LOW_51_BIT_MASK;
        // bits 51-101 (51 bits from t[0] shifted + 13 bits from t[1])
        let h1 = ((t[0] >> 51) | (t[1] << 13)) & Self::LOW_51_BIT_MASK;
        // bits 102-152 (38 bits from t[1] shifted + 26 bits from t[2])
        let h2 = ((t[1] >> 38) | (t[2] << 26)) & Self::LOW_51_BIT_MASK;
        // bits 153-203 (25 bits from t[2] shifted + 39 bits from t[3])
        let h3 = ((t[2] >> 25) | (t[3] << 39)) & Self::LOW_51_BIT_MASK;
        // bits 204-254 (12 bits from t[3] shifted)
        let h4 = t[3] >> 12;  // Don't mask yet - we need to handle bit 255
        
        // Handle bit 255 (if set, we need to reduce by p)
        // bit 255 is in position 255-204 = 51 of h4
        let bit_255 = (h4 >> 51) & 1;
        
        // If bit 255 is set, we have a value >= 2^255
        // Since 2^255 ≡ 19 (mod p), we need to add 19 to the low limb
        // and clear bit 255
        let mut limbs = [h0, h1, h2, h3, h4 & Self::LOW_51_BIT_MASK];
        
        if bit_255 == 1 {
            // Add 19 to handle 2^255 ≡ 19 (mod p)
            limbs[0] += 19;
            
            // Propagate carries
            let mut carry = limbs[0] >> 51;
            limbs[0] &= Self::LOW_51_BIT_MASK;
            limbs[1] += carry;
            carry = limbs[1] >> 51;
            limbs[1] &= Self::LOW_51_BIT_MASK;
            limbs[2] += carry;
            carry = limbs[2] >> 51;
            limbs[2] &= Self::LOW_51_BIT_MASK;
            limbs[3] += carry;
            carry = limbs[3] >> 51;
            limbs[3] &= Self::LOW_51_BIT_MASK;
            limbs[4] += carry;
            limbs[4] &= Self::LOW_51_BIT_MASK;
        }
        
        FieldElement51 { limbs }
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        // First, reduce to ensure canonical form
        let reduced = self.reduce();
        let limbs = reduced.limbs;
        
        // Compute h + 19 and check for carry to determine if h >= p
        let mut q = (limbs[0] + 19) >> 51;
        q = (limbs[1] + q) >> 51;
        q = (limbs[2] + q) >> 51;
        q = (limbs[3] + q) >> 51;
        q = (limbs[4] + q) >> 51;
        
        // If h >= p, subtract p by adding 19*q and discarding the carry
        let mut limbs = limbs;
        limbs[0] += 19 * q;
        
        // Propagate carries
        let mut carry = limbs[0] >> 51;
        limbs[0] &= Self::LOW_51_BIT_MASK;
        limbs[1] += carry;
        carry = limbs[1] >> 51;
        limbs[1] &= Self::LOW_51_BIT_MASK;
        limbs[2] += carry;
        carry = limbs[2] >> 51;
        limbs[2] &= Self::LOW_51_BIT_MASK;
        limbs[3] += carry;
        carry = limbs[3] >> 51;
        limbs[3] &= Self::LOW_51_BIT_MASK;
        limbs[4] += carry;
        limbs[4] &= Self::LOW_51_BIT_MASK;
        
        // Pack into bytes
        let mut s = [0u8; 32];
        s[0] = limbs[0] as u8;
        s[1] = (limbs[0] >> 8) as u8;
        s[2] = (limbs[0] >> 16) as u8;
        s[3] = (limbs[0] >> 24) as u8;
        s[4] = (limbs[0] >> 32) as u8;
        s[5] = (limbs[0] >> 40) as u8;
        s[6] = ((limbs[0] >> 48) | (limbs[1] << 3)) as u8;
        s[7] = (limbs[1] >> 5) as u8;
        s[8] = (limbs[1] >> 13) as u8;
        s[9] = (limbs[1] >> 21) as u8;
        s[10] = (limbs[1] >> 29) as u8;
        s[11] = (limbs[1] >> 37) as u8;
        s[12] = ((limbs[1] >> 45) | (limbs[2] << 6)) as u8;
        s[13] = (limbs[2] >> 2) as u8;
        s[14] = (limbs[2] >> 10) as u8;
        s[15] = (limbs[2] >> 18) as u8;
        s[16] = (limbs[2] >> 26) as u8;
        s[17] = (limbs[2] >> 34) as u8;
        s[18] = (limbs[2] >> 42) as u8;
        s[19] = ((limbs[2] >> 50) | (limbs[3] << 1)) as u8;
        s[20] = (limbs[3] >> 7) as u8;
        s[21] = (limbs[3] >> 15) as u8;
        s[22] = (limbs[3] >> 23) as u8;
        s[23] = (limbs[3] >> 31) as u8;
        s[24] = (limbs[3] >> 39) as u8;
        s[25] = ((limbs[3] >> 47) | (limbs[4] << 4)) as u8;
        s[26] = (limbs[4] >> 4) as u8;
        s[27] = (limbs[4] >> 12) as u8;
        s[28] = (limbs[4] >> 20) as u8;
        s[29] = (limbs[4] >> 28) as u8;
        s[30] = (limbs[4] >> 36) as u8;
        s[31] = (limbs[4] >> 44) as u8;
        
        s
    }
    
    /// Reduce limbs to ensure they're bounded
    fn reduce(&self) -> FieldElement51 {
        let mut limbs = self.limbs;
        
        // First carry propagation
        let c0 = limbs[0] >> 51;
        limbs[0] &= Self::LOW_51_BIT_MASK;
        limbs[1] += c0;
        
        let c1 = limbs[1] >> 51;
        limbs[1] &= Self::LOW_51_BIT_MASK;
        limbs[2] += c1;
        
        let c2 = limbs[2] >> 51;
        limbs[2] &= Self::LOW_51_BIT_MASK;
        limbs[3] += c2;
        
        let c3 = limbs[3] >> 51;
        limbs[3] &= Self::LOW_51_BIT_MASK;
        limbs[4] += c3;
        
        let c4 = limbs[4] >> 51;
        limbs[4] &= Self::LOW_51_BIT_MASK;
        
        // Reduce c4 by multiplying by 19
        limbs[0] += c4 * 19;
        
        // Second carry propagation in case limbs[0] overflowed
        let c0 = limbs[0] >> 51;
        limbs[0] &= Self::LOW_51_BIT_MASK;
        limbs[1] += c0;
        
        FieldElement51 { limbs }
    }
    
    /// Add two field elements
    pub fn add(&self, other: &FieldElement51) -> FieldElement51 {
        let mut result = FieldElement51 { limbs: [0; 5] };
        for i in 0..5 {
            result.limbs[i] = self.limbs[i] + other.limbs[i];
        }
        result.reduce()
    }
    
    /// Subtract two field elements
    pub fn sub(&self, other: &FieldElement51) -> FieldElement51 {
        // To avoid underflow, add 2*p before subtracting
        // 2*p in radix-51: [0xFFFFFFFFFFFDA, 0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE]
        let mut result = FieldElement51 { limbs: [0; 5] };
        
        result.limbs[0] = self.limbs[0] + 0xFFFFFFFFFFFDA - other.limbs[0];
        result.limbs[1] = self.limbs[1] + 0xFFFFFFFFFFFFE - other.limbs[1];
        result.limbs[2] = self.limbs[2] + 0xFFFFFFFFFFFFE - other.limbs[2];
        result.limbs[3] = self.limbs[3] + 0xFFFFFFFFFFFFE - other.limbs[3];
        result.limbs[4] = self.limbs[4] + 0xFFFFFFFFFFFFE - other.limbs[4];
        
        result.reduce()
    }
    
    /// Negate a field element
    pub fn negate(&self) -> FieldElement51 {
        FieldElement51::ZERO.sub(self)
    }
    
    /// Multiply two field elements
    pub fn mul(&self, other: &FieldElement51) -> FieldElement51 {
        // Helper function for 64x64->128 bit multiplication
        fn m(x: u64, y: u64) -> u128 {
            (x as u128) * (y as u128)
        }
        
        let a = &self.limbs;
        let b = &other.limbs;
        
        // Precompute multiples of b by 19
        let b1_19 = (b[1] as u128) * 19;
        let b2_19 = (b[2] as u128) * 19;
        let b3_19 = (b[3] as u128) * 19;
        let b4_19 = (b[4] as u128) * 19;
        
        // Compute 128-bit products using schoolbook multiplication
        // c[i] = sum of a[j] * b[k] where j + k = i (mod 5)
        let c0 = m(a[0], b[0]) + (a[1] as u128) * b4_19 + (a[2] as u128) * b3_19 + (a[3] as u128) * b2_19 + (a[4] as u128) * b1_19;
        let c1 = m(a[0], b[1]) + m(a[1], b[0]) + (a[2] as u128) * b4_19 + (a[3] as u128) * b3_19 + (a[4] as u128) * b2_19;
        let c2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + (a[3] as u128) * b4_19 + (a[4] as u128) * b3_19;
        let c3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + (a[4] as u128) * b4_19;
        let c4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        
        // First carry propagation
        let mut out = [0u64; 5];
        let mut carry: u128;
        
        carry = c0;
        out[0] = (carry as u64) & Self::LOW_51_BIT_MASK;
        carry = (carry >> 51) + c1;
        
        out[1] = (carry as u64) & Self::LOW_51_BIT_MASK;
        carry = (carry >> 51) + c2;
        
        out[2] = (carry as u64) & Self::LOW_51_BIT_MASK;
        carry = (carry >> 51) + c3;
        
        out[3] = (carry as u64) & Self::LOW_51_BIT_MASK;
        carry = (carry >> 51) + c4;
        
        out[4] = (carry as u64) & Self::LOW_51_BIT_MASK;
        carry >>= 51;
        
        // Reduce the carry
        out[0] += (carry as u64) * 19;
        
        // Second carry propagation to ensure canonical form
        carry = out[0] as u128;
        out[0] = (carry as u64) & Self::LOW_51_BIT_MASK;
        carry >>= 51;
        
        out[1] += carry as u64;
        
        FieldElement51 { limbs: out }
    }
    
    /// Square a field element
    pub fn square(&self) -> FieldElement51 {
        // For now, use multiplication until pow2k is fixed
        self.mul(self)
    }
    
    /// Compute self^(2^k)
    pub fn pow2k(&self, k: u32) -> FieldElement51 {
        debug_assert!(k > 0);
        
        let mut result = *self;
        for _ in 0..k {
            result = result.square();
        }
        result
    }
    
    /// Helper function for inversion and square root
    fn pow22501(&self) -> (FieldElement51, FieldElement51) {
        let t0 = self.square();           // 2^1
        let t1 = t0.square().square();    // 2^3
        let t2 = self.mul(&t1);           // 2^3 + 2^0
        let t3 = t0.mul(&t2);             // 2^3 + 2^1 + 2^0
        let t4 = t3.square();             // 2^4 + 2^2 + 2^1
        let t5 = t2.mul(&t4);             // 2^4 + 2^3 + 2^2 + 2^1 + 2^0
        let t6 = t5.pow2k(5);             // 2^9 + 2^8 + 2^7 + 2^6 + 2^5
        let t7 = t6.mul(&t5);             // 2^9 + ... + 2^0
        let t8 = t7.pow2k(10);            // 2^19 + ... + 2^10
        let t9 = t8.mul(&t7);             // 2^19 + ... + 2^0
        let t10 = t9.pow2k(20);           // 2^39 + ... + 2^20
        let t11 = t10.mul(&t9);           // 2^39 + ... + 2^0
        let t12 = t11.pow2k(10);          // 2^49 + ... + 2^10
        let t13 = t12.mul(&t7);           // 2^49 + ... + 2^0
        let t14 = t13.pow2k(50);          // 2^99 + ... + 2^50
        let t15 = t14.mul(&t13);          // 2^99 + ... + 2^0
        let t16 = t15.pow2k(100);         // 2^199 + ... + 2^100
        let t17 = t16.mul(&t15);          // 2^199 + ... + 2^0
        let t18 = t17.pow2k(50);          // 2^249 + ... + 2^50
        let t19 = t18.mul(&t13);          // 2^249 + ... + 2^0
        
        (t19, t3)
    }
    
    /// Compute the multiplicative inverse
    pub fn invert(&self) -> Option<FieldElement51> {
        if self.is_zero() {
            return None;
        }
        
        // Compute self^(p-2) = self^(2^255 - 21)
        let (t19, t3) = self.pow22501();  // t19: 2^249 + ... + 2^0, t3: 2^3 + 2^1 + 2^0
        let t20 = t19.pow2k(5);           // 2^254 + ... + 2^5
        let t21 = t20.mul(&t3);           // 2^254 + ... + 2^5 + 2^3 + 2^1 + 2^0
        
        Some(t21)
    }
    
    /// Check if this field element is zero
    pub fn is_zero(&self) -> bool {
        let bytes = self.to_bytes();
        bytes.iter().all(|&b| b == 0)
    }
    
    /// Check if this field element is negative (low bit set)
    pub fn is_negative(&self) -> bool {
        let bytes = self.to_bytes();
        (bytes[0] & 1) != 0
    }
    
    /// Compute the square root of this field element
    /// Returns None if the element is not a quadratic residue
    pub fn sqrt(&self) -> Option<FieldElement51> {
        // For p ≡ 5 (mod 8), we can use the formula:
        // sqrt(a) = a^((p+3)/8) if a is a quadratic residue
        // We need to compute self^((p+3)/8) = self^(2^252 - 2)
        
        // Use binary exponentiation since our addition chain has a bug
        // (p+3)/8 in little-endian bytes
        let exponent = [
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F,
        ];
        
        let mut result = FieldElement51::ONE;
        let mut temp = *self;
        
        // Process each bit of the exponent
        for byte in exponent.iter() {
            for i in 0..8 {
                if (byte >> i) & 1 == 1 {
                    result = result.mul(&temp);
                }
                temp = temp.square();
            }
        }
        
        let candidate = result;
        
        // Check if candidate^2 = self
        let check = candidate.square();
        if check == *self {
            return Some(candidate);
        }
        
        // Check if candidate^2 = -self
        // If so, multiply by sqrt(-1)
        let neg_self = self.negate();
        if check == neg_self {
            // sqrt(-1) in our field (precomputed)
            let sqrt_minus_1 = FieldElement51::from_bytes(&[
                0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
                0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
                0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
                0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
            ]);
            
            return Some(candidate.mul(&sqrt_minus_1));
        }
        
        // No square root exists
        None
    }
}

impl PartialEq for FieldElement51 {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for FieldElement51 {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_arithmetic() {
        let one = FieldElement51::ONE;
        let two = FieldElement51::TWO;
        
        // Test addition
        let three = one.add(&two);
        assert_eq!(three.limbs[0], 3);
        
        // Test multiplication
        let four = two.mul(&two);
        assert_eq!(four.limbs[0], 4);
        
        // Test inversion
        let two_inv = two.invert().expect("Should be able to invert 2");
        let check = two.mul(&two_inv);
        assert_eq!(check, FieldElement51::ONE);
    }
    
    #[test]
    fn test_bytes_roundtrip() {
        let bytes = [
            0x04, 0xfe, 0xdf, 0x98, 0xa7, 0xfa, 0x0a, 0x68,
            0x84, 0x92, 0xbd, 0x59, 0x08, 0x07, 0xa7, 0x03,
            0x9e, 0xd1, 0xf6, 0xf2, 0xe1, 0xd9, 0xe2, 0xa4,
            0xa4, 0x51, 0x47, 0x36, 0xf3, 0xc3, 0xa9, 0x17,
        ];
        
        let fe = FieldElement51::from_bytes(&bytes);
        let bytes2 = fe.to_bytes();
        assert_eq!(bytes, bytes2);
    }
}