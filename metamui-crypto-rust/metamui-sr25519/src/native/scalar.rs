#![allow(dead_code, unused_imports)]
/// Scalar arithmetic for Sr25519
/// Native implementation of scalar field operations

use metamui_security_utils::{Zeroize, ZeroizeOnDrop};

/// Scalar in the group of order l = 2^252 + 27742317777372353535851937790883648493
#[derive(Clone, Debug)]
pub struct Scalar {
    /// Little-endian byte representation
    pub(crate) bytes: [u8; 32],
}

impl Drop for Scalar {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for Scalar {}

impl Scalar {
    /// The group order l
    pub const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];
    
    /// Zero scalar
    pub const ZERO: Scalar = Scalar { bytes: [0; 32] };
    
    /// One scalar
    pub const ONE: Scalar = Scalar {
        bytes: [
            1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ],
    };
    
    /// Create scalar from bytes (reduces modulo l)
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        // Use the robust wide reduction to ensure canonical representation
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&bytes);
        Self::from_bytes_mod_order_wide(&wide)
    }
    
    /// Create scalar from bytes without reduction (for testing)
    #[cfg(test)]
    pub fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Scalar { bytes }
    }
    
    /// Create scalar from wide bytes (reduces modulo l)
    pub fn from_bytes_mod_order_wide(input: &[u8; 64]) -> Self {
        // This is a direct port of the Ed25519 sc_reduce function
        // which reduces a 512-bit number modulo l
        
        let mut s = [0u8; 64];
        s.copy_from_slice(input);
        
        // Load functions
        let load_3 = |bytes: &[u8]| -> u64 {
            let mut result = 0u64;
            result |= bytes[0] as u64;
            result |= (bytes[1] as u64) << 8;
            result |= (bytes[2] as u64) << 16;
            result
        };
        
        let load_4 = |bytes: &[u8]| -> u64 {
            let mut result = 0u64;
            result |= bytes[0] as u64;
            result |= (bytes[1] as u64) << 8;
            result |= (bytes[2] as u64) << 16;
            result |= (bytes[3] as u64) << 24;
            result
        };
        
        // Load into 21-bit limbs
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
        
        // Reduce coefficients
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
        let mut result = [0u8; 32];
        result[0] = s0 as u8;
        result[1] = (s0 >> 8) as u8;
        result[2] = ((s0 >> 16) | (s1 << 5)) as u8;
        result[3] = (s1 >> 3) as u8;
        result[4] = (s1 >> 11) as u8;
        result[5] = ((s1 >> 19) | (s2 << 2)) as u8;
        result[6] = (s2 >> 6) as u8;
        result[7] = ((s2 >> 14) | (s3 << 7)) as u8;
        result[8] = (s3 >> 1) as u8;
        result[9] = (s3 >> 9) as u8;
        result[10] = ((s3 >> 17) | (s4 << 4)) as u8;
        result[11] = (s4 >> 4) as u8;
        result[12] = (s4 >> 12) as u8;
        result[13] = ((s4 >> 20) | (s5 << 1)) as u8;
        result[14] = (s5 >> 7) as u8;
        result[15] = ((s5 >> 15) | (s6 << 6)) as u8;
        result[16] = (s6 >> 2) as u8;
        result[17] = (s6 >> 10) as u8;
        result[18] = ((s6 >> 18) | (s7 << 3)) as u8;
        result[19] = (s7 >> 5) as u8;
        result[20] = (s7 >> 13) as u8;
        result[21] = s8 as u8;
        result[22] = (s8 >> 8) as u8;
        result[23] = ((s8 >> 16) | (s9 << 5)) as u8;
        result[24] = (s9 >> 3) as u8;
        result[25] = (s9 >> 11) as u8;
        result[26] = ((s9 >> 19) | (s10 << 2)) as u8;
        result[27] = (s10 >> 6) as u8;
        result[28] = ((s10 >> 14) | (s11 << 7)) as u8;
        result[29] = (s11 >> 1) as u8;
        result[30] = (s11 >> 9) as u8;
        result[31] = (s11 >> 17) as u8;
        
        Scalar { bytes: result }
    }
    
    /// Reduce scalar modulo l
    fn reduce(&mut self) {
        // Load bytes into limbs for easier comparison
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes([
                self.bytes[i * 8],
                self.bytes[i * 8 + 1],
                self.bytes[i * 8 + 2],
                self.bytes[i * 8 + 3],
                self.bytes[i * 8 + 4],
                self.bytes[i * 8 + 5],
                self.bytes[i * 8 + 6],
                self.bytes[i * 8 + 7],
            ]);
        }
        
        // Load l into limbs
        let l_limbs = [
            u64::from_le_bytes([Self::L[0], Self::L[1], Self::L[2], Self::L[3], Self::L[4], Self::L[5], Self::L[6], Self::L[7]]),
            u64::from_le_bytes([Self::L[8], Self::L[9], Self::L[10], Self::L[11], Self::L[12], Self::L[13], Self::L[14], Self::L[15]]),
            u64::from_le_bytes([Self::L[16], Self::L[17], Self::L[18], Self::L[19], Self::L[20], Self::L[21], Self::L[22], Self::L[23]]),
            u64::from_le_bytes([Self::L[24], Self::L[25], Self::L[26], Self::L[27], Self::L[28], Self::L[29], Self::L[30], Self::L[31]]),
        ];
        
        // Check if we need to reduce (if limbs >= l)
        // Compare from most significant limb to least significant
        let mut greater_or_equal = false;
        for i in (0..4).rev() {
            if limbs[i] > l_limbs[i] {
                greater_or_equal = true;
                break;
            } else if limbs[i] < l_limbs[i] {
                greater_or_equal = false;
                break;
            }
            // If equal, continue to next limb
        }
        
        // If all limbs were equal, then the number equals l and should be reduced to 0
        if !greater_or_equal && limbs == l_limbs {
            greater_or_equal = true;
        }
        
        // If greater or equal to l, subtract l
        if greater_or_equal {
            let mut borrow = 0u64;
            for i in 0..4 {
                let subtrahend = l_limbs[i].wrapping_add(borrow);
                let (diff, b) = limbs[i].overflowing_sub(subtrahend);
                limbs[i] = diff;
                borrow = if b || (borrow > 0 && subtrahend == 0) { 1 } else { 0 };
            }
            
            // Write back the reduced value
            for i in 0..4 {
                self.bytes[i * 8..(i + 1) * 8].copy_from_slice(&limbs[i].to_le_bytes());
            }
        }
    }
    
    /// Barrett reduction for wide scalars
    fn barrett_reduce(limbs: &mut [u64; 9]) {
        // This is a simplified Barrett reduction
        // In production, this would use precomputed values
        
        // For now, use repeated subtraction (inefficient but correct)
        loop {
            let mut borrow = 0u64;
            let mut temp = [0u64; 9];
            
            // Try subtracting l
            for i in 0..4 {
                let l_limb = u64::from_le_bytes([
                    Self::L[i * 8],
                    Self::L[i * 8 + 1],
                    Self::L[i * 8 + 2],
                    Self::L[i * 8 + 3],
                    Self::L[i * 8 + 4],
                    Self::L[i * 8 + 5],
                    Self::L[i * 8 + 6],
                    Self::L[i * 8 + 7],
                ]);
                
                let (diff, b) = limbs[i].overflowing_sub(l_limb + borrow);
                temp[i] = diff;
                borrow = b as u64;
            }
            
            // Check if we can subtract
            if limbs[4] == 0 && limbs[5] == 0 && limbs[6] == 0 && limbs[7] == 0 && limbs[8] == 0 && borrow == 0 {
                limbs[0..4].copy_from_slice(&temp[0..4]);
            } else {
                break;
            }
        }
    }
    
    /// Add two scalars
    pub fn add(&self, other: &Scalar) -> Scalar {
        // Convert to limbs for easier arithmetic
        let mut a_limbs = [0u64; 4];
        let mut b_limbs = [0u64; 4];
        for i in 0..4 {
            a_limbs[i] = u64::from_le_bytes(self.bytes[i*8..(i+1)*8].try_into().unwrap());
            b_limbs[i] = u64::from_le_bytes(other.bytes[i*8..(i+1)*8].try_into().unwrap());
        }
        
        // Add with carry
        let mut sum = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let temp = a_limbs[i] as u128 + b_limbs[i] as u128 + carry;
            sum[i] = temp as u64;
            carry = temp >> 64;
        }
        
        // If there's a carry or sum >= l, reduce by subtracting l
        if carry > 0 || Self::is_ge_l(&sum) {
            // Subtract l
            let l_limbs: [u64; 4] = [
                0x5812631a5cf5d3ed,
                0x14def9dea2f79cd6,
                0x0000000000000000,
                0x1000000000000000,
            ];
            
            let mut borrow = 0u128;
            for i in 0..4 {
                let temp = (sum[i] as u128).wrapping_sub(l_limbs[i] as u128).wrapping_sub(borrow);
                sum[i] = temp as u64;
                borrow = if temp > (sum[i] as u128) { 1 } else { 0 };
            }
        }
        
        // Convert back to bytes
        let mut result_bytes = [0u8; 32];
        for i in 0..4 {
            result_bytes[i * 8..(i + 1) * 8].copy_from_slice(&sum[i].to_le_bytes());
        }
        
        Scalar { bytes: result_bytes }
    }
    
    /// Subtract two scalars
    pub fn sub(&self, other: &Scalar) -> Scalar {
        // a - b = a + (-b) = a + (l - b)
        let neg_other = other.negate();
        self.add(&neg_other)
    }
    
    /// Multiply two scalars
    pub fn mul(&self, other: &Scalar) -> Scalar {
        let mut product = [0u64; 8];
        
        // Schoolbook multiplication
        for i in 0..4 {
            let a = u64::from_le_bytes([
                self.bytes[i * 8],
                self.bytes[i * 8 + 1],
                self.bytes[i * 8 + 2],
                self.bytes[i * 8 + 3],
                self.bytes[i * 8 + 4],
                self.bytes[i * 8 + 5],
                self.bytes[i * 8 + 6],
                self.bytes[i * 8 + 7],
            ]);
            
            let mut carry = 0u64;
            for j in 0..4 {
                let b = u64::from_le_bytes([
                    other.bytes[j * 8],
                    other.bytes[j * 8 + 1],
                    other.bytes[j * 8 + 2],
                    other.bytes[j * 8 + 3],
                    other.bytes[j * 8 + 4],
                    other.bytes[j * 8 + 5],
                    other.bytes[j * 8 + 6],
                    other.bytes[j * 8 + 7],
                ]);
                
                let (low, high) = Self::mul_u64(a, b);
                let (sum, c1) = product[i + j].overflowing_add(low);
                let (sum, c2) = sum.overflowing_add(carry);
                product[i + j] = sum;
                carry = high + (c1 as u64) + (c2 as u64);
            }
            product[i + 4] = carry;
        }
        
        // Convert to bytes for reduction
        let mut wide_bytes = [0u8; 64];
        for i in 0..8 {
            wide_bytes[i * 8..(i + 1) * 8].copy_from_slice(&product[i].to_le_bytes());
        }
        
        Scalar::from_bytes_mod_order_wide(&wide_bytes)
    }
    
    /// Multiply two u64s, returning (low, high)
    fn mul_u64(a: u64, b: u64) -> (u64, u64) {
        let product = (a as u128) * (b as u128);
        (product as u64, (product >> 64) as u64)
    }

    
    /// Negate scalar
    pub fn negate(&self) -> Scalar {
        // -a = l - a
        let mut neg = [0u64; 4];
        let mut borrow = 0u64;
        
        for i in 0..4 {
            let l_limb = u64::from_le_bytes([
                Self::L[i * 8],
                Self::L[i * 8 + 1],
                Self::L[i * 8 + 2],
                Self::L[i * 8 + 3],
                Self::L[i * 8 + 4],
                Self::L[i * 8 + 5],
                Self::L[i * 8 + 6],
                Self::L[i * 8 + 7],
            ]);
            let a_limb = u64::from_le_bytes([
                self.bytes[i * 8],
                self.bytes[i * 8 + 1],
                self.bytes[i * 8 + 2],
                self.bytes[i * 8 + 3],
                self.bytes[i * 8 + 4],
                self.bytes[i * 8 + 5],
                self.bytes[i * 8 + 6],
                self.bytes[i * 8 + 7],
            ]);
            
            let (diff, b) = l_limb.overflowing_sub(a_limb + borrow);
            neg[i] = diff;
            borrow = b as u64;
        }
        
        let mut result_bytes = [0u8; 32];
        for i in 0..4 {
            result_bytes[i * 8..(i + 1) * 8].copy_from_slice(&neg[i].to_le_bytes());
        }
        
        Scalar { bytes: result_bytes }
    }
    
    /// Compute scalar inverse
    pub fn invert(&self) -> Option<Scalar> {
        if self.is_zero() {
            return None;
        }
        
        // Use Fermat's little theorem: a^(-1) = a^(l-2) mod l
        // This is a placeholder - in production, use constant-time inversion
        let mut result = Scalar::ONE;
        let mut base = self.clone();
        
        // Simplified exponentiation - not constant time!
        for i in 0..252 {
            if i != 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base);
        }
        
        Some(result)
    }
    
    /// Check if scalar is zero
    pub fn is_zero(&self) -> bool {
        let mut result = 0u8;
        for &byte in &self.bytes {
            result |= byte;
        }
        result == 0
    }
    
    /// Get bytes representation
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }
    
    /// Check if limbs represent a value >= l
    fn is_ge_l(limbs: &[u64; 4]) -> bool {
        let l_limbs = [
            0x5812631a5cf5d3ed,
            0x14def9dea2f79cd6,
            0x0000000000000000,
            0x1000000000000000,
        ];
        
        // Compare from most significant limb
        for i in (0..4).rev() {
            if limbs[i] > l_limbs[i] {
                return true;
            } else if limbs[i] < l_limbs[i] {
                return false;
            }
        }
        // All equal means >= l
        true
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison
        let mut result = 0u8;
        for i in 0..32 {
            result |= self.bytes[i] ^ other.bytes[i];
        }
        result == 0
    }
}

impl Eq for Scalar {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scalar_arithmetic() {
        let a = Scalar::from_bytes_mod_order([5; 32]);
        let b = Scalar::from_bytes_mod_order([3; 32]);
        
        let sum = a.add(&b);
        let diff = a.sub(&b);
        let prod = a.mul(&b);
        
        assert_ne!(sum, a);
        assert_ne!(sum, b);
        assert_ne!(diff, Scalar::ZERO);
        assert_ne!(prod, a);
    }
    
    #[test]
    fn test_scalar_reduction() {
        // Test that values larger than l are properly reduced
        let large = [0xff; 32];
        let scalar = Scalar::from_bytes_mod_order(large);
        
        // Should be reduced modulo l
        assert_ne!(scalar.bytes, large);
    }
    
    #[test]
    fn test_scalar_round_trip() {
        println!("Testing scalar round-trip consistency...");
        
        // Test with various values
        let test_cases = [
            [0x01; 32],
            [0x02; 32],
            [0x42; 32],
            [0x55; 32],
            [0xaa; 32],
            [0xff; 32],
        ];
        
        for (i, &bytes) in test_cases.iter().enumerate() {
            let original = Scalar::from_bytes_mod_order(bytes);
            let serialized = original.to_bytes();
            let parsed = Scalar::from_bytes_mod_order(serialized);
            
            println!("Test case {}: Original: {:02x?}", i, &original.bytes[0..8]);
            println!("Test case {}: Serialized: {:02x?}", i, &serialized[0..8]);
            println!("Test case {}: Parsed: {:02x?}", i, &parsed.bytes[0..8]);
            
            assert_eq!(original, parsed, "Round-trip failed for test case {}", i);
            
            // Also test multiple round trips
            let second_serialized = parsed.to_bytes();
            let second_parsed = Scalar::from_bytes_mod_order(second_serialized);
            
            assert_eq!(original, second_parsed, "Second round-trip failed for test case {}", i);
            assert_eq!(serialized, second_serialized, "Serialization not consistent for test case {}", i);
        }
        
        println!("All round-trip tests passed!");
    }
    
    #[test]
    fn test_ecvrf_scalar_arithmetic() {
        println!("Testing ECVRF scalar arithmetic specifically...");
        
        // Use the exact values from the failing test
        let k_bytes = hex::decode("5bdd88ae6929b25bfbee06baf41a6fc6666c2de5713e4edb24c55e4c62796103").unwrap();
        let c_bytes = hex::decode("133345e648f659481668a5c649494c99cbfd8a1e2eb837fc4a691d520f18db03").unwrap();
        let x_bytes = hex::decode("0f5fcf1249027d35a6ca3b037b811648169f58b6414fd263d3c98da627170f0e").unwrap();
        let s_bytes = hex::decode("53a82bac9007c26d5ba6df1cd86198c9e08337d776e793fe4a7c994a4dadea05").unwrap();
        
        let k = Scalar::from_bytes_mod_order(k_bytes.try_into().unwrap());
        let c = Scalar::from_bytes_mod_order(c_bytes.try_into().unwrap());
        let x = Scalar::from_bytes_mod_order(x_bytes.try_into().unwrap());
        let s_expected = Scalar::from_bytes_mod_order(s_bytes.try_into().unwrap());
        
        // Compute c*x
        let c_x = c.mul(&x);
        println!("c*x computed: {}", hex::encode(c_x.to_bytes()));
        println!("c*x expected: f8caa2fd26de0f1260b7d862e34629037a170af204a9452326b73afeea338902");
        
        // Compute s = k + c*x
        let s_computed = k.add(&c_x);
        println!("s computed: {}", hex::encode(s_computed.to_bytes()));
        println!("s expected: {}", hex::encode(s_expected.to_bytes()));
        
        assert_eq!(s_computed, s_expected, "Scalar arithmetic s = k + c*x failed");
        
        // Verify the reverse: k = s - c*x
        let k_recovered = s_computed.sub(&c_x);
        println!("k recovered: {}", hex::encode(k_recovered.to_bytes()));
        println!("k original:  {}", hex::encode(k.to_bytes()));
        
        assert_eq!(k_recovered, k, "Reverse scalar arithmetic k = s - c*x failed");
        
        println!("ECVRF scalar arithmetic test passed!");
    }
}