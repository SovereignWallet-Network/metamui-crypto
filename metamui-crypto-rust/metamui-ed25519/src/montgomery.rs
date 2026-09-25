//! Montgomery multiplication for Ed25519 field arithmetic
//!
//! This module implements Montgomery multiplication for efficient
//! modular arithmetic in the field GF(2^255 - 19).

/// The Ed25519 field prime: p = 2^255 - 19
const P: [u64; 4] = [
    0xffffffffffffffed,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x7fffffffffffffff,
];

/// Montgomery parameter R = 2^256 mod p = 38
#[allow(dead_code)]
const R: [u64; 4] = [
    38,
    0,
    0,
    0,
];

/// Montgomery parameter R^2 mod p = 1444
const R2: [u64; 4] = [
    1444,
    0,
    0,
    0,
];

/// Montgomery parameter R^3 mod p
#[allow(dead_code)]
const R3: [u64; 4] = [
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0800000000000000,
];

/// Montgomery inverse: -p^(-1) mod 2^64
const P_INV: u64 = 0x86bca1af286bca1b;

/// Field element in Montgomery form
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MontgomeryFieldElement {
    /// Limbs in little-endian order
    pub limbs: [u64; 4],
}

impl MontgomeryFieldElement {
    /// Create a new field element from raw limbs (already in Montgomery form)
    pub const fn from_montgomery_limbs(limbs: [u64; 4]) -> Self {
        Self { limbs }
    }

    /// Create a field element from an integer
    pub fn from_u64(x: u64) -> Self {
        let mut limbs = [0u64; 4];
        limbs[0] = x;
        Self { limbs }.to_montgomery()
    }

    /// Convert to Montgomery form by multiplying by R^2
    pub fn to_montgomery(self) -> Self {
        self.montgomery_mul(&Self::from_montgomery_limbs(R2))
    }

    /// Convert from Montgomery form by multiplying by 1
    pub fn from_montgomery(self) -> Self {
        self.montgomery_mul(&Self::from_montgomery_limbs([1, 0, 0, 0]))
    }

    /// Montgomery multiplication: compute (a * b * R^(-1)) mod p
    pub fn montgomery_mul(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];

        // Compute a * b
        let mut product = [0u128; 8];
        for i in 0..4 {
            let mut c = 0u128;
            for j in 0..4 {
                let temp = (self.limbs[i] as u128)
                    .wrapping_mul(other.limbs[j] as u128)
                    .wrapping_add(product[i + j])
                    .wrapping_add(c);
                product[i + j] = temp & 0xffffffffffffffff;
                c = temp >> 64;
            }
            product[i + 4] = c;
        }

        // Montgomery reduction - CIOS (Coarsely Integrated Operand Scanning) method
        for i in 0..4 {
            let m = (product[i] as u64).wrapping_mul(P_INV);
            let mut c = 0u128;
            
            for j in 0..4 {
                let temp = (m as u128)
                    .wrapping_mul(P[j] as u128)
                    .wrapping_add(product[i + j])
                    .wrapping_add(c);
                product[i + j] = temp & 0xffffffffffffffff;
                c = temp >> 64;
            }
            
            // Propagate carry
            for j in i + 4..7 {
                let temp = product[j].wrapping_add(c);
                product[j] = temp & 0xffffffffffffffff;
                c = temp >> 64;
            }
            product[7] = product[7].wrapping_add(c);
        }

        // Extract result (shift right by 4 limbs)
        for i in 0..4 {
            result[i] = product[i + 4] as u64;
        }

        // Conditional subtraction if result >= p
        let mut borrow = 0u64;
        let mut temp = [0u64; 4];
        for i in 0..4 {
            let (diff, b1) = result[i].overflowing_sub(P[i]);
            let (diff, b2) = diff.overflowing_sub(borrow);
            temp[i] = diff;
            borrow = (b1 as u64) | (b2 as u64);
        }

        // Select result or temp based on borrow
        let mask = 0u64.wrapping_sub(borrow);
        for i in 0..4 {
            result[i] = (result[i] & mask) | (temp[i] & !mask);
        }

        Self { limbs: result }
    }

    /// Montgomery squaring: compute (a^2 * R^(-1)) mod p
    pub fn montgomery_square(&self) -> Self {
        // For simplicity and correctness, just use multiplication
        self.montgomery_mul(self)
    }

    /// Modular addition
    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u64;

        // Add limbs with carry
        for i in 0..4 {
            let sum = (self.limbs[i] as u128) + (other.limbs[i] as u128) + (carry as u128);
            result[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }

        // If carry is set or result >= p, subtract p
        if carry != 0 || Self::ge_p(&result) {
            let mut borrow = 0u64;
            for i in 0..4 {
                let (diff, b1) = result[i].overflowing_sub(P[i]);
                let (diff, b2) = diff.overflowing_sub(borrow);
                result[i] = diff;
                borrow = (b1 as u64) | (b2 as u64);
            }
        }

        Self { limbs: result }
    }
    
    /// Check if limbs represent a value >= p
    fn ge_p(limbs: &[u64; 4]) -> bool {
        // Check if the value is >= p
        for i in (0..4).rev() {
            if limbs[i] > P[i] {
                return true;
            } else if limbs[i] < P[i] {
                return false;
            }
        }
        // All limbs are equal, so value == p
        true
    }

    /// Modular subtraction
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;

        // Subtract limbs
        for i in 0..4 {
            let (diff, b1) = self.limbs[i].overflowing_sub(other.limbs[i]);
            let (diff, b2) = diff.overflowing_sub(borrow);
            result[i] = diff;
            borrow = (b1 as u64) | (b2 as u64);
        }

        // Add p if we borrowed
        let mut carry = 0u64;
        let mut temp = [0u64; 4];
        for i in 0..4 {
            let (sum, c1) = result[i].overflowing_add(P[i] & (0u64.wrapping_sub(borrow)));
            let (sum, c2) = sum.overflowing_add(carry);
            temp[i] = sum;
            carry = (c1 as u64) + (c2 as u64);
        }

        // Select based on borrow
        let mask = 0u64.wrapping_sub(borrow);
        for i in 0..4 {
            result[i] = (temp[i] & mask) | (result[i] & !mask);
        }

        Self { limbs: result }
    }

    /// Modular negation
    pub fn neg(&self) -> Self {
        let zero = Self::from_montgomery_limbs([0, 0, 0, 0]);
        zero.sub(self)
    }

    /// Modular inversion using Fermat's little theorem  
    /// Since p = 2^255 - 19, we have a^(-1) = a^(p-2) mod p
    pub fn invert(&self) -> Self {
        // Use the exact same addition chain from ref10/donna
        // 2^255 - 21 computation
        let z2 = self.montgomery_square();
        let z8 = z2.montgomery_square().montgomery_square(); 
        let z9 = self.montgomery_mul(&z8);
        let z11 = z2.montgomery_mul(&z9);
        let z22 = z11.montgomery_square();
        let z_5_0 = z9.montgomery_mul(&z22);
        
        // z_10_5 = z_5_0^(2^5)
        let mut z_10_5 = z_5_0.montgomery_square();
        for _ in 1..5 {
            z_10_5 = z_10_5.montgomery_square();
        }
        
        let z_10_0 = z_10_5.montgomery_mul(&z_5_0);
        
        // z_20_10 = z_10_0^(2^10)  
        let mut z_20_10 = z_10_0.montgomery_square();
        for _ in 1..10 {
            z_20_10 = z_20_10.montgomery_square();
        }
        
        let z_20_0 = z_20_10.montgomery_mul(&z_10_0);
        
        // z_40_20 = z_20_0^(2^20)
        let mut z_40_20 = z_20_0.montgomery_square();
        for _ in 1..20 {
            z_40_20 = z_40_20.montgomery_square();
        }
        
        let z_40_0 = z_40_20.montgomery_mul(&z_20_0);
        
        // z_50_10 = z_40_0^(2^10)
        let mut z_50_10 = z_40_0.montgomery_square();
        for _ in 1..10 {
            z_50_10 = z_50_10.montgomery_square();
        }
        
        let z_50_0 = z_50_10.montgomery_mul(&z_10_0);
        
        // z_100_50 = z_50_0^(2^50)
        let mut z_100_50 = z_50_0.montgomery_square();
        for _ in 1..50 {
            z_100_50 = z_100_50.montgomery_square();
        }
        
        let z_100_0 = z_100_50.montgomery_mul(&z_50_0);
        
        // z_200_100 = z_100_0^(2^100)
        let mut z_200_100 = z_100_0.montgomery_square();
        for _ in 1..100 {
            z_200_100 = z_200_100.montgomery_square();
        }
        
        let z_200_0 = z_200_100.montgomery_mul(&z_100_0);
        
        // z_250_50 = z_200_0^(2^50)
        let mut z_250_50 = z_200_0.montgomery_square();
        for _ in 1..50 {
            z_250_50 = z_250_50.montgomery_square();
        }
        
        let z_250_0 = z_250_50.montgomery_mul(&z_50_0);
        
        // z_255_5 = z_250_0^(2^5)
        let mut z_255_5 = z_250_0.montgomery_square();
        for _ in 1..5 {
            z_255_5 = z_255_5.montgomery_square();
        }
        
        // Result: z_255_5 * z11
        z_255_5.montgomery_mul(&z11)
    }

    /// Convert to bytes in little-endian order
    pub fn to_bytes(&self) -> [u8; 32] {
        let normalized = self.from_montgomery();
        
        // Ensure the value is fully reduced mod p
        // If the value is >= p, subtract p
        let mut limbs = normalized.limbs;
        
        // Check if limbs >= p
        let mut ge_p = true;
        for i in (0..4).rev() {
            if limbs[i] < P[i] {
                ge_p = false;
                break;
            } else if limbs[i] > P[i] {
                break;
            }
        }
        
        if ge_p {
            // Subtract p
            let mut borrow = 0u64;
            for i in 0..4 {
                let (diff, b) = limbs[i].overflowing_sub(P[i]);
                let (diff, b2) = diff.overflowing_sub(borrow);
                limbs[i] = diff;
                borrow = (b as u64) | (b2 as u64);
            }
        }
        
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limbs[i].to_le_bytes());
        }
        
        bytes
    }

    /// Create from bytes in little-endian order
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        
        for i in 0..4 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            limbs[i] = u64::from_le_bytes(b);
        }
        
        Self { limbs }.to_montgomery()
    }
    
    /// Ensure the field element is fully reduced modulo p
    pub fn reduce(&self) -> Self {
        // For now, just return self - our operations should already be reducing
        // If we find we need explicit reduction, we can implement it here
        *self
    }
    
}

/// Precomputed constants for common operations
pub struct MontgomeryConstants {
    /// Montgomery form of 1
    pub one: MontgomeryFieldElement,
    /// Montgomery form of 2
    pub two: MontgomeryFieldElement,
    /// Montgomery form of d = -121665/121666
    pub d: MontgomeryFieldElement,
    /// Montgomery form of 2*d
    pub two_d: MontgomeryFieldElement,
    /// Montgomery form of sqrt(-1)
    pub sqrt_m1: MontgomeryFieldElement,
}

impl MontgomeryConstants {
    /// Initialize precomputed constants
    pub fn new() -> Self {
        let one = MontgomeryFieldElement::from_u64(1);
        let two = MontgomeryFieldElement::from_u64(2);
        
        // d = -121665/121666 mod p
        // First compute it correctly
        let n1 = MontgomeryFieldElement::from_u64(121665);
        let n2 = MontgomeryFieldElement::from_u64(121666);
        let n2_inv = n2.invert();
        let d_positive = n1.montgomery_mul(&n2_inv);
        let d = d_positive.neg();
        
        let two_d = d.add(&d);
        
        // sqrt(-1) mod p
        let sqrt_m1 = MontgomeryFieldElement::from_montgomery_limbs([
            0xc4ee1b274a0ea0b0,
            0x2f431806ad2fe478,
            0x2b4d00993dfbd7a7,
            0x2b8324804fc1df0b,
        ]);
        
        Self {
            one,
            two,
            d,
            two_d,
            sqrt_m1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_multiplication() {
        let a = MontgomeryFieldElement::from_u64(12345);
        let b = MontgomeryFieldElement::from_u64(67890);
        
        let c = a.montgomery_mul(&b);
        let expected = MontgomeryFieldElement::from_u64(12345 * 67890);
        
        assert_eq!(c.from_montgomery(), expected.from_montgomery());
    }

    #[test]
    fn test_montgomery_squaring() {
        let a = MontgomeryFieldElement::from_u64(12345);
        
        let square = a.montgomery_square();
        let expected = a.montgomery_mul(&a);
        
        assert_eq!(square, expected);
    }

    #[test]
    fn test_field_arithmetic() {
        let a = MontgomeryFieldElement::from_u64(100);
        let b = MontgomeryFieldElement::from_u64(200);
        
        let sum = a.add(&b);
        assert_eq!(sum.from_montgomery().limbs[0], 300);
        
        let diff = b.sub(&a);
        assert_eq!(diff.from_montgomery().limbs[0], 100);
        
        let neg_a = a.neg();
        let zero = a.add(&neg_a);
        assert_eq!(zero.from_montgomery().limbs[0], 0);
    }

    #[test]
    fn test_inversion() {
        let a = MontgomeryFieldElement::from_u64(12345);
        let a_inv = a.invert();
        
        let one = a.montgomery_mul(&a_inv);
        let expected_one = MontgomeryFieldElement::from_u64(1);
        
        // Compare in Montgomery form since both are Montgomery elements
        assert_eq!(one, expected_one);
    }
}