//! Point operations for Ed25519 curve
//! 
//! Ed25519 uses the twisted Edwards curve:
//! -x^2 + y^2 = 1 + d*x^2*y^2 where d = -121665/121666

use crate::field::FieldElement;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use core::ops::{Add, Sub, Neg};

/// A point on the Ed25519 curve in extended coordinates (X:Y:Z:T)
/// 
/// Extended coordinates represent the point (X/Z, Y/Z) where T = XY/Z
/// This representation allows for efficient point addition and doubling.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct EdwardsPoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
    pub t: FieldElement,
}

impl EdwardsPoint {
    /// The identity element (point at infinity)
    pub const IDENTITY: EdwardsPoint = EdwardsPoint {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };
    
    /// The base point (generator) of the Ed25519 curve
    pub fn generator() -> EdwardsPoint {
        // Ed25519 base point coordinates (little-endian):
        // x = 15112221349535400772501151409588531511454012693041857206046113283949847762202
        // y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
        
        // Direct construction to avoid decoding issues
        let x_bytes = [
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
            0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
            0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
            0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
        ];
        
        let y_bytes = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        ];
        
        let x = FieldElement::from_bytes(&x_bytes);
        let y = FieldElement::from_bytes(&y_bytes);
        let z = FieldElement::ONE;
        let t = x * y;
        
        EdwardsPoint { x, y, z, t }
    }
    
    /// Create the identity point
    pub fn identity() -> EdwardsPoint {
        Self::IDENTITY
    }
    
    /// Create a point from x and y coordinates
    pub fn from_xy_coordinates(x: FieldElement, y: FieldElement) -> EdwardsPoint {
        let z = FieldElement::ONE;
        let t = x * y;
        
        EdwardsPoint { x, y, z, t }
    }
    
    /// Check if the point is on the Ed25519 curve
    pub fn is_on_curve(&self) -> bool {
        // Verify the curve equation: -x^2 + y^2 = z^2 + d*x^2*y^2
        // In projective form: -x^2*z^2 + y^2*z^2 = z^4 + d*x^2*y^2
        let x2 = self.x.square();
        let y2 = self.y.square();
        let z2 = self.z.square();
        let z4 = z2.square();
        
        let lhs = (y2 - x2) * z2;  // (-x^2 + y^2) * z^2
        let rhs = z4 + (FieldElement::EDWARDS_D * (x2 * y2));
        
        lhs.ct_eq(&rhs).into()
    }
    
    /// Convert to affine coordinates (x, y)
    pub fn to_affine(&self) -> (FieldElement, FieldElement) {
        let z_inv = self.z.invert();
        (self.x * z_inv, self.y * z_inv)
    }
    
    /// Encode the point to bytes (32 bytes, little-endian y with sign bit)
    pub fn encode(&self) -> [u8; 32] {
        let (x, y) = self.to_affine();
        let mut bytes = y.to_bytes();
        
        // Set the sign bit based on the parity of x
        if x.is_negative() {
            bytes[31] |= 0x80;
        }
        
        bytes
    }
    
    /// Check if point is the identity
    pub fn is_identity(&self) -> Choice {
        let y_minus_z: FieldElement = &self.y - &self.z;
        self.x.ct_eq(&FieldElement::ZERO) & 
        y_minus_z.ct_eq(&FieldElement::ZERO)
    }
    
    /// Check if point has small order (order divides 8)
    pub fn is_small_order(&self) -> bool {
        // Multiply by 8 and check if result is identity
        let p2 = self.double();
        let p4 = p2.double();
        let p8 = p4.double();
        p8.is_identity().into()
    }
    
    /// Double this point
    pub fn double(&self) -> Self {
        // 2008 Hisil–Wong–Carter–Dawson
        // 3M + 4S + 1D + 6add + 1times2
        let xx = self.x.square();
        let yy = self.y.square();
        let zz = self.z.square();
        let zz2 = &zz + &zz;
        let xy2 = (&self.x + &self.y).square();
        
        let yy_plus_xx = &yy + &xx;
        let yy_minus_xx = &yy - &xx;
        
        let a = &xy2 - &yy_plus_xx;
        let b = yy_plus_xx;
        let c = yy_minus_xx;
        let d = &zz2 - &c;
        
        Self {
            x: &a * &d,
            y: &b * &c,
            z: &c * &d,
            t: &a * &b,
        }
    }
    
    /// Add two points
    pub fn add(&self, other: &EdwardsPoint) -> Self {
        // 2008 Hisil–Wong–Carter–Dawson
        // 9M + 1D + 7add
        let y_plus_x = &self.y + &self.x;
        let y_minus_x = &self.y - &self.x;
        let pp = &y_plus_x * &(&other.y + &other.x);
        let mm = &y_minus_x * &(&other.y - &other.x);
        let tt2d = &(&self.t * &other.t) * &FieldElement::D2;
        let zz2 = &(&self.z * &other.z) + &(&self.z * &other.z);
        
        let a = &pp - &mm;
        let b = &pp + &mm;
        let c = &zz2 + &tt2d;
        let d = &zz2 - &tt2d;
        
        Self {
            x: &a * &d,
            y: &b * &c,
            z: &c * &d,
            t: &a * &b,
        }
    }
    
    /// Subtract two points
    pub fn sub(&self, other: &EdwardsPoint) -> Self {
        self.add(&other.neg())
    }
    
    /// Negate the point
    pub fn neg(&self) -> Self {
        Self {
            x: -&self.x,
            y: self.y,
            z: self.z,
            t: -&self.t,
        }
    }
    
    /// Scalar multiplication using double-and-add
    pub fn scalar_mult(&self, scalar: &[u8; 32]) -> Self {
        // Constant-time scalar multiplication using the Montgomery ladder
        let mut r0 = Self::identity();
        let mut r1 = *self;
        
        for byte in scalar.iter().rev() {
            for i in (0..8).rev() {
                let bit = Choice::from(((byte >> i) & 1) as u8);
                
                // Constant-time conditional swap
                Self::conditional_swap(&mut r0, &mut r1, bit);
                
                // Double r0 and add r1
                r1 = &r0 + &r1;
                r0 = r0.double();
                
                // Swap back if bit was set
                Self::conditional_swap(&mut r0, &mut r1, bit);
            }
        }
        
        r0
    }
    
    /// Multiply by the cofactor (8) for Ed25519
    pub fn multiply_by_cofactor(&self) -> EdwardsPoint {
        self.double().double().double() // 2^3 = 8
    }
    
    /// Constant-time conditional swap of two points
    pub fn conditional_swap(a: &mut EdwardsPoint, b: &mut EdwardsPoint, choice: Choice) {
        FieldElement::conditional_swap(&mut a.x, &mut b.x, choice);
        FieldElement::conditional_swap(&mut a.y, &mut b.y, choice);
        FieldElement::conditional_swap(&mut a.z, &mut b.z, choice);
        FieldElement::conditional_swap(&mut a.t, &mut b.t, choice);
    }
    
    /// Zero element (alias for identity)
    pub fn zero() -> Self {
        Self::identity()
    }
    
    /// One element (alias for generator)
    pub fn one() -> Self {
        Self::generator()
    }
}

impl Add for &EdwardsPoint {
    type Output = EdwardsPoint;
    
    fn add(self, other: Self) -> EdwardsPoint {
        self.add(other)
    }
}

impl Add for EdwardsPoint {
    type Output = EdwardsPoint;
    
    fn add(self, other: Self) -> EdwardsPoint {
        (&self).add(&other)
    }
}

impl Sub for &EdwardsPoint {
    type Output = EdwardsPoint;
    
    fn sub(self, other: Self) -> EdwardsPoint {
        self.sub(other)
    }
}

impl Sub for EdwardsPoint {
    type Output = EdwardsPoint;
    
    fn sub(self, other: Self) -> EdwardsPoint {
        (&self).sub(&other)
    }
}

impl Neg for &EdwardsPoint {
    type Output = EdwardsPoint;
    
    fn neg(self) -> EdwardsPoint {
        self.neg()
    }
}

impl Neg for EdwardsPoint {
    type Output = EdwardsPoint;
    
    fn neg(self) -> EdwardsPoint {
        (&self).neg()
    }
}

impl ConditionallySelectable for EdwardsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        EdwardsPoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
            t: FieldElement::conditional_select(&a.t, &b.t, choice),
        }
    }
}

impl ConstantTimeEq for EdwardsPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Two points are equal if X1*Z2 = X2*Z1 and Y1*Z2 = Y2*Z1
        let x1z2 = &self.x * &other.z;
        let x2z1 = &other.x * &self.z;
        let y1z2 = &self.y * &other.z;
        let y2z1 = &other.y * &self.z;
        
        x1z2.ct_eq(&x2z1) & y1z2.ct_eq(&y2z1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_identity_point() {
        let id = EdwardsPoint::identity();
        assert!(bool::from(id.is_identity()));
        assert!(id.is_on_curve());
    }
    
    #[test]
    fn test_generator_point() {
        let g = EdwardsPoint::generator();
        assert!(!bool::from(g.is_identity()));
        assert!(g.is_on_curve());
        
        // Check that 8*cofactor*generator = identity (l = 8*cofactor)
        // For Ed25519, the order is 2^252 + 27742317777372353535851937790883648493
        // cofactor = 8, so we need to multiply by the subgroup order
        
        // For now, just check the generator is valid
        let g2 = g.double();
        assert!(g2.is_on_curve());
    }
    
    #[test]
    fn test_point_addition() {
        let g = EdwardsPoint::generator();
        let g2 = g.double();
        let g3 = &g + &g2;
        
        assert!(g3.is_on_curve());
        
        // Check g + g = 2*g
        let g_plus_g = &g + &g;
        // Use constant-time equality which properly compares projective points
        assert!(bool::from(g_plus_g.ct_eq(&g2)));
    }
    
    #[test]
    fn test_point_negation() {
        let g = EdwardsPoint::generator();
        let neg_g = g.neg();
        
        assert!(neg_g.is_on_curve());
        
        // Check g + (-g) = 0
        let sum = &g + &neg_g;
        assert!(bool::from(sum.is_identity()));
    }
}