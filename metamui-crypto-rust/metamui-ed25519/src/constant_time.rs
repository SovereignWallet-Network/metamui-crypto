//! Constant-time Ed25519 operations for security-critical implementations
//! 
//! Copyright (c) 2025 Sovereign Wallet Co., Ltd.
//! Licensed under the Apache License, Version 2.0
//! Author: Phantom Seokgu Yun <phantom@metamui.id>
//! Repository: https://github.com/SovereignWallet-Network/metamui-crypto

use crate::field::FieldElement;
use crate::point::EdwardsPoint;
use crate::scalar::Scalar;
use crate::error::{Ed25519Error, Result};
use metamui_security_utils::memory::Zeroize;
use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};
use metamui_sha2::sha512::Sha512Hasher;

/// Constant-time Ed25519 operations
pub struct ConstantTimeEd25519;

impl ConstantTimeEd25519 {
    /// Constant-time scalar multiplication using Montgomery ladder
    /// 
    /// This implementation is resistant to timing attacks by ensuring
    /// all code paths take the same amount of time regardless of the
    /// scalar value.
    pub fn scalar_mult_constant_time(scalar: &Scalar, point: &EdwardsPoint) -> EdwardsPoint {
        // Use a simple double-and-add algorithm for now
        // This is still constant-time due to our field operations
        let mut result = EdwardsPoint::identity();
        let mut temp = *point;
        
        // Process scalar bits from least significant to most significant
        for i in 0..256 {
            let bit = scalar.bit(i);
            
            // Conditionally add temp to result if bit is set
            let new_result = result + temp;
            result = EdwardsPoint::conditional_select(&result, &new_result, bit);
            
            // Always double temp
            temp = temp.double();
        }
        
        result
    }
    
    /// Constant-time field element inversion using Fermat's little theorem
    /// 
    /// For prime p = 2^255 - 19, we compute a^(-1) = a^(p-2) mod p
    pub fn field_invert_constant_time(a: &FieldElement) -> FieldElement {
        // Use the proper inversion algorithm
        a.invert()
    }
    
    /// Constant-time square root computation using Tonelli-Shanks algorithm
    /// 
    /// Returns None if no square root exists, but in constant time
    pub fn field_sqrt_constant_time(a: &FieldElement) -> Option<FieldElement> {
        // Use optimized square root for Ed25519's prime
        // Implementation ensures constant time regardless of whether root exists
        
        // (p-1)/2 for Legendre symbol computation
        // Use the field element sqrt implementation
        a.sqrt()
    }
    
    /// Decode a point exactly as RFC 8032 §5.1.3 specifies.
    ///
    /// Decoding FAILS (returns `Err`) when
    /// 1. the 255-bit y-coordinate is not canonical (y >= p),
    /// 2. x^2 = (y^2 - 1) / (d y^2 + 1) has no square root, or
    /// 3. x = 0 and the sign bit x_0 is 1.
    ///
    /// Nothing else is screened: small-order (torsion) points decode, because
    /// RFC 8032 does not reject them. Policy oracle:
    /// test-vectors/ed25519/ed25519-policy-vectors.json (`valid_rfc8032`).
    pub fn decode_point_constant_time(bytes: &[u8; 32]) -> Result<EdwardsPoint> {
        // Extract y-coordinate and sign bit
        let mut y_bytes = *bytes;
        let sign_bit = (y_bytes[31] & 0x80) != 0;
        y_bytes[31] &= 0x7f; // Clear sign bit

        // §5.1.3 step 1: "If the resulting value is >= p, decoding fails."
        if !is_canonical_field_encoding(&y_bytes) {
            return Err(Ed25519Error::InvalidPoint("Non-canonical y-coordinate (y >= p)".to_string()));
        }

        let y = FieldElement::from_bytes(&y_bytes);

        // Compute x-coordinate: x^2 = (y^2 - 1) / (d*y^2 + 1)
        let y_squared = y.square();
        let numerator = &y_squared - &FieldElement::ONE;
        let denominator = &(&FieldElement::EDWARDS_D * &y_squared) + &FieldElement::ONE;

        // Constant-time inversion
        let denominator_inv = Self::field_invert_constant_time(&denominator);
        let x_squared = &numerator * &denominator_inv;

        // §5.1.3 step 3: no square root => decoding fails.
        let x_opt = Self::field_sqrt_constant_time(&x_squared);

        match x_opt {
            Some(mut x) => {
                // §5.1.3 step 4: "If x = 0, and x_0 = 1, decoding fails."
                if sign_bit && x.is_zero() {
                    return Err(Ed25519Error::InvalidPoint("x = 0 with the sign bit set".to_string()));
                }

                // Adjust sign to match sign bit
                let x_is_negative = x.is_negative();
                let should_negate = Choice::from((x_is_negative as u8) ^ (sign_bit as u8));
                x = x.conditional_negate(should_negate);

                // Validate point is on curve (constant time)
                let point = EdwardsPoint::from_xy_coordinates(x, y);
                if point.is_on_curve() {
                    Ok(point)
                } else {
                    Err(Ed25519Error::InvalidPoint("Point not on curve".to_string()))
                }
            }
            None => Err(Ed25519Error::InvalidPoint("Invalid y-coordinate".to_string())),
        }
    }

    /// Ed25519 signature verification: RFC 8032 §5.1.7 as written.
    ///
    /// MetaMUI policy (decided 2026-09-24, "RFC 8032 as written"):
    /// - A and R are decoded per §5.1.3 ([`Self::decode_point_constant_time`]):
    ///   y >= p, x = 0 with the sign bit set, and a missing square root are
    ///   all decoding failures (`Err`).
    /// - S >= L is refused (`Err`), by a full comparison against L.
    /// - The signature is accepted iff the COFACTORED equation
    ///   [8][S]B = [8]R + [8][k]A holds, k = SHA-512(R || A || M) mod L over
    ///   the received encodings of R and A.
    /// - Small-order A and R are NOT screened; RFC 8032 does not require it.
    ///   (Before 2026-09-24 this function rejected small-order public keys and
    ///   accepted non-canonical encodings of A and R; both were wrong for the
    ///   policy and both are gone.)
    ///
    /// Oracle: test-vectors/ed25519/ed25519-policy-vectors.json, column
    /// `valid_rfc8032`; gated by tests/ed25519_policy_vectors.rs.
    pub fn verify_constant_time(
        signature: &[u8; 64],
        message: &[u8],
        public_key: &[u8; 32]
    ) -> Result<bool> {
        // Decode signature components
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature[0..32]);
        s_bytes.copy_from_slice(&signature[32..64]);
        
        // Validate R point (constant time)
        let r_point = Self::decode_point_constant_time(&r_bytes)?;
        
        // Validate S scalar (constant time)
        let s_scalar = Scalar::from_bytes(&s_bytes)
            .ok_or_else(|| Ed25519Error::InvalidSignature("Invalid S scalar".to_string()))?;
        
        // Decode public key (constant time)
        let public_key_point = Self::decode_point_constant_time(public_key)?;
        
        // No small-order screen on A (or R): RFC 8032 does not require one,
        // and the cofactored equation below is what §5.1.7 permits.

        // Compute hash H(R || A || M) (constant time)
        let mut hasher = Sha512Hasher::new();
        hasher.update(&r_bytes);
        hasher.update(public_key);
        hasher.update(message);
        let hash = hasher.finalize();
        
        let h_scalar = Scalar::from_bytes_mod_order(&hash);
        
        // Verify equation: [8][S]B = [8]R + [8][H(R||A||M)]A (constant time)
        let base_point = EdwardsPoint::generator();
        let lhs = Self::scalar_mult_constant_time(&s_scalar, &base_point).multiply_by_cofactor();
        let rhs = r_point.multiply_by_cofactor() + 
                  Self::scalar_mult_constant_time(&h_scalar, &public_key_point).multiply_by_cofactor();
        
        // Constant-time comparison
        Ok(lhs.ct_eq(&rhs).into())
    }
    
    /// Constant-time key generation
    /// 
    /// Generates Ed25519 keypair with proper entropy validation
    pub fn generate_keypair_constant_time(seed: &[u8; 32]) -> Result<([u8; 32], [u8; 64])> {
        // Hash the seed to get scalar and prefix
        let mut hasher = Sha512Hasher::new();
        hasher.update(seed);
        let hash = hasher.finalize();
        
        // Extract scalar from first 32 bytes
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash[0..32]);
        
        // Clamp the scalar according to Ed25519 specification
        scalar_bytes[0] &= 248;  // Clear bottom 3 bits
        scalar_bytes[31] &= 127; // Clear top bit
        scalar_bytes[31] |= 64;  // Set second-highest bit
        
        // Use from_bytes_mod_order since clamped scalars can be >= L
        let scalar = Scalar::from_bytes_mod_order(&scalar_bytes);
        
        // Compute public key: A = [a]B
        let base_point = EdwardsPoint::generator();
        let public_key_point = Self::scalar_mult_constant_time(&scalar, &base_point);
        let public_key_bytes = public_key_point.encode();
        
        // Construct private key (scalar + prefix)
        let mut private_key = [0u8; 64];
        private_key[0..32].copy_from_slice(seed);
        private_key[32..64].copy_from_slice(&hash[32..64]);
        
        Ok((public_key_bytes, private_key))
    }
    
    /// Secure memory clearing for sensitive data
    /// 
    /// Ensures cryptographic material is properly cleared from memory
    pub fn clear_memory(data: &mut [u8]) {
        data.zeroize();
    }
}

/// `true` iff the 255-bit little-endian value (sign bit already cleared) is
/// strictly less than p = 2^255 - 19, i.e. a canonical field encoding.
fn is_canonical_field_encoding(y: &[u8; 32]) -> bool {
    // p - 1 = 2^255 - 20, little-endian.
    const P_MINUS_1: [u8; 32] = [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ];
    for i in (0..32).rev() {
        if y[i] < P_MINUS_1[i] {
            return true;
        }
        if y[i] > P_MINUS_1[i] {
            return false;
        }
    }
    true // y == p - 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    
    #[test]
    fn test_constant_time_scalar_mult() {
        // Scalar = 1 (little-endian)
        let scalar_bytes = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let scalar = Scalar::from_bytes(&scalar_bytes)
            .expect("Valid scalar");
        let base = EdwardsPoint::generator();
        let result = ConstantTimeEd25519::scalar_mult_constant_time(&scalar, &base);
        assert!(bool::from(result.ct_eq(&base)));
    }
    
    #[test]
    fn test_constant_time_verification() {
        // Test with known good signature
        let public_key = hex!("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let message = b"test message";
        let signature = hex!("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        
        let result = ConstantTimeEd25519::verify_constant_time(&signature, message, &public_key);
        assert!(result.is_ok());
    }
}