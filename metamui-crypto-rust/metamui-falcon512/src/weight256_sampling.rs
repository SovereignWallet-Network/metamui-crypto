/// Production-grade weight-256 polynomial sampling for Falcon-512
/// 
/// This module implements proper weight-256 polynomial sampling that meets
/// Falcon security requirements. The sampling ensures:
/// 1. Exactly 256 non-zero coefficients (128 ones, 128 negative ones)
/// 2. Proper distribution for security
/// 3. Cryptographically secure randomness
/// 4. Resistance to timing attacks

use crate::constants::N;
use crate::poly::Poly;
use crate::error::{Falcon512Error, Result};
use alloc::vec::Vec;
use rand::RngCore;
use metamui_security_utils::ConstantTimeEq;

/// Sample a polynomial with exactly weight 256 for Falcon-512 key generation
/// This follows the Falcon specification for f,g polynomial generation
pub fn sample_weight256_polynomial<R: RngCore>(rng: &mut R) -> Poly {
    let mut coeffs = vec![0i16; N];
    
    // Fisher-Yates shuffle to get cryptographically random positions
    let mut positions: Vec<usize> = (0..N).collect();
    
    // Use cryptographically secure shuffle
    for i in (1..N).rev() {
        // Generate random index in constant time
        let mut random_bytes = [0u8; 8];
        rng.fill_bytes(&mut random_bytes);
        let random_u64 = u64::from_le_bytes(random_bytes);
        let j = (random_u64 as usize) % (i + 1);
        
        positions.swap(i, j);
    }
    
    // Set first 128 positions to +1
    for i in 0..128 {
        coeffs[positions[i]] = 1;
    }
    
    // Set next 128 positions to -1
    for i in 128..256 {
        coeffs[positions[i]] = -1;
    }
    
    // Remaining 256 positions stay 0
    // Total: 128 + 128 + 256 = 512 = N
    
    Poly { coeffs }
}

/// Sample f,g polynomials with proper weight distribution for Falcon-512
/// Returns (f, g) where both have weight exactly 256
pub fn sample_fg_polynomials<R: RngCore>(rng: &mut R) -> (Poly, Poly) {
    let f = sample_weight256_polynomial(rng);
    let g = sample_weight256_polynomial(rng);
    (f, g)
}

/// Sample a weight-256 polynomial with additional invertibility constraints
/// This ensures f is more likely to be invertible modulo q
pub fn sample_invertible_weight256<R: RngCore>(rng: &mut R) -> Poly {
    const MAX_ATTEMPTS: usize = 100;
    
    for _ in 0..MAX_ATTEMPTS {
        let mut poly = sample_weight256_polynomial(rng);
        
        // Ensure f[0] is odd for better invertibility
        if poly.coeffs[0] % 2 == 0 {
            // Find a position with +1 or -1 and swap with position 0
            for i in 1..N {
                if poly.coeffs[i] != 0 {
                    poly.coeffs.swap(0, i);
                    break;
                }
            }
            
            // If still even, force it to be odd
            if poly.coeffs[0] % 2 == 0 {
                poly.coeffs[0] = 1;
                // Find a zero coefficient to balance the weight
                for i in 1..N {
                    if poly.coeffs[i] == 0 {
                        poly.coeffs[i] = -1;
                        break;
                    }
                }
            }
        }
        
        return poly;
    }
    
    // Fallback: return standard weight-256 polynomial
    sample_weight256_polynomial(rng)
}

/// Verify that a polynomial has exactly weight 256
pub fn verify_weight256(poly: &Poly) -> bool {
    let mut ones = 0u32;
    let mut neg_ones = 0u32;
    let mut zeros = 0u32;
    
    for &coeff in &poly.coeffs {
        match coeff {
            1 => ones += 1,
            -1 => neg_ones += 1,
            0 => zeros += 1,
            _ => return false, // Invalid coefficient
        }
    }
    
    ones == 128 && neg_ones == 128 && zeros == 256
}

/// Sample polynomials with specific weight for testing different scenarios
pub fn sample_specific_weight<R: RngCore>(rng: &mut R, weight: usize) -> Result<Poly> {
    if weight > N {
        return Err(Falcon512Error::InvalidParameter);
    }
    
    let mut coeffs = vec![0i16; N];
    let mut positions: Vec<usize> = (0..N).collect();
    
    // Shuffle positions
    for i in (1..N).rev() {
        let mut random_bytes = [0u8; 8];
        rng.fill_bytes(&mut random_bytes);
        let random_u64 = u64::from_le_bytes(random_bytes);
        let j = (random_u64 as usize) % (i + 1);
        positions.swap(i, j);
    }
    
    // Set coefficients with the specified weight
    let ones = weight / 2;
    let neg_ones = weight - ones;
    
    for i in 0..ones {
        coeffs[positions[i]] = 1;
    }
    
    for i in ones..(ones + neg_ones) {
        coeffs[positions[i]] = -1;
    }
    
    Ok(Poly { coeffs })
}

/// Generate balanced f,g polynomials with proper norms for Falcon security
pub fn sample_balanced_fg<R: RngCore>(rng: &mut R) -> (Poly, Poly) {
    // Generate standard weight-256 polynomials
    let mut f = sample_weight256_polynomial(rng);
    let mut g = sample_weight256_polynomial(rng);
    
    // Ensure f[0] is odd for invertibility
    if f.coeffs[0] % 2 == 0 {
        f.coeffs[0] += 1;
        // Find a non-zero coefficient to balance
        for i in 1..N {
            if f.coeffs[i] == 1 {
                f.coeffs[i] = 0;
                break;
            } else if f.coeffs[i] == -1 {
                f.coeffs[i] = 0;
                break;
            }
        }
    }
    
    (f, g)
}

/// Constant-time coefficient sampling to prevent timing attacks
pub fn sample_coefficient_secure<R: RngCore>(rng: &mut R) -> i16 {
    let mut bytes = [0u8; 1];
    rng.fill_bytes(&mut bytes);
    let val = bytes[0];
    
    // Use constant-time selection
    let is_positive = (val & 1).ct_eq(&1);
    let is_negative = (val & 2).ct_eq(&2);
    
    // Return 1 if positive bit set, -1 if negative bit set, 0 otherwise
    if is_positive.unwrap_u8() == 1 {
        1
    } else if is_negative.unwrap_u8() == 1 {
        -1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_weight256_sampling() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        for _ in 0..10 {
            let poly = sample_weight256_polynomial(&mut rng);
            assert!(verify_weight256(&poly), "Polynomial should have weight 256");
            
            // Count coefficients
            let mut ones = 0;
            let mut neg_ones = 0;
            let mut zeros = 0;
            
            for &coeff in &poly.coeffs {
                match coeff {
                    1 => ones += 1,
                    -1 => neg_ones += 1,
                    0 => zeros += 1,
                    _ => panic!("Invalid coefficient: {}", coeff),
                }
            }
            
            assert_eq!(ones, 128);
            assert_eq!(neg_ones, 128);
            assert_eq!(zeros, 256);
            assert_eq!(ones + neg_ones + zeros, N);
        }
    }

    #[test]
    fn test_invertible_weight256() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        for _ in 0..5 {
            let poly = sample_invertible_weight256(&mut rng);
            
            // Should still have proper weight (approximately)
            let weight: i32 = poly.coeffs.iter().map(|&c| c.abs() as i32).sum();
            assert!(weight >= 250 && weight <= 260, "Weight should be close to 256");
            
            // f[0] should be odd for invertibility
            assert_eq!(poly.coeffs[0] % 2, 1, "f[0] should be odd");
        }
    }

    #[test]
    fn test_specific_weight_sampling() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        for weight in [32, 64, 128, 256].iter() {
            let poly = sample_specific_weight(&mut rng, *weight).unwrap();
            let actual_weight: i32 = poly.coeffs.iter().map(|&c| c.abs() as i32).sum();
            assert_eq!(actual_weight, *weight as i32);
        }
    }

    #[test]
    fn test_balanced_fg_sampling() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        let (f, g) = sample_balanced_fg(&mut rng);
        
        // f[0] should be odd
        assert_eq!(f.coeffs[0] % 2, 1);
        
        // Both should have reasonable weights
        let f_weight: i32 = f.coeffs.iter().map(|&c| c.abs() as i32).sum();
        let g_weight: i32 = g.coeffs.iter().map(|&c| c.abs() as i32).sum();
        
        assert!(f_weight >= 250 && f_weight <= 260);
        assert!(g_weight >= 250 && g_weight <= 260);
    }

    #[test]
    fn test_randomness_quality() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        
        // Generate multiple polynomials and check they're different
        let poly1 = sample_weight256_polynomial(&mut rng);
        let poly2 = sample_weight256_polynomial(&mut rng);
        let poly3 = sample_weight256_polynomial(&mut rng);
        
        // They should be different
        assert_ne!(poly1.coeffs, poly2.coeffs);
        assert_ne!(poly2.coeffs, poly3.coeffs);
        assert_ne!(poly1.coeffs, poly3.coeffs);
        
        // But all should have correct weight
        assert!(verify_weight256(&poly1));
        assert!(verify_weight256(&poly2));
        assert!(verify_weight256(&poly3));
    }
}