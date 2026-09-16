//! Sampling functions for ML-KEM

use crate::{
    error::{MLKemError, Result},
    polynomial::{Polynomial, N, Q},
};
use metamui_shake::shake128::Shake128;
use metamui_shake::shake256::Shake256;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Sample polynomial from uniform distribution
pub fn sample_uniform(rho: &[u8; 32], i: u8, j: u8) -> Result<Polynomial> {
    let mut poly = Polynomial::zero();
    
    // Create seed for XOF
    let mut seed = Vec::with_capacity(34);
    seed.extend_from_slice(rho);
    seed.push(j);
    seed.push(i);
    
    // Use SHAKE-128 as XOF
    let mut xof = Shake128::new();
    xof.update(&seed);
    let mut reader = xof.finalize_xof();
    
    let mut coeffs_sampled = 0;
    let mut buf = [0u8; 3];
    
    while coeffs_sampled < N {
        reader.read_into(&mut buf);
        
        let d1 = ((buf[0] as u16) | ((buf[1] as u16 & 0x0f) << 8)) as i16;
        let d2 = (((buf[1] as u16) >> 4) | ((buf[2] as u16) << 4)) as i16;
        
        if d1 < Q && coeffs_sampled < N {
            poly.coefficients[coeffs_sampled] = d1;
            coeffs_sampled += 1;
        }
        
        if d2 < Q && coeffs_sampled < N {
            poly.coefficients[coeffs_sampled] = d2;
            coeffs_sampled += 1;
        }
    }
    
    Ok(poly)
}

/// Sample polynomial from centered binomial distribution
pub fn sample_noise(eta: usize, sigma: &[u8; 32], nonce: u8) -> Result<Polynomial> {
    let mut poly = Polynomial::zero();
    
    // Create seed for PRF
    let mut seed = Vec::with_capacity(33);
    seed.extend_from_slice(sigma);
    seed.push(nonce);
    
    // Use SHAKE-256 as PRF
    let mut prf = Shake256::new();
    let _ = prf.update(&seed);
    let mut reader = prf.finalize_xof();
    
    // Sample bytes needed for CBD
    // For eta=2: each coefficient needs 4 bits, so 256 coeffs * 4 bits / 8 = 128 bytes
    // For eta=3: each coefficient needs 6 bits, so 256 coeffs * 6 bits / 8 = 192 bytes
    let bytes_needed = if eta == 2 {
        128  // 256 coefficients * 4 bits / 8 bits per byte
    } else if eta == 3 {
        192  // 256 coefficients * 6 bits / 8 bits per byte
    } else {
        return Err(MLKemError::InvalidParameter);
    };
    let buf = reader.read(bytes_needed);
    
    // Centered binomial distribution sampling
    if eta == 2 {
        // For eta=2, we need 128 bytes to generate 256 coefficients
        // Process 32 bits at a time to generate 8 coefficients
        for i in 0..N/8 {
            let t = load_32(&buf[4*i..4*i+4]);
            let mut d = t & 0x55555555;
            d += (t >> 1) & 0x55555555;
            
            for j in 0..8 {
                let a = ((d >> (4*j)) & 0x3) as i16;
                let b = ((d >> (4*j + 2)) & 0x3) as i16;
                poly.coefficients[8*i + j] = a - b;
            }
        }
    } else if eta == 3 {
        // For eta=3, we need 192 bytes to generate 256 coefficients
        // Each coefficient uses 6 bits (3 for positive a, 3 for negative b).
        //
        // FIPS 203 §4.2.1 BytesToBits is LSB-first:
        //   bit[8*i + j] = (B[i] >> j) & 1
        // Coefficient i consumes bits [6*i, 6*i+1, ..., 6*i+5] and computes
        //   a = popcount(bits[6i, 6i+1, 6i+2])
        //   b = popcount(bits[6i+3, 6i+4, 6i+5])
        //   z[i] = a - b
        //
        // The previous implementation packed the 6 bits MSB-first into a
        // local register, then read alternating positions out — equivalent
        // to using the FIPS 203 IPD's old BytesToBits convention. Replaced
        // with the spec-compliant LSB-first cross-byte slice below
        // (Finding #28 in tools/swift-review/PHASE_2_STATUS.md).
        for i in 0..N {
            let bit_start = 6 * i;
            let byte_idx = bit_start / 8;
            let shift = bit_start % 8;

            // 6 bits may span two bytes — assemble them LSB-first.
            let raw = if shift <= 2 {
                ((buf[byte_idx] >> shift) & 0x3F) as u8
            } else {
                let low = buf[byte_idx] >> shift;
                let high = buf[byte_idx + 1] << (8 - shift);
                ((low | high) & 0x3F) as u8
            };

            let a = (raw & 0x07).count_ones() as i16;       // bits 0..2 → +ve
            let b = ((raw >> 3) & 0x07).count_ones() as i16; // bits 3..5 → -ve
            poly.coefficients[i] = a - b;
        }
    } else {
        return Err(MLKemError::InvalidParameter);
    }
    
    Ok(poly)
}

fn load_32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[allow(dead_code)]
fn load_24(bytes: &[u8]) -> u32 {
    (bytes[0] as u32) | ((bytes[1] as u32) << 8) | ((bytes[2] as u32) << 16)
}

#[allow(dead_code)]
fn hamming_weight(x: u32) -> u32 {
    x.count_ones()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sample_uniform() {
        let rho = [0u8; 32];
        let poly = sample_uniform(&rho, 0, 0).unwrap();
        
        // Check all coefficients are in valid range
        for i in 0..N {
            assert!(poly.coefficients[i] >= 0);
            assert!(poly.coefficients[i] < Q);
        }
    }
    
    #[test]
    fn test_sample_noise() {
        let sigma = [0u8; 32];
        
        // Test eta=2
        let poly2 = sample_noise(2, &sigma, 0).unwrap();
        for i in 0..N {
            assert!(poly2.coefficients[i] >= -2);
            assert!(poly2.coefficients[i] <= 2);
        }
        
        // Test eta=3
        let poly3 = sample_noise(3, &sigma, 0).unwrap();
        for i in 0..N {
            assert!(poly3.coefficients[i] >= -3);
            assert!(poly3.coefficients[i] <= 3);
        }
    }
}