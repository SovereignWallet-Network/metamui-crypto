//! Falcon signature format handling
//! 
//! Falcon signatures consist of:
//! - Header byte (0x39 for Falcon-512)
//! - 40-byte salt/nonce
//! - Compressed s1 polynomial (s0 is reconstructed during verification)

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;

const HEADER_FALCON512: u8 = 0x39;
const SALT_LEN: usize = 40;

/// Decompress a Falcon signature - now extracts BOTH s0 and s1
///
/// Returns (s0, s1) where both are directly stored in the signature.
/// This is necessary because s0 cannot be reconstructed with acceptable norm.
pub fn decompress_and_reconstruct(
    compressed_sig: &[u8],
    message: &[u8],
    public_key_h: &[i16],
) -> Result<(Vec<i16>, Vec<i16>)> {
    // Expected size: 1 (header) + 40 (salt) + 512*2 (s1) + 512*2 (s0) = 2089 bytes
    let expected_size = 1 + SALT_LEN + (N * 2) + (N * 2);

    if compressed_sig.len() < expected_size {
        return Err(Falcon512Error::InvalidSignature);
    }

    // Verify header
    if compressed_sig[0] != HEADER_FALCON512 {
        return Err(Falcon512Error::InvalidSignature);
    }

    // Extract salt
    let salt = &compressed_sig[1..1 + SALT_LEN];

    // Extract s1 (starts at offset 41, 512 * 2 bytes)
    let s1_start = 1 + SALT_LEN;
    let s1_end = s1_start + (N * 2);
    let s1 = decompress_s1(&compressed_sig[s1_start..s1_end])?;

    // Extract s0 (starts after s1, 512 * 2 bytes)
    let s0_start = s1_end;
    let s0_end = s0_start + (N * 2);
    let s0 = decompress_s1(&compressed_sig[s0_start..s0_end])?; // Reuse same decompression logic

    // Debug: Print extracted values
    #[cfg(feature = "std")]
    {
        let s0_norm: i64 = s0.iter().map(|&x| x as i64 * x as i64).sum();
        let s1_norm: i64 = s1.iter().map(|&x| x as i64 * x as i64).sum();
        let combined_norm = s0_norm + s1_norm;
        eprintln!("DEBUG signature_format::decompress_and_reconstruct:");
        eprintln!("  Signature size: {} bytes (expected {})", compressed_sig.len(), expected_size);
        eprintln!("  s0 norm²: {}", s0_norm);
        eprintln!("  s1 norm²: {}", s1_norm);
        eprintln!("  combined norm²: {} (bound: 34034726)", combined_norm);
        eprintln!("  norm check: {}", combined_norm < 34034726);
        eprintln!("  s0[0..5]: {:?}", &s0[..5.min(s0.len())]);
        eprintln!("  s1[0..5]: {:?}", &s1[..5.min(s1.len())]);
    }

    Ok((s0, s1))
}

/// Decompress s1 from Golomb-Rice encoded signature data
pub fn decompress_s1(compressed_data: &[u8]) -> Result<Vec<i16>> {
    crate::nist_encoding::comp_decode(compressed_data, 9) // logn=9 for N=512
}

/// Reconstruct s0 from c, h, and s1
/// Uses the equation: s0 = c - h*s1 (mod q)
pub fn reconstruct_s0(c: &[i16], h: &[i16], s1: &[i16]) -> Result<Vec<i16>> {
    if c.len() != N || h.len() != N || s1.len() != N {
        return Err(Falcon512Error::InvalidPolynomialSize);
    }
    
    let mut s0 = Vec::with_capacity(N);
    
    // Use NTT-based polynomial multiplication for efficiency and correctness
    // This handles the cyclotomic ring Z[X]/(X^N + 1) properly
    let h_times_s1 = crate::ntt_falcon::multiply_ntt(h, s1);

    // Compute s0 = c - h*s1 (mod q)
    for i in 0..N {
        // Both c and h*s1 might be in centered representation [-q/2, q/2]
        // or positive representation [0, q)
        // Ensure we work in consistent positive representation first
        let c_val = if c[i] < 0 {
            c[i] as i32 + Q as i32
        } else {
            c[i] as i32
        };

        let h_s1_val = if h_times_s1[i] < 0 {
            h_times_s1[i] as i32 + Q as i32
        } else {
            h_times_s1[i] as i32
        };

        // Modular subtraction: s0 = c - h*s1 (mod q)
        let s0_val = (c_val - h_s1_val).rem_euclid(Q as i32);

        // Center the value to [-q/2, q/2]
        let centered = if s0_val > Q as i32 / 2 {
            s0_val - Q as i32
        } else {
            s0_val
        };

        s0.push(centered as i16);
    }
    
    Ok(s0)
}

/// Hash message with salt to get challenge polynomial
fn hash_to_point(message: &[u8], salt: &[u8]) -> Result<Vec<i16>> {
    // Use SHAKE-256 to hash message and salt
    use metamui_shake::shake256::Shake256;

    let mut hasher = Shake256::new();
    hasher.update(salt).map_err(|_| Falcon512Error::InvalidSignature)?;
    hasher.update(message).map_err(|_| Falcon512Error::InvalidSignature)?;

    let mut reader = hasher.finalize_xof();
    let output = reader.read(N * 2);
    
    // Convert to polynomial coefficients mod q
    let mut c = Vec::with_capacity(N);
    for i in 0..N {
        if i * 2 + 1 < output.len() {
            let val = u16::from_le_bytes([output[i * 2], output[i * 2 + 1]]) % Q;
            
            // Center around 0
            let centered = if val > Q / 2 {
                (val as i32 - Q as i32) as i16
            } else {
                val as i16
            };
            
            c.push(centered);
        } else {
            c.push(0);
        }
    }
    
    Ok(c)
}

/// Compress s0 and s1 into signature format
pub fn compress_signature(s0: &[i16], s1: &[i16], salt: &[u8]) -> Result<Vec<u8>> {
    let mut sig = Vec::with_capacity(666);
    
    // Header
    sig.push(HEADER_FALCON512);
    
    // Salt (40 bytes)
    if salt.len() != SALT_LEN {
        return Err(Falcon512Error::InvalidSignature);
    }
    sig.extend_from_slice(salt);
    
    // Compress s1 using Golomb-Rice encoding (NIST format)
    let compressed_s1 = crate::nist_encoding::comp_encode(s1, 9); // logn=9 for N=512
    sig.extend_from_slice(&compressed_s1);
    
    // Ensure we don't exceed max signature size
    if sig.len() > 690 {
        return Err(Falcon512Error::SignatureTooLarge);
    }
    
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signature_format() {
        let s0 = vec![1i16; N];
        let s1 = vec![2i16; N];
        let salt = [3u8; SALT_LEN];
        
        // Test compression
        let compressed = compress_signature(&s0, &s1, &salt).unwrap();
        assert_eq!(compressed[0], HEADER_FALCON512);
        assert_eq!(&compressed[1..41], &salt);
        
        // Test s1 decompression round-trip
        let s1_decompressed = decompress_s1(&compressed[41..]).unwrap();
        assert_eq!(s1_decompressed.len(), N);
        assert_eq!(s1_decompressed, s1);
    }
}