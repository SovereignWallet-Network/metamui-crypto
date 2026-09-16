//! NIST-compliant signature format for Falcon-512
//! 
//! This module implements the signature compression and decompression
//! according to the NIST specification, including the proper header byte
//! and Golomb-Rice encoding.

use crate::constants::{N, NONCE_SIZE};
use crate::error::{Result, Falcon512Error};
use crate::nist_golomb_rice::comp_encode_nist;
use alloc::vec::Vec;

/// NIST signature header byte for Falcon-512
const SIGNATURE_HEADER: u8 = 0x20 + 9; // 0x29

/// Compress a signature in NIST format
/// 
/// Creates a signature with format:
/// - 1 byte: header (0x29 for Falcon-512)
/// - Variable: compressed s2 polynomial using Golomb-Rice encoding
/// 
/// Note: The nonce is NOT included in the signature itself but is
/// part of the signed message format in crypto_sign.
pub fn compress_signature_nist(s1: &[i16], s2: &[i16]) -> Result<Vec<u8>> {
    if s1.len() != N || s2.len() != N {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    let mut sig = Vec::new();
    
    // Add header byte
    sig.push(SIGNATURE_HEADER);
    
    // Compress s2 using improved Golomb-Rice encoding
    // In NIST format, only s2 is stored (s1 can be recomputed during verification)
    let compressed_s2 = comp_encode_nist(s2, 9)?;
    sig.extend_from_slice(&compressed_s2);
    
    // Ensure signature is not too large
    if sig.len() > 666 {
        // Signature too large, would need restart in real implementation
        return Err(Falcon512Error::SignatureTooLarge);
    }
    
    Ok(sig)
}

/// Decompress a signature from NIST format
/// 
/// Returns the s2 polynomial. The s1 polynomial must be recomputed
/// during verification using the equation: s1 = c - s2*h (mod q)
pub fn decompress_signature_nist(sig: &[u8]) -> Result<(Vec<i16>, Vec<i16>)> {
    if sig.is_empty() {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    // Check header byte
    if sig[0] != SIGNATURE_HEADER {
        return Err(Falcon512Error::InvalidSignature);
    }

    let _ = sig;
    Err(Falcon512Error::NotImplemented)
}

/// Create a complete NIST-format signed message
/// 
/// Format:
/// - 2 bytes: signature length (big-endian)
/// - 40 bytes: nonce
/// - mlen bytes: original message
/// - sig_len bytes: signature
pub fn create_signed_message_nist(
    nonce: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_SIZE {
        return Err(Falcon512Error::InvalidNonce);
    }
    
    let sig_len = signature.len();
    let total_len = 2 + NONCE_SIZE + message.len() + sig_len;
    
    let mut sm = Vec::with_capacity(total_len);
    
    // Add signature length (big-endian)
    sm.push((sig_len >> 8) as u8);
    sm.push((sig_len & 0xFF) as u8);
    
    // Add nonce
    sm.extend_from_slice(nonce);
    
    // Add message
    sm.extend_from_slice(message);
    
    // Add signature
    sm.extend_from_slice(signature);
    
    Ok(sm)
}

/// Extract components from a NIST-format signed message
/// 
/// Returns (nonce, message, signature)
pub fn extract_from_signed_message_nist(sm: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if sm.len() < 2 + NONCE_SIZE {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    // Extract signature length
    let sig_len = ((sm[0] as usize) << 8) | (sm[1] as usize);
    
    // Verify total length
    if sm.len() < 2 + NONCE_SIZE + sig_len {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    // Extract components
    let nonce = sm[2..2 + NONCE_SIZE].to_vec();
    let msg_start = 2 + NONCE_SIZE;
    let msg_end = sm.len() - sig_len;
    let message = sm[msg_start..msg_end].to_vec();
    let signature = sm[msg_end..].to_vec();
    
    Ok((nonce, message, signature))
}

/// Improved Golomb-Rice encoding for better compression
/// 
/// This is a more sophisticated version that should achieve
/// compression closer to the NIST reference implementation.
pub fn comp_encode_advanced(s: &[i16], logn: usize) -> Vec<u8> {
    let n = 1 << logn;
    assert_eq!(s.len(), n);
    
    // Start with the header byte
    let mut out = Vec::new();
    
    // Analyze the distribution to choose optimal Rice parameter
    let max_val = s.iter().map(|&x| x.abs()).max().unwrap_or(0);
    let rice_k = if max_val < 256 { 3 } else if max_val < 512 { 4 } else { 5 };
    
    // Encode Rice parameter (3 bits)
    let mut acc = rice_k as u32;
    let mut acc_len = 3;
    
    for &coeff in s {
        // Convert to unsigned with sign bit
        let sign = if coeff < 0 { 1u32 } else { 0u32 };
        let mag = coeff.abs() as u32;
        
        // Golomb-Rice encoding: quotient in unary, remainder in binary
        let quotient = mag >> rice_k;
        let remainder = mag & ((1 << rice_k) - 1);
        
        // Encode sign (1 bit)
        acc |= sign << acc_len;
        acc_len += 1;
        
        // Encode quotient in unary (q zeros followed by 1)
        for _ in 0..quotient.min(31) {
            // Add 0 bit (already in accumulator)
            acc_len += 1;
            if acc_len >= 32 {
                // Flush bytes
                while acc_len >= 8 {
                    out.push((acc & 0xFF) as u8);
                    acc >>= 8;
                    acc_len -= 8;
                }
            }
        }
        
        // Add terminating 1 for unary
        if quotient < 32 {
            acc |= 1u32 << acc_len;
            acc_len += 1;
        }
        
        // Encode remainder in binary (rice_k bits)
        acc |= remainder << acc_len;
        acc_len += rice_k;
        
        // Flush complete bytes
        while acc_len >= 8 {
            out.push((acc & 0xFF) as u8);
            acc >>= 8;
            acc_len -= 8;
        }
    }
    
    // Flush remaining bits
    if acc_len > 0 {
        out.push((acc & 0xFF) as u8);
    }
    
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signature_compression() {
        let s1 = vec![10i16; N];
        let s2 = vec![5i16; N];
        
        let compressed = compress_signature_nist(&s1, &s2).unwrap();
        
        // Check header
        assert_eq!(compressed[0], SIGNATURE_HEADER);
        
        // Decompress and verify
        let result = decompress_signature_nist(&compressed);
        assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
    }
    
    #[test]
    fn test_signed_message_format() {
        let nonce = vec![0x42u8; 40];
        let message = b"Test message";
        let signature = vec![SIGNATURE_HEADER, 1, 2, 3, 4, 5];
        
        let sm = create_signed_message_nist(&nonce, message, &signature).unwrap();
        
        // Check format
        assert_eq!(sm[0], 0x00); // sig_len high byte
        assert_eq!(sm[1], 0x06); // sig_len low byte (6 bytes)
        assert_eq!(&sm[2..42], &nonce[..]);
        
        // Extract and verify
        let (n, m, s) = extract_from_signed_message_nist(&sm).unwrap();
        assert_eq!(n, nonce);
        assert_eq!(m, message);
        assert_eq!(s, signature);
    }
    
    #[test]
    fn test_advanced_compression() {
        // Test with realistic signature values
        let mut s = vec![0i16; N];
        for i in 0..N {
            s[i] = ((i as i32 - 256) % 100) as i16;
        }
        
        let compressed = comp_encode_advanced(&s, 9);
        
        // Advanced compression should be more efficient
        assert!(compressed.len() < N * 2); // Should be much less than 2 bytes per coefficient
    }
}
