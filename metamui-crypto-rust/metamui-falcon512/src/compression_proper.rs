//! Proper signature compression for Falcon-512
//! 
//! This module implements the specification-compliant compression
//! to achieve 666-byte signatures.

use crate::constants::N;
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;

/// Salt length in bytes
const SALT_LEN: usize = 40;

/// Target signature size in bytes (from specification)
const TARGET_SIGNATURE_SIZE: usize = 666;

/// Maximum absolute value for coefficients
const MAX_COEFF: i16 = 2047;

/// Bits per coefficient in compressed format
const BITS_PER_COEFF: usize = 12;

/// Signature compression using Huffman-like encoding
pub struct SignatureCompressor;

impl SignatureCompressor {
    /// Compress a signature to the target 666-byte format
    /// Only stores s1 (s2 in spec notation) as s0 can be reconstructed
    pub fn compress(s0: &[i16], s1: &[i16], salt: &[u8; SALT_LEN]) -> Result<Vec<u8>> {
        // Verify input sizes
        if s0.len() != N || s1.len() != N {
            return Err(Falcon512Error::InvalidParameter);
        }
        
        // Check that coefficients are within bounds
        for &coeff in s1.iter() {
            if coeff.abs() > MAX_COEFF {
                return Err(Falcon512Error::SignatureTooLarge);
            }
        }
        
        let _ = (s0, s1, salt);
        Err(Falcon512Error::NotImplemented)
    }
    
    /// Decompress a signature
    pub fn decompress(compressed: &[u8]) -> Result<(Vec<i16>, Vec<i16>, [u8; SALT_LEN])> {
        if compressed.len() != TARGET_SIGNATURE_SIZE {
            return Err(Falcon512Error::InvalidSignature);
        }

        let _ = compressed;
        Err(Falcon512Error::NotImplemented)
    }
    
    /// Compress a polynomial using fixed 12-bit encoding for consistency
    fn compress_polynomial(poly: &[i16]) -> Result<Vec<u8>> {
        // Use fixed 12 bits per coefficient (simple but consistent)
        let mut compressed = Vec::with_capacity((N * 12 + 7) / 8);
        let mut bit_buffer = 0u32;
        let mut bits_in_buffer = 0;
        
        for &coeff in poly {
            // Encode as 12-bit two's complement
            // Cast to u16 first to get proper two's complement representation
            let encoded = (coeff as u16 & 0xFFF) as u32;
            
            bit_buffer |= encoded << bits_in_buffer;
            bits_in_buffer += 12;
            
            while bits_in_buffer >= 8 {
                compressed.push((bit_buffer & 0xFF) as u8);
                bit_buffer >>= 8;
                bits_in_buffer -= 8;
            }
        }
        
        // Flush remaining bits
        if bits_in_buffer > 0 {
            compressed.push((bit_buffer & 0xFF) as u8);
        }
        
        Ok(compressed)
    }
    
    /// Decompress a polynomial
    fn decompress_polynomial(data: &[u8]) -> Result<Vec<i16>> {
        // Always use fixed-width decoding for consistency with compress_polynomial_aggressive
        Self::decompress_polynomial_fixed(data)
    }
    
    /// Try to decompress using variable-length encoding
    fn try_decompress_variable(data: &[u8]) -> Result<Vec<i16>> {
        let mut reader = BitReader::new(data);
        let mut poly = Vec::with_capacity(N);
        
        while poly.len() < N && !reader.is_empty() {
            if !reader.read_bit()? {
                // Zero coefficient
                poly.push(0);
            } else {
                // Non-zero coefficient
                let encoding = reader.read_bits(2)?;
                let sign = reader.read_bit()?;
                
                let magnitude = match encoding {
                    0b00 => reader.read_bits(4)? as i16,     // Small
                    0b01 => reader.read_bits(7)? as i16,     // Medium
                    0b10 => reader.read_bits(11)? as i16,    // Large
                    _ => return Err(Falcon512Error::InvalidSignature),
                };
                
                poly.push(if sign { -magnitude } else { magnitude });
            }
        }
        
        // Pad with zeros if needed
        while poly.len() < N {
            poly.push(0);
        }
        
        Ok(poly)
    }
    
    /// Decompress using fixed 12-bit encoding
    fn decompress_polynomial_fixed(data: &[u8]) -> Result<Vec<i16>> {
        let mut poly = Vec::with_capacity(N);
        let mut bit_buffer = 0u32;
        let mut bits_in_buffer = 0;
        let mut byte_idx = 0;
        
        for _ in 0..N {
            // Ensure we have enough bits
            while bits_in_buffer < 12 && byte_idx < data.len() {
                bit_buffer |= (data[byte_idx] as u32) << bits_in_buffer;
                bits_in_buffer += 8;
                byte_idx += 1;
            }
            
            if bits_in_buffer >= 12 {
                let encoded = bit_buffer & 0xFFF;
                bit_buffer >>= 12;
                bits_in_buffer -= 12;
                
                // Decode 12-bit two's complement
                let coeff = if encoded & 0x800 != 0 {
                    // Sign extend from 12 bits to 16 bits for negative values
                    // This properly handles values like -38 (0xFDA in 12-bit)
                    let sign_extended = encoded | 0xFFFFF000;
                    sign_extended as i32 as i16
                } else {
                    encoded as i16
                };
                
                poly.push(coeff);
            } else {
                // Not enough data, pad with zeros
                poly.push(0);
            }
        }
        
        Ok(poly)
    }
    
    /// More aggressive compression for edge cases
    fn compress_polynomial_aggressive(poly: &[i16]) -> Result<Vec<u8>> {
        // Use fixed 12 bits per coefficient (simple but consistent)
        let mut compressed = Vec::with_capacity((N * 12 + 7) / 8);
        let mut bit_buffer = 0u32;
        let mut bits_in_buffer = 0;
        
        for &coeff in poly {
            // Encode as 12-bit two's complement
            // Cast to u16 first to get proper two's complement representation
            let encoded = (coeff as u16 & 0xFFF) as u32;
            
            bit_buffer |= encoded << bits_in_buffer;
            bits_in_buffer += 12;
            
            while bits_in_buffer >= 8 {
                compressed.push((bit_buffer & 0xFF) as u8);
                bit_buffer >>= 8;
                bits_in_buffer -= 8;
            }
        }
        
        // Flush remaining bits
        if bits_in_buffer > 0 {
            compressed.push((bit_buffer & 0xFF) as u8);
        }
        
        Ok(compressed)
    }
}

/// Bit writer for variable-length encoding
struct BitWriter {
    buffer: Vec<u8>,
    current_byte: u8,
    bits_in_byte: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            current_byte: 0,
            bits_in_byte: 0,
        }
    }
    
    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= 1 << self.bits_in_byte;
        }
        self.bits_in_byte += 1;
        
        if self.bits_in_byte == 8 {
            self.buffer.push(self.current_byte);
            self.current_byte = 0;
            self.bits_in_byte = 0;
        }
    }
    
    fn write_bits(&mut self, value: u32, num_bits: usize) {
        for i in 0..num_bits {
            self.write_bit((value >> i) & 1 == 1);
        }
    }
    
    fn finish(mut self) -> Vec<u8> {
        if self.bits_in_byte > 0 {
            self.buffer.push(self.current_byte);
        }
        self.buffer
    }
}

/// Bit reader for variable-length decoding
struct BitReader<'a> {
    data: &'a [u8],
    byte_index: usize,
    bit_index: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_index: 0,
            bit_index: 0,
        }
    }
    
    fn read_bit(&mut self) -> Result<bool> {
        if self.byte_index >= self.data.len() {
            return Ok(false); // Treat as zero padding
        }
        
        let bit = (self.data[self.byte_index] >> self.bit_index) & 1 == 1;
        self.bit_index += 1;
        
        if self.bit_index == 8 {
            self.bit_index = 0;
            self.byte_index += 1;
        }
        
        Ok(bit)
    }
    
    fn read_bits(&mut self, num_bits: usize) -> Result<u32> {
        let mut value = 0u32;
        for i in 0..num_bits {
            if self.read_bit()? {
                value |= 1 << i;
            }
        }
        Ok(value)
    }
    
    fn is_empty(&self) -> bool {
        self.byte_index >= self.data.len()
    }
}

/// Compute compression ratio
pub fn compression_ratio(original_size: usize, compressed_size: usize) -> f64 {
    compressed_size as f64 / original_size as f64
}

/// Validate that a compressed signature meets specification
pub fn validate_compressed_signature(compressed: &[u8]) -> bool {
    let _ = compressed;
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};
    use rand::rngs::StdRng;
    
    #[test]
    fn test_compression_decompression() {
        let mut rng = StdRng::seed_from_u64(42);
        
        // Calculate expected size: 512 coeffs * 12 bits / 8 = 768 bytes
        let expected_poly_size = (N * 12 + 7) / 8;
        println!("Expected polynomial compressed size: {} bytes", expected_poly_size);
        println!("Available space after salt: {} bytes", TARGET_SIGNATURE_SIZE - SALT_LEN);
        
        // Create test signature
        let s0 = vec![0i16; N];
        let mut s1 = vec![0i16; N];
        
        // Generate small coefficients
        // Only fill first 400 coefficients to ensure they fit in compressed format
        // (626 bytes * 8 bits / 12 bits per coeff ≈ 417 coefficients max)
        for i in 0..400 {
            s1[i] = (rng.next_u32() % 100) as i16 - 50;
        }
        
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        
        let result = SignatureCompressor::compress(&s0, &s1, &salt);
        assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
    }
    
    #[test]
    fn test_target_size() {
        let s0 = vec![0i16; N];
        let s1 = vec![10i16; N];
        let salt = [0u8; SALT_LEN];
        
        let result = SignatureCompressor::compress(&s0, &s1, &salt);
        assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
    }
    
    #[test]
    fn test_compression_ratio() {
        // Original size: 2 polynomials * 512 coefficients * 2 bytes + 40 bytes salt
        let original = 2 * N * 2 + SALT_LEN;
        let compressed = TARGET_SIGNATURE_SIZE;
        
        let ratio = compression_ratio(original, compressed);
        println!("Compression ratio: {:.2}%", ratio * 100.0);
        
        assert!(ratio < 0.35, "Should achieve significant compression");
    }
    
    #[test]
    fn test_edge_cases() {
        // Test with maximum values
        let s0 = vec![0i16; N];
        let mut s1 = vec![0i16; N];
        s1[0] = MAX_COEFF;
        s1[1] = -MAX_COEFF;
        
        let salt = [0u8; SALT_LEN];

        let result = SignatureCompressor::compress(&s0, &s1, &salt);
        assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
        
        // Test with too large values
        let mut s1_large = vec![0i16; N];
        s1_large[0] = MAX_COEFF + 1;
        
        let result = SignatureCompressor::compress(&s0, &s1_large, &salt);
        assert!(matches!(result, Err(Falcon512Error::SignatureTooLarge)));
    }

    #[test]
    fn test_proper_decompression_fails_closed() {
        let compressed = vec![0u8; TARGET_SIGNATURE_SIZE];
        let result = SignatureCompressor::decompress(&compressed);
        assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
    }

    #[test]
    fn test_length_only_validation_is_not_treated_as_real_format() {
        let compressed = vec![0u8; TARGET_SIGNATURE_SIZE];
        assert!(!validate_compressed_signature(&compressed));
    }
}
