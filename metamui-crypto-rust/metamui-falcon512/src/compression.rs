//! Signature compression for Falcon512
//! Implements Huffman-like encoding to reduce signature size

use crate::constants::N;
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;

/// Maximum signature size in bytes
const MAX_SIG_SIZE: usize = 666;
const SALT_LEN: usize = 40;
const HEADER_LEN: usize = 1;

/// Compress a signature polynomial using variable-length encoding
pub fn compress_signature(s0: &[i16], s1: &[i16], salt: &[u8; SALT_LEN]) -> Result<Vec<u8>> {
    let mut compressed = Vec::with_capacity(MAX_SIG_SIZE);
    
    // Header byte (0x30 + logn where logn = 9 for n=512)
    compressed.push(0x39);
    
    // Add salt
    compressed.extend_from_slice(salt);
    
    // Compress s1 (s0 is reconstructed from s1 and the public key during verification)
    compress_poly(s1, &mut compressed)?;
    
    // Check size limit
    if compressed.len() > MAX_SIG_SIZE {
        return Err(Falcon512Error::SignatureTooLarge);
    }
    
    Ok(compressed)
}

/// Compress a polynomial using variable-length encoding
fn compress_poly(poly: &[i16], output: &mut Vec<u8>) -> Result<()> {
    let mut bits = BitWriter::new(output);
    
    for &coeff in poly {
        // Encode coefficient using variable-length code
        encode_coefficient(coeff, &mut bits)?;
    }
    
    // Flush remaining bits
    bits.flush();
    
    Ok(())
}

/// Encode a single coefficient
fn encode_coefficient(coeff: i16, bits: &mut BitWriter) -> Result<()> {
    // Convert to signed magnitude representation
    let sign = coeff < 0;
    let magnitude = coeff.abs() as u16;
    
    // Simple encoding: 1 bit for zero/non-zero, then sign bit, then 12-bit magnitude
    if magnitude == 0 {
        bits.write_bit(false);  // 0 = zero value
    } else {
        bits.write_bit(true);   // 1 = non-zero value
        bits.write_bit(sign);   // Sign bit
        bits.write_bits(magnitude, 12);  // 12-bit magnitude
    }
    
    Ok(())
}

/// Decompress a signature
pub fn decompress_signature(compressed: &[u8]) -> Result<(Vec<i16>, [u8; SALT_LEN])> {
    if compressed.len() < HEADER_LEN + SALT_LEN {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    // Check header
    if compressed[0] != 0x39 {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    // Extract salt
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&compressed[1..HEADER_LEN + SALT_LEN]);
    
    // Decompress s1
    let s1 = decompress_poly(&compressed[HEADER_LEN + SALT_LEN..], N)?;
    
    Ok((s1, salt))
}

/// Decompress a polynomial
fn decompress_poly(data: &[u8], n: usize) -> Result<Vec<i16>> {
    let mut poly = Vec::with_capacity(n);
    let mut bits = BitReader::new(data);
    
    while poly.len() < n {
        let coeff = decode_coefficient(&mut bits)?;
        poly.push(coeff);
    }
    
    Ok(poly)
}

/// Decode a single coefficient
fn decode_coefficient(bits: &mut BitReader) -> Result<i16> {
    // Read first bit to determine if zero
    if !bits.read_bit()? {
        return Ok(0);
    }
    
    // Non-zero value: read sign and magnitude
    let sign = bits.read_bit()?;
    let magnitude = bits.read_bits(12)? as u16;
    
    Ok(if sign { -(magnitude as i16) } else { magnitude as i16 })
}

/// Bit writer for compression
struct BitWriter<'a> {
    output: &'a mut Vec<u8>,
    current_byte: u8,
    bit_position: u8,
}

impl<'a> BitWriter<'a> {
    fn new(output: &'a mut Vec<u8>) -> Self {
        BitWriter {
            output,
            current_byte: 0,
            bit_position: 0,
        }
    }
    
    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= 1 << (7 - self.bit_position);
        }
        self.bit_position += 1;
        
        if self.bit_position == 8 {
            self.output.push(self.current_byte);
            self.current_byte = 0;
            self.bit_position = 0;
        }
    }
    
    fn write_bits(&mut self, value: u16, num_bits: u8) {
        for i in (0..num_bits).rev() {
            self.write_bit((value >> i) & 1 == 1);
        }
    }
    
    fn flush(&mut self) {
        if self.bit_position > 0 {
            self.output.push(self.current_byte);
        }
    }
}

/// Bit reader for decompression
struct BitReader<'a> {
    data: &'a [u8],
    byte_position: usize,
    bit_position: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            byte_position: 0,
            bit_position: 0,
        }
    }
    
    fn read_bit(&mut self) -> Result<bool> {
        if self.byte_position >= self.data.len() {
            return Err(Falcon512Error::InvalidSignature);
        }
        
        let bit = (self.data[self.byte_position] >> (7 - self.bit_position)) & 1 == 1;
        self.bit_position += 1;
        
        if self.bit_position == 8 {
            self.byte_position += 1;
            self.bit_position = 0;
        }
        
        Ok(bit)
    }
    
    fn read_bits(&mut self, num_bits: u8) -> Result<u16> {
        let mut value = 0u16;
        for _ in 0..num_bits {
            value = (value << 1) | (self.read_bit()? as u16);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compress_decompress() {
        let s1 = vec![0i16, 1, -1, 5, -10, 100, -200, 0, 3, -3];
        let salt = [42u8; SALT_LEN];
        
        // Pad s1 to full size
        let mut s1_full = s1.clone();
        s1_full.resize(N, 0);
        
        // Compress
        let compressed = compress_signature(&s1_full, &s1_full, &salt)
            .expect("Compression failed");
        
        // Check size is reasonable
        assert!(compressed.len() < MAX_SIG_SIZE);
        
        // Decompress
        let (decompressed, salt_out) = decompress_signature(&compressed)
            .expect("Decompression failed");
        
        // Check salt
        assert_eq!(salt, salt_out);
        
        // Check first few coefficients match
        for i in 0..10 {
            assert_eq!(s1_full[i], decompressed[i], "Coefficient {} mismatch", i);
        }
    }
    
    #[test]
    fn test_bit_writer_reader() {
        let mut output = Vec::new();
        let mut writer = BitWriter::new(&mut output);
        
        writer.write_bit(true);
        writer.write_bit(false);
        writer.write_bits(0b1010, 4);
        writer.write_bit(true);
        writer.write_bit(true);
        writer.flush();
        
        let mut reader = BitReader::new(&output);
        assert_eq!(reader.read_bit().unwrap(), true);
        assert_eq!(reader.read_bit().unwrap(), false);
        assert_eq!(reader.read_bits(4).unwrap(), 0b1010);
        assert_eq!(reader.read_bit().unwrap(), true);
        assert_eq!(reader.read_bit().unwrap(), true);
    }
}
