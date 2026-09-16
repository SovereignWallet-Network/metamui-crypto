/// Hex encoding/decoding utilities
///
/// Native implementation of hexadecimal encoding and decoding.
/// Supports optional "0x" prefix and case-insensitive decoding.

use crate::error::{CryptoUtilError, Result, EncodingError};

#[cfg(feature = "std")]
use std::vec::Vec;

/// Hex characters lookup table
const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_CHARS_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Encode bytes to lowercase hex string
pub fn encode(data: &[u8]) -> String {
    encode_lower(data)
}

/// Encode bytes to lowercase hex string
pub fn encode_lower(data: &[u8]) -> String {
    // Use checked arithmetic to prevent overflow
    let capacity = data.len().saturating_mul(2);
    
    // Sanity check to prevent huge allocations
    if capacity > 1_000_000_000 {
        panic!("Data too large to encode");
    }
    
    let mut hex = String::with_capacity(capacity);
    for byte in data {
        hex.push(HEX_CHARS_LOWER[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS_LOWER[(byte & 0x0f) as usize] as char);
    }
    hex
}

/// Encode bytes to uppercase hex string
pub fn encode_upper(data: &[u8]) -> String {
    // Use checked arithmetic to prevent overflow
    let capacity = data.len().saturating_mul(2);
    
    // Sanity check to prevent huge allocations
    if capacity > 1_000_000_000 {
        panic!("Data too large to encode");
    }
    
    let mut hex = String::with_capacity(capacity);
    for byte in data {
        hex.push(HEX_CHARS_UPPER[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS_UPPER[(byte & 0x0f) as usize] as char);
    }
    hex
}

/// Encode bytes to hex string with "0x" prefix
pub fn encode_prefixed(data: &[u8]) -> String {
    format!("0x{}", encode_lower(data))
}

/// Decode hex string to bytes
/// Accepts both uppercase and lowercase, with or without "0x" prefix
pub fn decode(hex_str: &str) -> Result<Vec<u8>> {
    let hex_str = hex_str.trim();
    
    // Remove "0x" or "0X" prefix if present
    let hex_str = if hex_str.len() >= 2 {
        match &hex_str[..2] {
            "0x" | "0X" => &hex_str[2..],
            _ => hex_str,
        }
    } else {
        hex_str
    };
    
    // Check for empty string
    if hex_str.is_empty() {
        return Ok(Vec::new());
    }
    
    // Check for odd length
    if hex_str.len() % 2 != 0 {
        return Err(CryptoUtilError::InvalidEncoding(EncodingError::InvalidHex));
    }
    
    // Use checked arithmetic to prevent overflow
    let capacity = hex_str.len()
        .checked_div(2)
        .ok_or(CryptoUtilError::InvalidEncoding(EncodingError::DataTooLarge))?;
    
    // Sanity check to prevent huge allocations
    if capacity > 1_000_000_000 {
        return Err(CryptoUtilError::InvalidEncoding(EncodingError::DataTooLarge));
    }
    
    let mut bytes = Vec::with_capacity(capacity);
    
    for chunk in hex_str.as_bytes().chunks(2) {
        let high = decode_hex_char(chunk[0])?;
        let low = decode_hex_char(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    
    Ok(bytes)
}

/// Decode a single hex character to its value
fn decode_hex_char(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(CryptoUtilError::InvalidEncoding(EncodingError::InvalidHex)),
    }
}

/// Validate if a string is valid hexadecimal
pub fn is_hex(s: &str) -> bool {
    decode(s).is_ok()
}

/// Normalize a hex string (remove prefix, convert to lowercase)
pub fn normalize(hex_str: &str) -> Result<String> {
    let bytes = decode(hex_str)?;
    Ok(encode_lower(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"\x00"), "00");
        assert_eq!(encode(b"\xff"), "ff");
        assert_eq!(encode(b"Hello"), "48656c6c6f");
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn test_encode_upper() {
        assert_eq!(encode_upper(b"Hello"), "48656C6C6F");
        assert_eq!(encode_upper(&[0xde, 0xad, 0xbe, 0xef]), "DEADBEEF");
    }

    #[test]
    fn test_encode_prefixed() {
        assert_eq!(encode_prefixed(b""), "0x");
        assert_eq!(encode_prefixed(b"\xff"), "0xff");
        assert_eq!(encode_prefixed(&[0xde, 0xad, 0xbe, 0xef]), "0xdeadbeef");
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode("00").unwrap(), vec![0x00]);
        assert_eq!(decode("ff").unwrap(), vec![0xff]);
        assert_eq!(decode("FF").unwrap(), vec![0xff]);
        assert_eq!(decode("48656c6c6f").unwrap(), b"Hello");
        assert_eq!(decode("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode("0xdeadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode("0XDEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_errors() {
        assert!(decode("0").is_err()); // Odd length
        assert!(decode("0g").is_err()); // Invalid character
        assert!(decode("zz").is_err()); // Invalid characters
    }

    #[test]
    fn test_is_hex() {
        assert!(is_hex(""));
        assert!(is_hex("00"));
        assert!(is_hex("deadbeef"));
        assert!(is_hex("DEADBEEF"));
        assert!(is_hex("0xdeadbeef"));
        assert!(!is_hex("0"));
        assert!(!is_hex("xyz"));
    }

    #[test]
    fn test_normalize() {
        assert_eq!(normalize("DEADBEEF").unwrap(), "deadbeef");
        assert_eq!(normalize("0xDEADBEEF").unwrap(), "deadbeef");
        assert_eq!(normalize("0XDEADBEEF").unwrap(), "deadbeef");
    }
}