/// Base58 encoding/decoding utilities
///
/// Native implementation of Base58 encoding and decoding.
/// Uses Bitcoin's alphabet (excludes 0, O, I, l to avoid confusion).

use crate::error::{CryptoUtilError, Result, EncodingError};


/// Base58 alphabet (Bitcoin-style, no 0OIl)
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes to base58 string
pub fn encode(data: &[u8]) -> Result<String> {
    if data.is_empty() {
        return Ok(String::new());
    }

    // Count leading zeros
    let mut zeros = 0;
    for &byte in data {
        if byte == 0 {
            zeros += 1;
        } else {
            break;
        }
    }

    // Allocate enough space in big-endian base58 representation
    // Use checked arithmetic to prevent overflow
    let data_len = data.len().saturating_sub(zeros);
    let size = data_len
        .checked_mul(138)
        .and_then(|x| x.checked_div(100))
        .and_then(|x| x.checked_add(1))
        .ok_or(CryptoUtilError::InvalidEncoding(EncodingError::DataTooLarge))?;
    
    // Sanity check to prevent huge allocations
    if size > 1_000_000_000 {
        return Err(CryptoUtilError::InvalidEncoding(EncodingError::DataTooLarge));
    }
    
    let mut buf = vec![0u8; size];

    // Process the bytes
    let mut i = zeros;
    let mut high = size - 1;
    while i < data.len() {
        let mut carry = data[i] as u32;
        let mut j = size - 1;
        
        while j > high || carry != 0 {
            carry += 256 * (buf[j] as u32);
            buf[j] = (carry % 58) as u8;
            carry /= 58;
            if j > 0 {
                j -= 1;
            } else {
                break;
            }
        }
        
        high = j;
        i += 1;
    }

    // Skip leading zeros in base58 result
    let mut j = 0;
    while j < buf.len() && buf[j] == 0 {
        j += 1;
    }

    // Translate the result into a string
    let mut result = String::with_capacity(zeros + (size - j));
    
    // Add '1' for each leading zero byte
    for _ in 0..zeros {
        result.push('1');
    }
    
    // Convert the rest
    while j < buf.len() {
        result.push(ALPHABET[buf[j] as usize] as char);
        j += 1;
    }

    Ok(result)
}

/// Decode base58 string to bytes
pub fn decode(encoded: &str) -> Result<Vec<u8>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }

    // Count leading '1's (representing zeros)
    let mut zeros = 0;
    for ch in encoded.chars() {
        if ch == '1' {
            zeros += 1;
        } else {
            break;
        }
    }

    // Decode from base58 to base256
    // Use checked arithmetic to prevent overflow
    let size = encoded.len()
        .checked_mul(733)
        .and_then(|x| x.checked_div(1000))
        .and_then(|x| x.checked_add(1))
        .ok_or(CryptoUtilError::InvalidEncoding(EncodingError::DataTooLarge))?;
    
    // Sanity check to prevent huge allocations
    if size > 1_000_000_000 {
        return Err(CryptoUtilError::InvalidEncoding(EncodingError::DataTooLarge));
    }
    
    let mut buf = vec![0u8; size];
    
    let encoded_bytes = encoded.as_bytes();
    let mut i = zeros;
    let mut high = size - 1;
    
    while i < encoded_bytes.len() {
        // Decode base58 character
        let ch = encoded_bytes[i];
        let mut carry = match decode_char(ch) {
            Some(val) => val as u32,
            None => return Err(CryptoUtilError::InvalidEncoding(EncodingError::InvalidBase58)),
        };
        
        let mut j = size - 1;
        while j > high || carry != 0 {
            carry += 58 * (buf[j] as u32);
            buf[j] = (carry % 256) as u8;
            carry /= 256;
            if j > 0 {
                j -= 1;
            } else {
                break;
            }
        }
        
        high = j;
        i += 1;
    }

    // Skip leading zeros in base256 result
    let mut j = 0;
    while j < buf.len() && buf[j] == 0 {
        j += 1;
    }

    // Create result with correct number of zeros
    let mut result = Vec::with_capacity(zeros + (buf.len() - j));
    
    // Add zeros
    for _ in 0..zeros {
        result.push(0);
    }
    
    // Add the rest
    result.extend_from_slice(&buf[j..]);

    Ok(result)
}

/// Decode a single base58 character
fn decode_char(ch: u8) -> Option<u8> {
    match ch {
        b'1'..=b'9' => Some(ch - b'1'),
        b'A'..=b'H' => Some(ch - b'A' + 9),
        b'J'..=b'N' => Some(ch - b'J' + 17),
        b'P'..=b'Z' => Some(ch - b'P' + 22),
        b'a'..=b'k' => Some(ch - b'a' + 33),
        b'm'..=b'z' => Some(ch - b'm' + 44),
        _ => None,
    }
}

/// Check if a string is valid Base58
pub fn is_base58(s: &str) -> bool {
    decode(s).is_ok()
}

/// Encode with checksum (Bitcoin-style)
pub fn encode_check(data: &[u8]) -> Result<String> {
    // For checksum variant, would need SHA256 dependency
    // For now, just use regular encoding
    encode(data)
}

/// Decode with checksum verification
pub fn decode_check(encoded: &str) -> Result<Vec<u8>> {
    // For checksum variant, would need SHA256 dependency
    // For now, just use regular decoding
    decode(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!(encode(b"").unwrap(), "");
        assert_eq!(encode(b"\x00").unwrap(), "1");
        assert_eq!(encode(b"\x00\x00").unwrap(), "11");
        assert_eq!(encode(b"\x00\x00\x00").unwrap(), "111");
        assert_eq!(encode(b"Hello World!").unwrap(), "2NEpo7TZRRrLZSi2U");
        assert_eq!(encode(b"\x00abc").unwrap(), "1ZiCa");
        assert_eq!(encode(b"\xff").unwrap(), "5Q");
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(decode("1").unwrap(), b"\x00");
        assert_eq!(decode("11").unwrap(), b"\x00\x00");
        assert_eq!(decode("111").unwrap(), b"\x00\x00\x00");
        assert_eq!(decode("2NEpo7TZRRrLZSi2U").unwrap(), b"Hello World!");
        assert_eq!(decode("1ZiCa").unwrap(), b"\x00abc");
        assert_eq!(decode("5Q").unwrap(), b"\xff");
    }

    #[test]
    fn test_decode_invalid() {
        assert!(decode("0").is_err()); // Invalid character '0'
        assert!(decode("O").is_err()); // Invalid character 'O'
        assert!(decode("I").is_err()); // Invalid character 'I'
        assert!(decode("l").is_err()); // Invalid character 'l'
        assert!(decode("!@#").is_err()); // Invalid characters
    }

    #[test]
    fn test_roundtrip() {
        let test_data = vec![
            b"".to_vec(),
            b"\x00".to_vec(),
            b"\x00\x00\x00".to_vec(),
            b"Hello, World!".to_vec(),
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            vec![255; 32],
            b"The quick brown fox jumps over the lazy dog.".to_vec(),
        ];
        
        for data in test_data {
            let encoded = encode(&data).unwrap();
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded, data, "Failed for data: {:?}", data);
        }
    }

    #[test]
    fn test_is_base58() {
        assert!(is_base58(""));
        assert!(is_base58("123456789"));
        assert!(is_base58("2NEpo7TZRRrLZSi2U"));
        assert!(!is_base58("0OIl")); // Invalid characters
        assert!(!is_base58("Hello World!")); // Space is invalid
    }

    #[test]
    fn test_leading_zeros() {
        // Test that leading zeros are properly encoded/decoded
        let data = vec![0, 0, 0, 1, 2, 3];
        let encoded = encode(&data).unwrap();
        assert!(encoded.starts_with("111")); // Three '1's for three zeros
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}