/// Base64 encoding/decoding utilities
///
/// Native implementation of Base64 encoding and decoding.
/// Supports both standard and URL-safe variants.

use crate::error::{CryptoUtilError, Result, EncodingError};


/// Standard Base64 alphabet
const STANDARD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// URL-safe Base64 alphabet (RFC 4648)
const URL_SAFE_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Padding character
const PADDING: u8 = b'=';

/// Encode bytes to standard Base64
pub fn encode(data: &[u8]) -> String {
    encode_with_alphabet(data, STANDARD_ALPHABET, true)
}

/// Encode bytes to standard Base64 without padding
pub fn encode_no_pad(data: &[u8]) -> String {
    encode_with_alphabet(data, STANDARD_ALPHABET, false)
}

/// Encode bytes to URL-safe Base64
pub fn encode_url_safe(data: &[u8]) -> String {
    encode_with_alphabet(data, URL_SAFE_ALPHABET, true)
}

/// Encode bytes to URL-safe Base64 without padding
pub fn encode_url_safe_no_pad(data: &[u8]) -> String {
    encode_with_alphabet(data, URL_SAFE_ALPHABET, false)
}

/// Internal encoding function
fn encode_with_alphabet(data: &[u8], alphabet: &[u8; 64], use_padding: bool) -> String {
    if data.is_empty() {
        return String::new();
    }

    // Use checked arithmetic to prevent overflow
    let capacity = data.len()
        .checked_add(2)
        .and_then(|x| x.checked_div(3))
        .and_then(|x| x.checked_mul(4))
        .unwrap_or(0);
    
    // Sanity check to prevent huge allocations
    if capacity > 1_000_000_000 {
        // For now, panic on overflow in encoding since we return String
        // In a future version, we should change the API to return Result<String>
        panic!("Data too large to encode");
    }

    let mut result = String::with_capacity(capacity);
    let chunks = data.chunks(3);
    
    for chunk in chunks {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);
        
        // Convert 3 bytes to 4 base64 characters
        let b1 = buf[0] >> 2;
        let b2 = ((buf[0] & 0x03) << 4) | (buf[1] >> 4);
        let b3 = ((buf[1] & 0x0f) << 2) | (buf[2] >> 6);
        let b4 = buf[2] & 0x3f;
        
        result.push(alphabet[b1 as usize] as char);
        result.push(alphabet[b2 as usize] as char);
        
        if chunk.len() > 1 {
            result.push(alphabet[b3 as usize] as char);
        } else if use_padding {
            result.push(PADDING as char);
        }
        
        if chunk.len() > 2 {
            result.push(alphabet[b4 as usize] as char);
        } else if use_padding {
            result.push(PADDING as char);
        }
    }
    
    result
}

/// Decode standard Base64 to bytes
pub fn decode(encoded: &str) -> Result<Vec<u8>> {
    decode_with_alphabet(encoded, STANDARD_ALPHABET)
}

/// Decode URL-safe Base64 to bytes
pub fn decode_url_safe(encoded: &str) -> Result<Vec<u8>> {
    decode_with_alphabet(encoded, URL_SAFE_ALPHABET)
}

/// Create decode table from alphabet
fn create_decode_table(alphabet: &[u8; 64]) -> [u8; 256] {
    let mut table = [0xff; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    table
}

/// Internal decoding function
fn decode_with_alphabet(encoded: &str, alphabet: &[u8; 64]) -> Result<Vec<u8>> {
    let encoded = encoded.trim();
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    
    // Check for only padding
    if encoded.chars().all(|c| c == '=') {
        return Err(CryptoUtilError::InvalidEncoding(EncodingError::InvalidBase64));
    }
    
    let decode_table = create_decode_table(alphabet);
    
    // Use checked arithmetic to prevent overflow
    let capacity = encoded.len()
        .checked_mul(3)
        .and_then(|x| x.checked_div(4))
        .ok_or(CryptoUtilError::InvalidEncoding(EncodingError::DataTooLarge))?;
    
    // Sanity check to prevent huge allocations
    if capacity > 1_000_000_000 {
        return Err(CryptoUtilError::InvalidEncoding(EncodingError::DataTooLarge));
    }
    
    let mut result = Vec::with_capacity(capacity);
    
    let encoded_bytes = encoded.as_bytes();
    let mut padding_count = 0;
    
    // Count padding
    for &b in encoded_bytes.iter().rev() {
        if b == PADDING {
            padding_count += 1;
        } else {
            break;
        }
    }
    
    // Validate padding count
    if padding_count > 2 {
        return Err(CryptoUtilError::InvalidEncoding(EncodingError::InvalidBase64));
    }
    
    // Process in groups of 4
    let clean_len = encoded_bytes.len() - padding_count;
    
    // If we have padding, ensure total length is multiple of 4
    if padding_count > 0 && encoded_bytes.len() % 4 != 0 {
        return Err(CryptoUtilError::InvalidEncoding(EncodingError::InvalidBase64));
    }
    
    // Handle unpadded input
    let effective_len = if padding_count == 0 && clean_len % 4 != 0 {
        // Calculate padding needed
        let remainder = clean_len % 4;
        if remainder == 1 {
            return Err(CryptoUtilError::InvalidEncoding(EncodingError::InvalidBase64));
        }
        clean_len
    } else {
        clean_len
    };
    
    let mut i = 0;
    while i < effective_len {
        let remaining = effective_len - i;
        let chunk_len = remaining.min(4);
        
        if chunk_len < 2 {
            return Err(CryptoUtilError::InvalidEncoding(EncodingError::InvalidBase64));
        }
        
        // Decode characters
        let mut vals = [0u8; 4];
        for j in 0..chunk_len {
            let val = decode_table[encoded_bytes[i + j] as usize];
            if val == 0xff {
                return Err(CryptoUtilError::InvalidEncoding(EncodingError::InvalidBase64));
            }
            vals[j] = val;
        }
        
        // Convert base64 characters to bytes
        result.push((vals[0] << 2) | (vals[1] >> 4));
        
        if chunk_len > 2 {
            result.push((vals[1] << 4) | (vals[2] >> 2));
        }
        
        if chunk_len > 3 {
            result.push((vals[2] << 6) | vals[3]);
        }
        
        i += chunk_len;
    }
    
    Ok(result)
}

/// Check if a string is valid Base64
pub fn is_base64(s: &str) -> bool {
    decode(s).is_ok()
}

/// Check if a string is valid URL-safe Base64
pub fn is_base64_url_safe(s: &str) -> bool {
    decode_url_safe(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_encode_no_pad() {
        assert_eq!(encode_no_pad(b""), "");
        assert_eq!(encode_no_pad(b"f"), "Zg");
        assert_eq!(encode_no_pad(b"fo"), "Zm8");
        assert_eq!(encode_no_pad(b"foo"), "Zm9v");
        assert_eq!(encode_no_pad(b"foob"), "Zm9vYg");
        assert_eq!(encode_no_pad(b"fooba"), "Zm9vYmE");
        assert_eq!(encode_no_pad(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_encode_url_safe() {
        // Test with data that produces '+' and '/' in standard encoding
        // These bytes encode to "//" in standard base64
        let data1 = &[0xff, 0xff];
        let standard1 = encode(data1);
        let url_safe1 = encode_url_safe(data1);
        assert_eq!(standard1, "//8=");
        assert_eq!(url_safe1, "__8=");
        
        // These bytes encode to "++" in standard base64  
        let data2 = &[0xfb, 0xef];
        let standard2 = encode(data2);
        let url_safe2 = encode_url_safe(data2);
        assert_eq!(standard2, "++8=");
        assert_eq!(url_safe2, "--8=");
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(decode("Zg==").unwrap(), b"f");
        assert_eq!(decode("Zm8=").unwrap(), b"fo");
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
        assert_eq!(decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn test_decode_no_padding() {
        assert_eq!(decode("Zg").unwrap(), b"f");
        assert_eq!(decode("Zm8").unwrap(), b"fo");
        assert_eq!(decode("Zm9vYg").unwrap(), b"foob");
        assert_eq!(decode("Zm9vYmE").unwrap(), b"fooba");
    }

    #[test]
    fn test_decode_errors() {
        assert!(decode("Z").is_err()); // Too short
        assert!(decode("====").is_err()); // Only padding
        assert!(decode("Zg=").is_err()); // Wrong padding (should be Zg==)
        assert!(decode("Z???").is_err()); // Invalid characters
        assert!(decode("Zg===").is_err()); // Too much padding
    }

    #[test]
    fn test_roundtrip() {
        let test_data = vec![
            b"".to_vec(),
            b"Hello, World!".to_vec(),
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            vec![255; 256],
        ];
        
        for data in test_data {
            // Standard
            let encoded = encode(&data);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded, data);
            
            // URL-safe
            let encoded = encode_url_safe(&data);
            let decoded = decode_url_safe(&encoded).unwrap();
            assert_eq!(decoded, data);
        }
    }

    #[test]
    fn test_is_base64() {
        assert!(is_base64(""));
        assert!(is_base64("Zm9vYmFy"));
        assert!(is_base64("Zg=="));
        assert!(!is_base64("Zg="));
        assert!(!is_base64("????"));
    }
}