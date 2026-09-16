/// HKDF (HMAC-based Key Derivation Function) implementation
/// Based on RFC 5869
use metamui_security_utils::Zeroize;
use crate::mac::hmac::Hmac;
use metamui_sha2::sha512::hmac::HmacSha512;

#[cfg(feature = "std")]
use std::vec::Vec;

/// HKDF implementation with secure memory handling
pub struct Hkdf;

impl Hkdf {
    /// HKDF-SHA256: Extract-and-Expand in one step
    pub fn derive_sha256(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>, String> {
        if output_length == 0 {
            return Err("Output length must be greater than 0".to_string());
        }
        
        if output_length > 255 * 32 {
            return Err("Output length too large for SHA-256".to_string());
        }
        
        let prk = Self::extract_sha256(ikm, salt);
        let result = Self::expand_sha256(&prk, info, output_length)?;
        
        // Clear sensitive intermediate value
        let mut prk_mut = prk;
        prk_mut.zeroize();
        
        Ok(result)
    }
    
    /// HKDF-SHA256: Extract phase only
    pub fn extract_sha256(ikm: &[u8], salt: Option<&[u8]>) -> Vec<u8> {
        let salt = salt.unwrap_or(&[0u8; 32]); // Use zero salt if none provided
        Hmac::hmac_sha256_small(salt, ikm).to_vec()
    }
    
    /// HKDF-SHA256: Expand phase only
    pub fn expand_sha256(prk: &[u8], info: &[u8], output_length: usize) -> Result<Vec<u8>, String> {
        if output_length == 0 {
            return Err("Output length must be greater than 0".to_string());
        }
        
        if output_length > 255 * 32 {
            return Err("Output length too large for SHA-256".to_string());
        }
        
        if prk.len() != 32 {
            return Err("PRK must be 32 bytes for SHA-256".to_string());
        }
        
        let mut okm = Vec::with_capacity(output_length);
        let mut previous = Vec::new();
        let mut counter = 1u8;
        
        while okm.len() < output_length {
            let mut data = Vec::new();
            data.extend_from_slice(&previous);
            data.extend_from_slice(info);
            data.push(counter);
            
            let block = Hmac::hmac_sha256_small(prk, &data);
            previous = block.to_vec();
            
            let to_copy = (output_length - okm.len()).min(block.len());
            okm.extend_from_slice(&block[..to_copy]);

            if okm.len() < output_length {
                counter = counter.checked_add(1)
                    .ok_or("Counter overflow")?;
            }
        }

        // Clear sensitive intermediate value
        previous.zeroize();

        Ok(okm)
    }

    /// HKDF-SHA512: Extract-and-Expand in one step
    pub fn derive_sha512(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>, String> {
        if output_length == 0 {
            return Err("Output length must be greater than 0".to_string());
        }
        
        if output_length > 255 * 64 {
            return Err("Output length too large for SHA-512".to_string());
        }
        
        let prk = Self::extract_sha512(ikm, salt);
        let result = Self::expand_sha512(&prk, info, output_length)?;
        
        // Clear sensitive intermediate value
        let mut prk_mut = prk;
        prk_mut.zeroize();
        
        Ok(result)
    }
    
    /// HKDF-SHA512: Extract phase only
    pub fn extract_sha512(ikm: &[u8], salt: Option<&[u8]>) -> Vec<u8> {
        let salt = salt.unwrap_or(&[0u8; 64]); // Use zero salt if none provided
        
        let mut mac = HmacSha512::new_from_slice(salt)
            .expect("HMAC can take key of any size");
        mac.update(ikm);
        mac.finalize().into_bytes().to_vec()
    }
    
    /// HKDF-SHA512: Expand phase only
    pub fn expand_sha512(prk: &[u8], info: &[u8], output_length: usize) -> Result<Vec<u8>, String> {
        if output_length == 0 {
            return Err("Output length must be greater than 0".to_string());
        }
        
        if output_length > 255 * 64 {
            return Err("Output length too large for SHA-512".to_string());
        }
        
        if prk.len() != 64 {
            return Err("PRK must be 64 bytes for SHA-512".to_string());
        }
        
        let mut okm = Vec::with_capacity(output_length);
        let mut previous = Vec::new();
        let mut counter = 1u8;
        
        while okm.len() < output_length {
            let mut mac = HmacSha512::new_from_slice(prk)
                .map_err(|_| "Invalid PRK")?;
            mac.update(&previous);
            mac.update(info);
            mac.update(&[counter]);
            
            let block = mac.finalize().into_bytes();
            previous = block.to_vec();
            
            let to_copy = (output_length - okm.len()).min(block.len());
            okm.extend_from_slice(&block[..to_copy]);

            if okm.len() < output_length {
                counter = counter.checked_add(1)
                    .ok_or("Counter overflow")?;
            }
        }

        // Clear sensitive intermediate value
        previous.zeroize();

        Ok(okm)
    }
}

// Convenience functions
/// HKDF-SHA256 convenience function that performs both extract and expand
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt value
/// * `info` - Context and application specific information
/// * `output_length` - Desired length of output key material
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_length: usize,
) -> Result<Vec<u8>, String> {
    Hkdf::derive_sha256(ikm, salt, info, output_length)
}

/// HKDF-SHA256 extract phase only
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt value
pub fn hkdf_extract_sha256(ikm: &[u8], salt: Option<&[u8]>) -> Vec<u8> {
    Hkdf::extract_sha256(ikm, salt)
}

/// HKDF-SHA256 expand phase only
///
/// # Arguments
/// * `prk` - Pseudorandom key from extract phase
/// * `info` - Context and application specific information
/// * `output_length` - Desired length of output key material
pub fn hkdf_expand_sha256(prk: &[u8], info: &[u8], output_length: usize) -> Result<Vec<u8>, String> {
    Hkdf::expand_sha256(prk, info, output_length)
}

/// HKDF-SHA512 convenience function that performs both extract and expand
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt value
/// * `info` - Context and application specific information
/// * `output_length` - Desired length of output key material
pub fn hkdf_sha512(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_length: usize,
) -> Result<Vec<u8>, String> {
    Hkdf::derive_sha512(ikm, salt, info, output_length)
}

/// HKDF-SHA512 extract phase only
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt value
pub fn hkdf_extract_sha512(ikm: &[u8], salt: Option<&[u8]>) -> Vec<u8> {
    Hkdf::extract_sha512(ikm, salt)
}

/// HKDF-SHA512 expand phase only
///
/// # Arguments
/// * `prk` - Pseudorandom key from extract phase
/// * `info` - Context and application specific information
/// * `output_length` - Desired length of output key material
pub fn hkdf_expand_sha512(prk: &[u8], info: &[u8], output_length: usize) -> Result<Vec<u8>, String> {
    Hkdf::expand_sha512(prk, info, output_length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    
    #[test]
    fn test_rfc5869_test_case_1() {
        // Test Case 1 from RFC 5869
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let length = 42;
        
        let expected_prk = hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();
        let expected_okm = hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").unwrap();
        
        // Test extract
        let prk = hkdf_extract_sha256(&ikm, Some(&salt));
        assert_eq!(prk, expected_prk);
        
        // Test expand
        let okm = hkdf_expand_sha256(&prk, &info, length).unwrap();
        assert_eq!(okm, expected_okm);
        
        // Test complete HKDF
        let okm_complete = hkdf_sha256(&ikm, Some(&salt), &info, length).unwrap();
        assert_eq!(okm_complete, expected_okm);
    }
    
    #[test]
    fn test_rfc5869_test_case_2() {
        // Test Case 2 from RFC 5869
        let ikm = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f").unwrap();
        let salt = hex::decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap();
        let info = hex::decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let length = 82;
        
        let expected_okm = hex::decode("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87").unwrap();
        
        let okm = hkdf_sha256(&ikm, Some(&salt), &info, length).unwrap();
        assert_eq!(okm, expected_okm);
    }
    
    #[test]
    fn test_rfc5869_test_case_3() {
        // Test Case 3 from RFC 5869 - empty salt/info
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = vec![];
        let info = vec![];
        let length = 42;
        
        let expected_okm = hex::decode("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8").unwrap();
        
        let okm = hkdf_sha256(&ikm, Some(&salt), &info, length).unwrap();
        assert_eq!(okm, expected_okm);
    }
    
    #[test]
    fn test_no_salt() {
        let ikm = b"input key material";
        let info = b"application info";
        let length = 32;
        
        let okm = hkdf_sha256(ikm, None, info, length).unwrap();
        assert_eq!(okm.len(), length);
    }
    
    #[test]
    fn test_various_output_lengths() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        
        for length in &[16, 32, 48, 64, 128, 255] {
            let okm = hkdf_sha256(ikm, Some(salt), info, *length).unwrap();
            assert_eq!(okm.len(), *length);
        }
    }
    
    #[test]
    fn test_maximum_output_length() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        
        // Maximum for SHA-256: 255 * 32 = 8160
        let okm = hkdf_sha256(ikm, Some(salt), info, 8160).unwrap();
        assert_eq!(okm.len(), 8160);
        
        // Maximum for SHA-512: 255 * 64 = 16320
        let okm = hkdf_sha512(ikm, Some(salt), info, 16320).unwrap();
        assert_eq!(okm.len(), 16320);
    }
    
    #[test]
    fn test_invalid_output_length() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        
        // Zero length
        assert!(hkdf_sha256(ikm, Some(salt), info, 0).is_err());
        
        // Too long for SHA-256
        assert!(hkdf_sha256(ikm, Some(salt), info, 8161).is_err());
        
        // Too long for SHA-512
        assert!(hkdf_sha512(ikm, Some(salt), info, 16321).is_err());
    }
    
    #[test]
    fn test_invalid_prk_length() {
        let info = b"info";
        
        // Wrong PRK length for SHA-256
        let prk_wrong = vec![0u8; 31];
        assert!(hkdf_expand_sha256(&prk_wrong, info, 32).is_err());
        
        // Wrong PRK length for SHA-512
        let prk_wrong = vec![0u8; 63];
        assert!(hkdf_expand_sha512(&prk_wrong, info, 64).is_err());
    }
}