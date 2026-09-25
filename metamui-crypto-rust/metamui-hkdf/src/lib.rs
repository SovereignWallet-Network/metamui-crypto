// MetaMUI metamui hkdf
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// See LICENSE for full terms.
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! # HKDF
//!
//! HKDF (RFC 5869) with HMAC-SHA-256 and HMAC-SHA-512, as extract-and-expand
//! in one step or as the two phases separately. HMAC is built in this crate
//! on the one-shot hashes of `metamui-sha2`. Portable scalar Rust, the same
//! on every target.

use thiserror::Error;
use serde::{Serialize, Deserialize};

mod hkdf_native;
use hkdf_native::{HkdfNative, Sha256, Sha512};

/// HKDF error types
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum HkdfError {
    #[error("Invalid key material: {0}")]
    InvalidKey(String),
    
    #[error("Invalid salt: {0}")]
    InvalidSalt(String),
    
    #[error("Invalid info: {0}")]
    InvalidInfo(String),
    
    #[error("Invalid output length: {0}")]
    InvalidOutputLength(String),
    
    #[error("HKDF extraction failed: {0}")]
    ExtractionFailed(String),
    
    #[error("HKDF expansion failed: {0}")]
    ExpansionFailed(String),
    
    #[error("Hex decoding error: {0}")]
    HexDecodingError(String),
}

impl From<hex::FromHexError> for HkdfError {
    fn from(e: hex::FromHexError) -> Self {
        HkdfError::HexDecodingError(e.to_string())
    }
}

/// HKDF result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HkdfResult {
    pub output_key_material: Vec<u8>,
    pub length: usize,
}

/// HKDF implementation using SHA-256
pub struct MetaMUIHkdfSha256;

impl MetaMUIHkdfSha256 {
    /// Extract-and-Expand in one step using SHA-256
    pub fn derive(
        input_key_material: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        output_length: usize,
    ) -> Result<HkdfResult, HkdfError> {
        if output_length == 0 {
            return Err(HkdfError::InvalidOutputLength("Output length must be greater than 0".to_string()));
        }
        
        if output_length > 255 * 32 {
            return Err(HkdfError::InvalidOutputLength("Output length too large for SHA-256".to_string()));
        }

        let hkdf = HkdfNative::<Sha256>::new(salt, input_key_material);
        let mut output_key_material = vec![0u8; output_length];
        
        hkdf.expand(info, &mut output_key_material)
            .map_err(|_| HkdfError::ExpansionFailed("HKDF expansion failed".to_string()))?;

        Ok(HkdfResult {
            output_key_material,
            length: output_length,
        })
    }

    /// Extract phase only using SHA-256
    pub fn extract(input_key_material: &[u8], salt: Option<&[u8]>) -> Vec<u8> {
        HkdfNative::<Sha256>::extract(salt, input_key_material)
    }

    /// Expand phase only using SHA-256
    pub fn expand(
        pseudo_random_key: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<HkdfResult, HkdfError> {
        if output_length == 0 {
            return Err(HkdfError::InvalidOutputLength("Output length must be greater than 0".to_string()));
        }
        
        if output_length > 255 * 32 {
            return Err(HkdfError::InvalidOutputLength("Output length too large for SHA-256".to_string()));
        }

        let hkdf = HkdfNative::<Sha256>::from_prk(pseudo_random_key)
            .map_err(|e| HkdfError::InvalidKey(e.to_string()))?;
        
        let mut output_key_material = vec![0u8; output_length];
        hkdf.expand(info, &mut output_key_material)
            .map_err(|_| HkdfError::ExpansionFailed("HKDF expansion failed".to_string()))?;

        Ok(HkdfResult {
            output_key_material,
            length: output_length,
        })
    }
}

/// HKDF implementation using SHA-512
pub struct MetaMUIHkdfSha512;

impl MetaMUIHkdfSha512 {
    /// Extract-and-Expand in one step using SHA-512
    pub fn derive(
        input_key_material: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        output_length: usize,
    ) -> Result<HkdfResult, HkdfError> {
        if output_length == 0 {
            return Err(HkdfError::InvalidOutputLength("Output length must be greater than 0".to_string()));
        }
        
        if output_length > 255 * 64 {
            return Err(HkdfError::InvalidOutputLength("Output length too large for SHA-512".to_string()));
        }

        let hkdf = HkdfNative::<Sha512>::new(salt, input_key_material);
        let mut output_key_material = vec![0u8; output_length];
        
        hkdf.expand(info, &mut output_key_material)
            .map_err(|_| HkdfError::ExpansionFailed("HKDF expansion failed".to_string()))?;

        Ok(HkdfResult {
            output_key_material,
            length: output_length,
        })
    }

    /// Extract phase only using SHA-512
    pub fn extract(input_key_material: &[u8], salt: Option<&[u8]>) -> Vec<u8> {
        HkdfNative::<Sha512>::extract(salt, input_key_material)
    }

    /// Expand phase only using SHA-512
    pub fn expand(
        pseudo_random_key: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<HkdfResult, HkdfError> {
        if output_length == 0 {
            return Err(HkdfError::InvalidOutputLength("Output length must be greater than 0".to_string()));
        }
        
        if output_length > 255 * 64 {
            return Err(HkdfError::InvalidOutputLength("Output length too large for SHA-512".to_string()));
        }

        let hkdf = HkdfNative::<Sha512>::from_prk(pseudo_random_key)
            .map_err(|e| HkdfError::InvalidKey(e.to_string()))?;
        
        let mut output_key_material = vec![0u8; output_length];
        hkdf.expand(info, &mut output_key_material)
            .map_err(|_| HkdfError::ExpansionFailed("HKDF expansion failed".to_string()))?;

        Ok(HkdfResult {
            output_key_material,
            length: output_length,
        })
    }
}

/// Simple function-based API for HKDF-SHA256
/// Derive key material using HKDF with SHA-256
pub fn hkdf_sha256(
    input_key_material: Vec<u8>,
    salt: Option<Vec<u8>>,
    info: Vec<u8>,
    output_length: usize,
) -> Result<Vec<u8>, HkdfError> {
    let result = MetaMUIHkdfSha256::derive(
        &input_key_material,
        salt.as_deref(),
        &info,
        output_length,
    )?;
    Ok(result.output_key_material)
}

/// Extract-only using HKDF with SHA-256
pub fn hkdf_extract_sha256(
    input_key_material: Vec<u8>,
    salt: Option<Vec<u8>>,
) -> Vec<u8> {
    MetaMUIHkdfSha256::extract(&input_key_material, salt.as_deref())
}

/// Expand-only using HKDF with SHA-256
pub fn hkdf_expand_sha256(
    pseudo_random_key: Vec<u8>,
    info: Vec<u8>,
    output_length: usize,
) -> Result<Vec<u8>, HkdfError> {
    let result = MetaMUIHkdfSha256::expand(&pseudo_random_key, &info, output_length)?;
    Ok(result.output_key_material)
}

/// Simple function-based API for HKDF-SHA512
/// Derive key material using HKDF with SHA-512
pub fn hkdf_sha512(
    input_key_material: Vec<u8>,
    salt: Option<Vec<u8>>,
    info: Vec<u8>,
    output_length: usize,
) -> Result<Vec<u8>, HkdfError> {
    let result = MetaMUIHkdfSha512::derive(
        &input_key_material,
        salt.as_deref(),
        &info,
        output_length,
    )?;
    Ok(result.output_key_material)
}

/// Extract-only using HKDF with SHA-512
pub fn hkdf_extract_sha512(
    input_key_material: Vec<u8>,
    salt: Option<Vec<u8>>,
) -> Vec<u8> {
    MetaMUIHkdfSha512::extract(&input_key_material, salt.as_deref())
}

/// Expand-only using HKDF with SHA-512
pub fn hkdf_expand_sha512(
    pseudo_random_key: Vec<u8>,
    info: Vec<u8>,
    output_length: usize,
) -> Result<Vec<u8>, HkdfError> {
    let result = MetaMUIHkdfSha512::expand(&pseudo_random_key, &info, output_length)?;
    Ok(result.output_key_material)
}

/// Hex utility functions
/// Format bytes as hex string with 0x prefix
pub fn format_hex(bytes: Vec<u8>) -> String {
    format!("0x{}", hex::encode(&bytes))
}

/// Parse hex string (with or without 0x prefix) to bytes
pub fn parse_hex(hex_str: String) -> Result<Vec<u8>, HkdfError> {
    let cleaned = if hex_str.starts_with("0x") {
        &hex_str[2..]
    } else {
        &hex_str
    };
    
    hex::decode(cleaned).map_err(HkdfError::from)
}

/// Hex versions of HKDF functions
pub fn hkdf_sha256_hex(
    input_key_material_hex: String,
    salt_hex: Option<String>,
    info_hex: String,
    output_length: usize,
) -> Result<String, HkdfError> {
    let input_key_material = parse_hex(input_key_material_hex)?;
    let salt = if let Some(s) = salt_hex {
        Some(parse_hex(s)?)
    } else {
        None
    };
    let info = parse_hex(info_hex)?;
    
    let result = hkdf_sha256(input_key_material, salt, info, output_length)?;
    Ok(format_hex(result))
}

pub fn hkdf_sha512_hex(
    input_key_material_hex: String,
    salt_hex: Option<String>,
    info_hex: String,
    output_length: usize,
) -> Result<String, HkdfError> {
    let input_key_material = parse_hex(input_key_material_hex)?;
    let salt = if let Some(s) = salt_hex {
        Some(parse_hex(s)?)
    } else {
        None
    };
    let info = parse_hex(info_hex)?;
    
    let result = hkdf_sha512(input_key_material, salt, info, output_length)?;
    Ok(format_hex(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hkdf_sha256_basic() {
        let ikm = b"initial key material".to_vec();
        let salt = Some(b"salt".to_vec());
        let info = b"context info".to_vec();
        
        let result = hkdf_sha256(ikm, salt, info, 32).unwrap();
        assert_eq!(result.len(), 32);
    }
    
    #[test]
    fn test_hkdf_sha512_basic() {
        let ikm = b"initial key material".to_vec();
        let salt = Some(b"salt".to_vec());
        let info = b"context info".to_vec();
        
        let result = hkdf_sha512(ikm, salt, info, 64).unwrap();
        assert_eq!(result.len(), 64);
    }
    
    #[test]
    fn test_hkdf_extract_expand() {
        let ikm = b"initial key material".to_vec();
        let salt = Some(b"salt".to_vec());
        let info = b"context info".to_vec();
        
        // Extract phase
        let prk = hkdf_extract_sha256(ikm, salt);
        assert_eq!(prk.len(), 32); // SHA-256 output size
        
        // Expand phase
        let result = hkdf_expand_sha256(prk, info, 48).unwrap();
        assert_eq!(result.len(), 48);
    }
    
    #[test]
    fn test_hkdf_no_salt() {
        let ikm = b"initial key material".to_vec();
        let info = b"context info".to_vec();
        
        let result = hkdf_sha256(ikm, None, info, 32).unwrap();
        assert_eq!(result.len(), 32);
    }
    
    #[test]
    fn test_hkdf_zero_length_fails() {
        let ikm = b"initial key material".to_vec();
        let salt = Some(b"salt".to_vec());
        let info = b"context info".to_vec();
        
        let result = hkdf_sha256(ikm, salt, info, 0);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_hkdf_hex_functions() {
        let ikm_hex = "696e697469616c206b6579206d6174657269616c".to_string(); // "initial key material"
        let salt_hex = Some("73616c74".to_string()); // "salt"
        let info_hex = "636f6e7465787420696e666f".to_string(); // "context info"
        
        let result = hkdf_sha256_hex(ikm_hex, salt_hex, info_hex, 32).unwrap();
        assert!(result.starts_with("0x"));
        assert_eq!(result.len(), 66); // 0x + 32 bytes * 2 hex chars
    }
    
    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"test key material".to_vec();
        let salt = Some(b"test salt".to_vec());
        let info = b"test info".to_vec();
        
        let result1 = hkdf_sha256(ikm.clone(), salt.clone(), info.clone(), 32).unwrap();
        let result2 = hkdf_sha256(ikm, salt, info, 32).unwrap();
        
        assert_eq!(result1, result2);
    }
    
    #[test]
    fn test_rfc5869_test_case_1() {
        // RFC 5869 Test Case 1 — Basic HKDF-SHA-256
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = Some(hex::decode("000102030405060708090a0b0c").unwrap());
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let result = hkdf_sha256(ikm, salt, info, 42).unwrap();
        let expected = hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").unwrap();

        assert_eq!(result, expected, "RFC 5869 Test Case 1 failed");
    }

    #[test]
    fn test_rfc5869_test_case_2() {
        // RFC 5869 Test Case 2 — HKDF-SHA-256 with longer inputs
        let ikm = hex::decode(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f\
             303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f"
        ).unwrap();
        let salt = Some(hex::decode(
            "606162636465666768696a6b6c6d6e6f\
             707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        ).unwrap());
        let info = hex::decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
             c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
             e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ).unwrap();

        let result = hkdf_sha256(ikm, salt, info, 82).unwrap();
        let expected = hex::decode(
            "b11e398dc80327a1c8e7f78c596a4934\
             4f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09\
             da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f\
             1d87"
        ).unwrap();

        assert_eq!(result, expected, "RFC 5869 Test Case 2 failed");
    }

    #[test]
    fn test_rfc5869_test_case_3() {
        // RFC 5869 Test Case 3 — HKDF-SHA-256 with zero-length salt and info
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt: Option<Vec<u8>> = None;
        let info = Vec::new();

        let result = hkdf_sha256(ikm, salt, info, 42).unwrap();
        let expected = hex::decode(
            "8da4e775a563c18f715f802a063c5a31\
             b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        ).unwrap();

        assert_eq!(result, expected, "RFC 5869 Test Case 3 failed");
    }
}
