// MetaMUI metamui crypto utilities   flathash
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto


/// MetaMUI FlatHash Implementation
/// 
/// Provides deterministic hashing of JSON objects by flattening them
/// into a canonical representation before hashing with SHA-256.

use crate::error::{CryptoUtilError, Result};
use metamui_sha2::sha256::MetaMUISha256;
use serde_json::Value;
use core::fmt;


use std::collections::BTreeMap;

/// FlatHash output size (32 bytes, same as SHA-256)
pub const FLATHASH_OUTPUT_SIZE: usize = 32;

/// FlatHash result
pub type FlatHash = [u8; FLATHASH_OUTPUT_SIZE];

/// MetaMUI FlatHash implementation
/// 
/// FlatHash provides deterministic hashing of JSON objects by:
/// 1. Parsing the JSON into a structured format
/// 2. Flattening the structure using dot notation for keys
/// 3. Creating a canonical string representation
/// 4. Hashing with SHA-256
/// 
/// # Examples
/// 
/// ```rust
/// use metamui_crypto_utilities::flathash::MetaMUIFlatHash;
/// 
/// let hasher = MetaMUIFlatHash::new();
/// let json = r#"{"name": "test", "value": 42}"#;
/// let hash = hasher.hash(json).unwrap();
/// println!("Hash: {}", hex::encode(hash));
/// ```
pub struct MetaMUIFlatHash;

impl MetaMUIFlatHash {
    /// Create a new FlatHash instance
    pub fn new() -> Self {
        Self
    }

    /// Compute FlatHash of a JSON string
    /// 
    /// # Arguments
    /// 
    /// * `json_string` - JSON string to hash
    /// 
    /// # Returns
    /// 
    /// 32-byte FlatHash
    /// 
    /// # Errors
    /// 
    /// Returns `CryptoUtilError` if JSON parsing or hashing fails
    pub fn hash(&self, json_string: &str) -> Result<FlatHash> {
        // Parse JSON
        let json_value: Value = serde_json::from_str(json_string)
            .map_err(|_| CryptoUtilError::InvalidEncoding(crate::error::EncodingError::InvalidUtf8))?;

        // Flatten the JSON structure
        let flattened = self.flatten(&json_value)?;

        // Create canonical representation
        let canonical = self.create_canonical_representation(&flattened);

        // Hash the canonical representation
        let hash = MetaMUISha256::new()
            .hash(canonical.as_bytes())
            .map_err(|e| CryptoUtilError::HashError(e.to_string()))?;
        Ok(hash)
    }

    /// Compute FlatHash and return as hex string
    /// 
    /// # Arguments
    /// 
    /// * `json_string` - JSON string to hash
    /// 
    /// # Returns
    /// 
    /// Hex string representation with 0x prefix
    pub fn hash_hex(&self, json_string: &str) -> Result<String> {
        let hash = self.hash(json_string)?;
        Ok(format!("0x{}", hex::encode(&hash)))
    }

    /// Flatten a JSON value into a key-value map
    fn flatten(&self, value: &Value) -> Result<BTreeMap<String, String>> {
        let mut result = BTreeMap::new();
        self.flatten_recursive(value, String::new(), &mut result)?;
        Ok(result)
    }

    /// Recursively flatten a JSON value
    fn flatten_recursive(
        &self,
        value: &Value,
        prefix: String,
        result: &mut BTreeMap<String, String>,
    ) -> Result<()> {
        match value {
            Value::Object(obj) => {
                if obj.is_empty() {
                    let key = if prefix.is_empty() {
                        "__empty_object__".to_string()
                    } else {
                        format!("{}.__empty_object__", prefix)
                    };
                    result.insert(key, "{}".to_string());
                } else {
                    for (key, val) in obj {
                        let new_prefix = if prefix.is_empty() {
                            key.clone()
                        } else {
                            format!("{}.{}", prefix, key)
                        };
                        self.flatten_recursive(val, new_prefix, result)?;
                    }
                }
            }
            Value::Array(arr) => {
                if arr.is_empty() {
                    let key = if prefix.is_empty() {
                        "__empty_array__".to_string()
                    } else {
                        format!("{}.__empty_array__", prefix)
                    };
                    result.insert(key, "[]".to_string());
                } else {
                    for (index, val) in arr.iter().enumerate() {
                        let new_prefix = format!("{}[{}]", prefix, index);
                        self.flatten_recursive(val, new_prefix, result)?;
                    }
                }
            }
            Value::String(s) => {
                result.insert(prefix, s.clone());
            }
            Value::Number(n) => {
                result.insert(prefix, n.to_string());
            }
            Value::Bool(b) => {
                result.insert(prefix, b.to_string());
            }
            Value::Null => {
                result.insert(prefix, "null".to_string());
            }
        }
        Ok(())
    }

    /// Create canonical string representation from flattened map
    fn create_canonical_representation(&self, flattened: &BTreeMap<String, String>) -> String {
        flattened
            .iter()
            .map(|(key, value)| format!("{}:{}", key, value))
            .collect::<Vec<_>>()
            .join("")
    }

    /// Verify that JSON produces the expected hash
    /// 
    /// # Arguments
    /// 
    /// * `json_string` - JSON string to verify
    /// * `expected_hash` - Expected hash value
    /// 
    /// # Returns
    /// 
    /// True if hash matches, false otherwise
    pub fn verify_hash(&self, json_string: &str, expected_hash: &FlatHash) -> bool {
        match self.hash(json_string) {
            Ok(computed_hash) => &computed_hash == expected_hash,
            Err(_) => false,
        }
    }

    /// Get the algorithm name
    pub fn algorithm_name(&self) -> &'static str {
        "FlatHash"
    }

    /// Get the output size in bytes
    pub fn output_size(&self) -> usize {
        FLATHASH_OUTPUT_SIZE
    }
}

impl Default for MetaMUIFlatHash {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MetaMUIFlatHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MetaMUIFlatHash(output_size={})", self.output_size())
    }
}

impl fmt::Debug for MetaMUIFlatHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetaMUIFlatHash")
            .field("algorithm", &self.algorithm_name())
            .field("output_size", &self.output_size())
            .finish()
    }
}

/// Convenience function to compute FlatHash
/// 
/// # Arguments
/// 
/// * `json_string` - JSON string to hash
/// 
/// # Returns
/// 
/// 32-byte FlatHash
pub fn flat_hash(json_string: &str) -> Result<FlatHash> {
    let hasher = MetaMUIFlatHash::new();
    hasher.hash(json_string)
}

/// Convenience function to compute FlatHash as hex string
/// 
/// # Arguments
/// 
/// * `json_string` - JSON string to hash
/// 
/// # Returns
/// 
/// Hex string with 0x prefix
pub fn flat_hash_hex(json_string: &str) -> Result<String> {
    let hasher = MetaMUIFlatHash::new();
    hasher.hash_hex(json_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flathash_simple_object() {
        let hasher = MetaMUIFlatHash::new();
        let json = r#"{"name": "test", "value": 42}"#;
        let hash = hasher.hash(json).unwrap();
        
        assert_eq!(hash.len(), FLATHASH_OUTPUT_SIZE);
        
        // Hash should be deterministic
        let hash2 = hasher.hash(json).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_flathash_empty_object() {
        let hasher = MetaMUIFlatHash::new();
        let json = r#"{}"#;
        let hash = hasher.hash(json).unwrap();
        
        assert_eq!(hash.len(), FLATHASH_OUTPUT_SIZE);
    }

    #[test]
    fn test_flathash_empty_array() {
        let hasher = MetaMUIFlatHash::new();
        let json = r#"[]"#;
        let hash = hasher.hash(json).unwrap();
        
        assert_eq!(hash.len(), FLATHASH_OUTPUT_SIZE);
    }

    #[test]
    fn test_flathash_nested_object() {
        let hasher = MetaMUIFlatHash::new();
        let json = r#"{"user": {"name": "Alice", "age": 30}, "active": true}"#;
        let hash = hasher.hash(json).unwrap();
        
        assert_eq!(hash.len(), FLATHASH_OUTPUT_SIZE);
    }

    #[test]
    fn test_flathash_array() {
        let hasher = MetaMUIFlatHash::new();
        let json = r#"[1, 2, 3]"#;
        let hash = hasher.hash(json).unwrap();
        
        assert_eq!(hash.len(), FLATHASH_OUTPUT_SIZE);
    }

    #[test]
    fn test_flathash_order_independence() {
        let hasher = MetaMUIFlatHash::new();
        
        // These should produce the same hash (object key order doesn't matter)
        let json1 = r#"{"a": 1, "b": 2}"#;
        let json2 = r#"{"b": 2, "a": 1}"#;
        
        let hash1 = hasher.hash(json1).unwrap();
        let hash2 = hasher.hash(json2).unwrap();
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_flathash_array_order_dependence() {
        let hasher = MetaMUIFlatHash::new();
        
        // These should produce different hashes (array order matters)
        let json1 = r#"[1, 2]"#;
        let json2 = r#"[2, 1]"#;
        
        let hash1 = hasher.hash(json1).unwrap();
        let hash2 = hasher.hash(json2).unwrap();
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_flathash_verify() {
        let hasher = MetaMUIFlatHash::new();
        let json = r#"{"test": "data"}"#;
        let hash = hasher.hash(json).unwrap();
        
        assert!(hasher.verify_hash(json, &hash));
        
        let wrong_hash = [0u8; 32];
        assert!(!hasher.verify_hash(json, &wrong_hash));
    }

    #[test]
    fn test_flathash_hex() {
        let hasher = MetaMUIFlatHash::new();
        let json = r#"{"test": "data"}"#;
        let hex_hash = hasher.hash_hex(json).unwrap();
        
        assert!(hex_hash.starts_with("0x"));
        assert_eq!(hex_hash.len(), 2 + (FLATHASH_OUTPUT_SIZE * 2)); // 0x + 64 hex chars
    }

    #[test]
    fn test_convenience_functions() {
        let json = r#"{"test": "data"}"#;
        
        let hash1 = flat_hash(json).unwrap();
        let hasher = MetaMUIFlatHash::new();
        let hash2 = hasher.hash(json).unwrap();
        
        assert_eq!(hash1, hash2);
        
        let hex1 = flat_hash_hex(json).unwrap();
        let hex2 = hasher.hash_hex(json).unwrap();
        
        assert_eq!(hex1, hex2);
    }

    #[test]
    fn test_invalid_json() {
        let hasher = MetaMUIFlatHash::new();
        let invalid_json = r#"{"invalid": json}"#;
        
        let result = hasher.hash(invalid_json);
        assert!(result.is_err());
        
        match result {
            Err(CryptoUtilError::InvalidEncoding(_)) => {}
            _ => panic!("Expected InvalidEncoding error"),
        }
    }
}
