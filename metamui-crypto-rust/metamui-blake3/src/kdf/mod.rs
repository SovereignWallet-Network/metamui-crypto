//! BLAKE3-KDF - Key Derivation Function using BLAKE3
//!
//! This module provides a key derivation function based on BLAKE3's
//! derive_key mode, which is designed for deriving cryptographic keys
//! from input key material.
//!
//! # Example
//! ```
//! use metamui_blake3::kdf::Blake3Kdf;
//!
//! let kdf = Blake3Kdf::new(b"MyApp v1.0.0 Key Derivation");
//! let ikm = b"input key material";
//! let derived_key = kdf.derive_key(ikm, 32);
//! assert_eq!(derived_key.len(), 32);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::MetaMUIBlake3;
use metamui_security_utils::Zeroize;

/// BLAKE3-based Key Derivation Function
#[derive(Clone, Debug)]
pub struct Blake3Kdf {
    /// Context string for domain separation
    context: Vec<u8>,
}

impl Blake3Kdf {
    /// Create a new BLAKE3-KDF instance with the given context
    ///
    /// The context string provides domain separation between different
    /// applications of the KDF. It should be unique for each use case.
    ///
    /// # Example
    /// ```
    /// use metamui_blake3::kdf::Blake3Kdf;
    ///
    /// let kdf = Blake3Kdf::new(b"MyApp v1.0.0 User Key");
    /// ```
    pub fn new(context: &[u8]) -> Self {
        Blake3Kdf {
            context: context.to_vec(),
        }
    }

    /// Derive key material from input key material (IKM)
    ///
    /// # Arguments
    /// * `ikm` - Input key material
    /// * `output_length` - Desired length of derived key material
    ///
    /// # Returns
    /// A vector containing the derived key material
    ///
    /// # Example
    /// ```
    /// use metamui_blake3::kdf::Blake3Kdf;
    ///
    /// let kdf = Blake3Kdf::new(b"MyApp Key Derivation");
    /// let ikm = b"secret input material";
    /// let key = kdf.derive_key(ikm, 32);
    /// assert_eq!(key.len(), 32);
    /// ```
    pub fn derive_key(&self, ikm: &[u8], output_length: usize) -> Vec<u8> {
        // Create a BLAKE3 hasher in derive_key mode with our context
        let context_str = core::str::from_utf8(&self.context).unwrap_or("BLAKE3-KDF");
        let mut hasher = MetaMUIBlake3::new_derive_key(context_str);
        
        // Add the input key material
        hasher.update(ikm);
        
        // Use variable output length generation
        hasher.finalize_variable(output_length)
    }

    /// Derive key material with additional info parameter
    ///
    /// This follows a pattern similar to HKDF where additional
    /// application-specific information can be included.
    ///
    /// # Arguments
    /// * `ikm` - Input key material
    /// * `info` - Optional context and application specific information
    /// * `output_length` - Desired length of derived key material
    ///
    /// # Example
    /// ```
    /// use metamui_blake3::kdf::Blake3Kdf;
    ///
    /// let kdf = Blake3Kdf::new(b"MyApp KDF");
    /// let ikm = b"secret material";
    /// let info = b"session-2024-01-01";
    /// let key = kdf.derive_key_with_info(ikm, Some(info), 32);
    /// ```
    pub fn derive_key_with_info(
        &self,
        ikm: &[u8],
        info: Option<&[u8]>,
        output_length: usize,
    ) -> Vec<u8> {
        let context_str = core::str::from_utf8(&self.context).unwrap_or("BLAKE3-KDF");
        let mut hasher = MetaMUIBlake3::new_derive_key(context_str);
        
        // Add input key material
        hasher.update(ikm);
        
        // Add info if provided
        if let Some(info_bytes) = info {
            hasher.update(info_bytes);
        }
        
        // Generate output
        hasher.finalize_variable(output_length)
    }

    /// Derive multiple keys from the same input material
    ///
    /// This is useful when you need multiple keys for different purposes
    /// (e.g., encryption key, MAC key, etc.) from the same input.
    ///
    /// # Arguments
    /// * `ikm` - Input key material
    /// * `key_lengths` - Array of desired key lengths
    ///
    /// # Returns
    /// A vector of derived keys
    ///
    /// # Example
    /// ```
    /// use metamui_blake3::kdf::Blake3Kdf;
    ///
    /// let kdf = Blake3Kdf::new(b"MyApp Multi-Key");
    /// let ikm = b"master secret";
    /// let keys = kdf.derive_multiple_keys(ikm, &[32, 32, 16]);
    /// assert_eq!(keys.len(), 3);
    /// assert_eq!(keys[0].len(), 32); // Encryption key
    /// assert_eq!(keys[1].len(), 32); // MAC key
    /// assert_eq!(keys[2].len(), 16); // IV
    /// ```
    pub fn derive_multiple_keys(&self, ikm: &[u8], key_lengths: &[usize]) -> Vec<Vec<u8>> {
        let context_str = core::str::from_utf8(&self.context).unwrap_or("BLAKE3-KDF");
        let mut hasher = MetaMUIBlake3::new_derive_key(context_str);
        
        hasher.update(ikm);
        
        // Calculate total length needed
        let total_length: usize = key_lengths.iter().sum();
        let output = hasher.finalize_variable(total_length);
        
        let mut keys = Vec::with_capacity(key_lengths.len());
        let mut offset = 0;
        
        for &length in key_lengths {
            let key = output[offset..offset + length].to_vec();
            keys.push(key);
            offset += length;
        }
        
        keys
    }
}

impl Drop for Blake3Kdf {
    fn drop(&mut self) {
        self.context.zeroize();
    }
}

/// Convenience function for one-shot key derivation
///
/// # Example
/// ```
/// use metamui_blake3::kdf::derive_key;
///
/// let key = derive_key(
///     b"MyApp Context",
///     b"input key material",
///     32
/// );
/// assert_eq!(key.len(), 32);
/// ```
pub fn derive_key(context: &[u8], ikm: &[u8], output_length: usize) -> Vec<u8> {
    Blake3Kdf::new(context).derive_key(ikm, output_length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_basic_derivation() {
        let kdf = Blake3Kdf::new(b"Test Context");
        let ikm = b"test input";
        let key = kdf.derive_key(ikm, 32);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_different_contexts_produce_different_keys() {
        let ikm = b"same input";
        
        let kdf1 = Blake3Kdf::new(b"Context 1");
        let key1 = kdf1.derive_key(ikm, 32);
        
        let kdf2 = Blake3Kdf::new(b"Context 2");
        let key2 = kdf2.derive_key(ikm, 32);
        
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_inputs_produce_different_keys() {
        let kdf = Blake3Kdf::new(b"Test Context");
        
        let key1 = kdf.derive_key(b"input 1", 32);
        let key2 = kdf.derive_key(b"input 2", 32);
        
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_variable_output_length() {
        let kdf = Blake3Kdf::new(b"Test Context");
        let ikm = b"test input";
        
        let key16 = kdf.derive_key(ikm, 16);
        let key32 = kdf.derive_key(ikm, 32);
        let key64 = kdf.derive_key(ikm, 64);
        
        assert_eq!(key16.len(), 16);
        assert_eq!(key32.len(), 32);
        assert_eq!(key64.len(), 64);
        
        // First 16 bytes should match
        assert_eq!(&key32[..16], &key16[..]);
        assert_eq!(&key64[..32], &key32[..]);
    }

    #[test]
    fn test_with_info() {
        let kdf = Blake3Kdf::new(b"Test Context");
        let ikm = b"test input";
        
        let key_without_info = kdf.derive_key(ikm, 32);
        let key_with_info = kdf.derive_key_with_info(ikm, Some(b"extra info"), 32);
        
        assert_ne!(key_without_info, key_with_info);
    }

    #[test]
    fn test_multiple_keys() {
        let kdf = Blake3Kdf::new(b"Multi-Key Test");
        let ikm = b"master secret";
        
        let keys = kdf.derive_multiple_keys(ikm, &[32, 32, 16]);
        
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].len(), 32);
        assert_eq!(keys[1].len(), 32);
        assert_eq!(keys[2].len(), 16);
        
        // Keys should be different from each other
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[0], keys[2][..16]);
    }

    #[test]
    fn test_known_vector() {
        // Test with a known context and input
        let kdf = Blake3Kdf::new(b"BLAKE3 2019-12-27 16:13:59 example context");
        let ikm = hex!("00010203 04050607 08090a0b 0c0d0e0f");
        let derived = kdf.derive_key(&ikm, 32);
        
        // The output should be deterministic
        assert_eq!(derived.len(), 32);
        
        // Verify it's reproducible
        let derived2 = kdf.derive_key(&ikm, 32);
        assert_eq!(derived, derived2);
    }
}
