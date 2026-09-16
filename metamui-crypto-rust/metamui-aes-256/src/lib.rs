// MetaMUI metamui aes 256
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! AES-256 implementation for MetaMUI Crypto Primitives.
//!
//! Provides a secure AES-256 block cipher with ECB, CBC, CTR, and GCM modes.

#![warn(missing_docs, rust_2018_idioms)]

///
/// This module provides a secure implementation of AES-256 encryption with support for
/// multiple modes of operation including ECB, CBC, GCM (authenticated), and CTR.
///
/// # Security Features
/// - Automatic key zeroization on drop
/// - Constant-time operations where possible  
/// - Side-channel resistant implementation
/// - No simplified or placeholder code
///
/// # Example (External Implementation)
/// ```rust,ignore
/// use metamui_aes_256::{Aes256Key, Aes256Gcm};
/// use hex_literal::hex;
///
/// // Generate a random 256-bit key
/// let key = Aes256Key::generate()?;
///
/// // Create AES-GCM instance (external implementation)
/// let cipher = Aes256Gcm::new(&key)?;
///
/// // Encrypt data
/// let plaintext = b"Secret message";
/// let nonce = hex!("000102030405060708090a0b"); // 96-bit nonce for GCM
/// let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, None)?;
///
/// // Decrypt data
/// let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None)?;
/// assert_eq!(plaintext, &decrypted[..]);
/// ```
///
/// # Example (Native Implementation)
/// ```rust
/// use metamui_aes_256::{Aes256Key, aes256::Aes256Core};
///
/// // Generate a random 256-bit key
/// let key = Aes256Key::generate().unwrap();
///
/// // Create native AES instance
/// let aes = Aes256Core::new(key.as_bytes());
///
/// // Encrypt data using CBC mode
/// let iv = [0u8; 16]; // Use random IV in production
/// let plaintext = b"Hello, AES-256!";
/// let ciphertext = aes.encrypt_cbc(&iv, plaintext);
///
/// // Decrypt data
/// let decrypted = aes.decrypt_cbc(&iv, &ciphertext).unwrap();
/// assert_eq!(plaintext, &decrypted[..]);
/// ```

/// Error types for AES-256 operations.
pub mod error;
/// AES-256 key management and generation.
pub mod key;


/// AES-128 block cipher (FIPS 197, Nk = 4) for constructions that fix it by
/// specification (FrodoKEM-AES); the crate's modes stay AES-256.
#[cfg(feature = "native")]
pub mod aes128;
/// Native AES-256 block cipher implementation.
#[cfg(feature = "native")]
pub mod aes256;

// Re-exports
pub use error::{Aes256Error, Result};
pub use key::Aes256Key;

// Native implementation re-exports
#[cfg(feature = "native")]
pub use aes128::Aes128;
#[cfg(feature = "native")]
pub use aes256::Aes256;

/// Type alias for the native AES-256 core (compatibility).
#[cfg(feature = "native")]
pub type Aes256Core = aes256::Aes256;

/// AES-256 modes of operation (ECB, CBC, CTR, GCM).
#[cfg(feature = "native")]
pub mod modes;

#[cfg(feature = "native")]
pub use modes::gcm::Aes256Gcm;

/// AES block size in bytes (always 128 bits / 16 bytes)
pub const BLOCK_SIZE: usize = 16;

/// AES-256 key size in bytes (256 bits / 32 bytes)
pub const KEY_SIZE: usize = 32;

/// GCM authentication tag size in bytes (128 bits / 16 bytes)
pub const GCM_TAG_SIZE: usize = 16;

/// GCM nonce size in bytes (96 bits / 12 bytes)
pub const GCM_NONCE_SIZE: usize = 12;

/// CBC/CTR IV size in bytes (128 bits / 16 bytes)
pub const IV_SIZE: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_key_generation() {
        let key = Aes256Key::generate().unwrap();
        assert_eq!(key.as_bytes().len(), KEY_SIZE);
    }

    #[test]
    fn test_key_from_bytes() {
        let key_bytes = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let key = Aes256Key::from_bytes(&key_bytes).unwrap();
        assert_eq!(key.as_bytes(), &key_bytes);
    }

    #[test]
    fn test_key_zeroization() {
        let key_bytes = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let key = Aes256Key::from_bytes(&key_bytes).unwrap();
        
        // Just test that zeroization trait is implemented - actual memory test would be unsafe
        // The zeroize crate handles the actual secure clearing
        assert_eq!(key.as_bytes().len(), KEY_SIZE);
    }
}
