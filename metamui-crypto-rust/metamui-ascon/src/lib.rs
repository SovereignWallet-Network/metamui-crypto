// MetaMUI metamui ascon
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

//! # MetaMUI Ascon
//!
//! Pure Rust implementation of the four NIST SP 800-232 Ascon functions:
//! Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128.

#![no_std]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

/// # MetaMUI Ascon
///
/// Pure Rust implementation of NIST SP 800-232 (August 2025), the
/// standardised form of the NIST Lightweight Cryptography winner.
///
/// ## Functions
///
/// - **Ascon-AEAD128** (`AsconAead128`): 128-bit key/nonce/tag AEAD, rate 16
/// - **Ascon-Hash256** (`AsconHash256`): fixed 256-bit digest
/// - **Ascon-XOF128** (`AsconXof128`): arbitrary-length output
/// - **Ascon-CXOF128** (`AsconCxof128`): XOF bound to a customization string
///
/// Every function is byte-exact to the reference implementation's KAT files
/// vendored under `test-vectors/ascon-upstream/`.
///
/// - **Pure Rust**: No external dependencies or unsafe code
/// - **no_std**: Compatible with embedded environments
/// - **Portable**: scalar Rust only, no SIMD, assembly or CPU-feature detection;
///   designed for constant time and unmeasured (see README)
///
/// ## Usage
///
/// ```rust
/// use metamui_ascon::{AsconAead128, AsconAead};
///
/// let key = [0u8; 16];
/// let nonce = [0u8; 16];
/// let plaintext = b"Hello, Ascon!";
///
/// let ascon = AsconAead128::new(key);
/// let (ciphertext, tag) = ascon.encrypt(&nonce, plaintext, &[]).unwrap();
/// let decrypted = ascon.decrypt(&nonce, &ciphertext, &tag, &[]).unwrap();
///
/// assert_eq!(plaintext, decrypted.as_slice());
/// ```

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use core::fmt;

mod aead128;
mod cxof128;
mod hash256;
mod permutation;
mod sponge;
mod xof128;

pub use crate::aead128::{AsconAead, AsconAead128};
pub use crate::cxof128::{ascon_cxof128, AsconCxof128, AsconCxof128Reader, MAX_CUSTOMIZATION_LEN};
pub use crate::hash256::{ascon_hash256, AsconHash256, DIGEST_LEN};
pub use crate::xof128::{ascon_xof128, AsconXof128, AsconXof128Reader};

/// Error types for Ascon operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsconError {
    /// Invalid key length (must be 16 bytes)
    InvalidKeyLength,
    /// Invalid nonce length (must be 16 bytes)
    InvalidNonceLength,
    /// Authentication tag verification failed
    AuthenticationFailed,
    /// Nonce has been reused (critical security violation)
    NonceReuse,
    /// Ascon-CXOF128 customization string longer than 2048 bits (256 bytes)
    CustomizationTooLong,
}

impl fmt::Display for AsconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsconError::InvalidKeyLength => write!(f, "Key must be 16 bytes"),
            AsconError::InvalidNonceLength => write!(f, "Nonce must be 16 bytes"),
            AsconError::AuthenticationFailed => write!(f, "Authentication tag verification failed"),
            AsconError::NonceReuse => write!(f, "Nonce has been reused - critical security violation"),
            AsconError::CustomizationTooLong => {
                write!(f, "Ascon-CXOF128 customization string exceeds 256 bytes")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AsconError {}

/// Result type for Ascon operations
pub type Result<T> = core::result::Result<T, AsconError>;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_aead128_basic() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"Hello, Ascon-128a!";

        let ascon = AsconAead128::new(key);
        let (ciphertext, tag) = ascon.encrypt(&nonce, plaintext, &[]).unwrap();
        let decrypted = ascon.decrypt(&nonce, &ciphertext, &tag, &[]).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aead128_with_ad() {
        let key = [1u8; 16];
        let nonce = [2u8; 16];
        let plaintext = b"Secret message";
        let associated_data = b"Public header";

        let ascon = AsconAead128::new(key);
        let (ciphertext, tag) = ascon.encrypt(&nonce, plaintext, associated_data).unwrap();
        let decrypted = ascon.decrypt(&nonce, &ciphertext, &tag, associated_data).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_different_outputs() {
        let key1 = [0u8; 16];
        let key2 = [1u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"Same plaintext";

        let ascon1 = AsconAead128::new(key1);
        let ascon2 = AsconAead128::new(key2);

        let (ciphertext1, tag1) = ascon1.encrypt(&nonce, plaintext, &[]).unwrap();
        let (ciphertext2, tag2) = ascon2.encrypt(&nonce, plaintext, &[]).unwrap();

        assert_ne!(ciphertext1, ciphertext2);
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_authentication_failure() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"Authenticated message";

        let ascon = AsconAead128::new(key);
        let (mut ciphertext, tag) = ascon.encrypt(&nonce, plaintext, &[]).unwrap();

        // Modify ciphertext
        ciphertext[0] ^= 1;

        let result = ascon.decrypt(&nonce, &ciphertext, &tag, &[]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AsconError::AuthenticationFailed);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let plaintext = b"";

        let ascon = AsconAead128::new(key);
        let (ciphertext, tag) = ascon.encrypt(&nonce, plaintext, &[]).unwrap();
        let decrypted = ascon.decrypt(&nonce, &ciphertext, &tag, &[]).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
        assert_eq!(ciphertext.len(), 0);
    }

    #[test]
    fn test_various_lengths() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let ascon = AsconAead128::new(key);

        for (i, len) in [1, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65].iter().enumerate() {
            let mut unique_nonce = nonce;
            unique_nonce[0] = i as u8;  // Make nonce unique for each test
            let plaintext = vec![0xAAu8; *len];
            let (ciphertext, tag) = ascon.encrypt(&unique_nonce, &plaintext, &[]).unwrap();
            let decrypted = ascon.decrypt(&unique_nonce, &ciphertext, &tag, &[]).unwrap();
            assert_eq!(plaintext, decrypted);
        }
    }

    // Note: Nonce reuse detection is not implemented in this version
    // as it would require interior mutability and state tracking.
    // Users must ensure nonces are never reused.

    #[test]
    fn test_nist_vector_1() {
        // Official NIST vector 1: empty plaintext, empty AAD (using Ascon-128a/AEAD128)
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
        let plaintext = b"";
        let aad = b"";

        let ascon = AsconAead128::new(key);
        let (ciphertext, tag) = ascon.encrypt(&nonce, plaintext, aad).unwrap();
        
        assert!(ciphertext.is_empty(), "Ciphertext should be empty");
        assert_eq!(tag.len(), 16, "Tag should be 16 bytes");
        
        // SP 800-232 Ascon-AEAD128 KAT #1 (test-vectors/ascon/ascon-vectors.json)
        let expected_tag = [0x4f, 0x9c, 0x27, 0x82, 0x11, 0xbe, 0xc9, 0x31, 0x6b, 0xf6, 0x8f, 0x46, 0xee, 0x8b, 0x2e, 0xc6];
        assert_eq!(tag, expected_tag, "Tag should match SP 800-232 KAT #1");
    }

    #[test] 
    fn test_nist_vector_2() {
        // Official NIST vector 2: empty plaintext, single byte AAD (using Ascon-128a/AEAD128)
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
        let plaintext = b"";
        let aad = b"\x30";

        let ascon = AsconAead128::new(key);
        let (ciphertext, tag) = ascon.encrypt(&nonce, plaintext, aad).unwrap();
        
        assert!(ciphertext.is_empty(), "Ciphertext should be empty");
        assert_eq!(tag.len(), 16, "Tag should be 16 bytes");
        
        // SP 800-232 Ascon-AEAD128 KAT #2 (test-vectors/ascon/ascon-vectors.json)
        let expected_tag = [0xcc, 0xcb, 0x67, 0x4f, 0xe1, 0x8a, 0x09, 0xa2, 0x85, 0xd6, 0xab, 0x11, 0xb3, 0x56, 0x75, 0xc0];
        assert_eq!(tag, expected_tag, "Tag should match SP 800-232 KAT #2");
        
        // The tag should be different from vector 1
        let ascon1 = AsconAead128::new(key);
        let (_, tag1) = ascon1.encrypt(&nonce, b"", b"").unwrap();
        assert_ne!(tag, tag1, "Tags should be different with different AAD");
    }
}
