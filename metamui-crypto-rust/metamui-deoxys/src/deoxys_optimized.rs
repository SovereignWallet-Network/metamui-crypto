/// Optimized Deoxys-II-256-128 implementation
///
/// This module provides an optimized implementation that delegates to the reference
/// implementation until the optimizations are complete and verified.

use crate::{Error, KEY_SIZE, NONCE_SIZE};

/// Optimized Deoxys-II-256-128 AEAD
pub struct DeoxysII;

impl DeoxysII {
    /// Encrypt with associated data
    pub fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        crate::DeoxysII::encrypt(key, nonce, plaintext, associated_data)
    }

    /// Decrypt and verify
    pub fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        crate::DeoxysII::decrypt(key, nonce, ciphertext, associated_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x24u8; NONCE_SIZE];
        let plaintext = b"Hello, Deoxys-II Optimized!";
        let aad = b"Additional data";

        let ciphertext = DeoxysII::encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = DeoxysII::decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_authentication_failure() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x24u8; NONCE_SIZE];
        let plaintext = b"Test message";
        let aad = b"AAD";

        let mut ciphertext = DeoxysII::encrypt(&key, &nonce, plaintext, aad).unwrap();
        ciphertext[0] ^= 1; // Tamper

        let result = DeoxysII::decrypt(&key, &nonce, &ciphertext, aad);
        assert!(matches!(result, Err(Error::AuthenticationFailed)));
    }
}
