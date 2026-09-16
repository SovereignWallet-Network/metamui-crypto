/// AES-256-CBC (Cipher Block Chaining) mode with PKCS#7 padding

use crate::{
    error::{Aes256Error, Result},
    key::Aes256Key,
    aes256::Aes256,
    IV_SIZE,
};

/// AES-256-CBC cipher
pub struct Aes256Cbc {
    core: Aes256,
}

impl Aes256Cbc {
    /// Create new AES-256-CBC instance
    pub fn new(key: &Aes256Key) -> Result<Self> {
        let core = crate::aes256::Aes256Core::new(key.as_bytes());
        Ok(Self { core })
    }

    /// Encrypt data with AES-256-CBC and PKCS#7 padding
    ///
    /// The empty message is valid input: PKCS#7 always appends at least one
    /// padding byte, so it encrypts to exactly one block (Wycheproof
    /// aes_cbc_pkcs5 tcId 145).
    pub fn encrypt(&self, iv: &[u8; IV_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok(self.core.encrypt_cbc(iv, plaintext))
    }

    /// Decrypt data with AES-256-CBC and PKCS#7 padding
    pub fn decrypt(&self, iv: &[u8; IV_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
            return Err(Aes256Error::InvalidBlockSize { block_size: 16 });
        }
        
        self.core.decrypt_cbc(iv, ciphertext)
            .map_err(|e| Aes256Error::DecryptionError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Aes256Key;
    use hex_literal::hex;

    #[test]
    fn test_cbc_roundtrip() {
        let key = Aes256Key::from_bytes(&[0x42; 32]).unwrap();
        let cipher = Aes256Cbc::new(&key).unwrap();
        let iv = [0u8; IV_SIZE];

        let plaintext = b"Hello, AES-256-CBC!";
        let ciphertext = cipher.encrypt(&iv, plaintext).unwrap();
        let decrypted = cipher.decrypt(&iv, &ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    /// NIST SP 800-38A Section F.2.5 — AES-256-CBC Encryption
    /// Verifies the first block of CBC encryption against NIST test vectors.
    #[test]
    fn test_nist_sp800_38a_f25_cbc() {
        let key = Aes256Key::from_bytes(&hex!(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        )).unwrap();
        let cipher = Aes256Cbc::new(&key).unwrap();
        let iv = hex!("000102030405060708090a0b0c0d0e0f");

        // NIST SP 800-38A F.2.5: CBC-AES256 encryption, block 1
        let pt = hex!("6bc1bee22e409f96e93d7e117393172a");
        let expected_ct_block1 = hex!("f58c4c04d6e5f1ba779eabfb5f7bfbd6");

        let ct = cipher.encrypt(&iv, &pt).unwrap();
        // CBC with PKCS7 padding adds a padding block, so ct is 32 bytes;
        // the first 16 bytes should match NIST expected ciphertext
        assert_eq!(&ct[..16], &expected_ct_block1[..],
            "NIST SP 800-38A F.2.5 CBC block 1 failed");
    }
}