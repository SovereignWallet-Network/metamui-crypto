/// AES-256-ECB (Electronic Codebook) mode
/// 
/// WARNING: ECB mode is NOT recommended for most use cases as it doesn't provide
/// semantic security. Identical plaintext blocks produce identical ciphertext blocks.
/// Use CBC, GCM, or CTR mode instead.

use crate::{
    error::{Aes256Error, Result},
    key::Aes256Key,
    aes256::Aes256,
};

/// AES-256-ECB cipher (NOT RECOMMENDED for most use cases)
pub struct Aes256Ecb {
    core: Aes256,
}

impl Aes256Ecb {
    /// Create new AES-256-ECB instance
    pub fn new(key: &Aes256Key) -> Result<Self> {
        let core = Aes256::new(key.as_bytes());
        Ok(Self { core })
    }

    /// Encrypt data with AES-256-ECB
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            return Err(Aes256Error::InvalidBlockSize { block_size: 16 });
        }
        
        Ok(self.core.encrypt_ecb(plaintext))
    }

    /// Decrypt data with AES-256-ECB
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
            return Err(Aes256Error::InvalidBlockSize { block_size: 16 });
        }
        
        self.core.decrypt_ecb(ciphertext)
            .map_err(|e| Aes256Error::DecryptionError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Aes256Key;
    use hex_literal::hex;

    #[test]
    fn test_ecb_roundtrip() {
        let key = Aes256Key::from_bytes(&[0x42; 32]).unwrap();
        let cipher = Aes256Ecb::new(&key).unwrap();

        let plaintext = b"Hello, AES-256!!";  // 16 bytes
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    /// NIST FIPS 197 Appendix C.3 — AES-256 ECB test vectors
    /// Key: 603deb10...14dff4
    /// These are the official NIST test vectors for AES-256 single-block encryption.
    #[test]
    fn test_nist_fips197_appendix_c3_ecb() {
        let key = Aes256Key::from_bytes(&hex!(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        )).unwrap();
        let cipher = Aes256Ecb::new(&key).unwrap();

        // Block 1
        let pt1 = hex!("6bc1bee22e409f96e93d7e117393172a");
        let expected_ct1 = hex!("f3eed1bdb5d2a03c064b5a7e3db181f8");
        let ct1 = cipher.encrypt(&pt1).unwrap();
        assert_eq!(&ct1[..16], &expected_ct1[..], "FIPS 197 C.3 block 1 encrypt failed");
        let dec1 = cipher.decrypt(&ct1).unwrap();
        assert_eq!(&dec1[..], &pt1[..], "FIPS 197 C.3 block 1 decrypt failed");

        // Block 2
        let pt2 = hex!("ae2d8a571e03ac9c9eb76fac45af8e51");
        let expected_ct2 = hex!("591ccb10d410ed26dc5ba74a31362870");
        let ct2 = cipher.encrypt(&pt2).unwrap();
        assert_eq!(&ct2[..16], &expected_ct2[..], "FIPS 197 C.3 block 2 encrypt failed");

        // Block 3
        let pt3 = hex!("30c81c46a35ce411e5fbc1191a0a52ef");
        let expected_ct3 = hex!("b6ed21b99ca6f4f9f153e7b1beafed1d");
        let ct3 = cipher.encrypt(&pt3).unwrap();
        assert_eq!(&ct3[..16], &expected_ct3[..], "FIPS 197 C.3 block 3 encrypt failed");

        // Block 4
        let pt4 = hex!("f69f2445df4f9b17ad2b417be66c3710");
        let expected_ct4 = hex!("23304b7a39f9f3ff067d8d8f9e24ecc7");
        let ct4 = cipher.encrypt(&pt4).unwrap();
        assert_eq!(&ct4[..16], &expected_ct4[..], "FIPS 197 C.3 block 4 encrypt failed");
    }
}