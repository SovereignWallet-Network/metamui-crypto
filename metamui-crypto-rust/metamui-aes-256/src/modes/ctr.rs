/// AES-256-CTR (Counter) mode - Stream cipher mode

use crate::{
    error::Result,
    key::Aes256Key,
    aes256::Aes256,
    IV_SIZE,
};

/// AES-256-CTR stream cipher
pub struct Aes256CtrCipher {
    core: Aes256,
}

impl Aes256CtrCipher {
    /// Create new AES-256-CTR instance
    pub fn new(key: &Aes256Key) -> Result<Self> {
        let core = Aes256::new(key.as_bytes());
        Ok(Self { core })
    }
    
    /// Process data (encrypt or decrypt - CTR mode is symmetric)
    pub fn process(&self, nonce: &[u8; IV_SIZE], data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        
        Ok(self.core.process_ctr(nonce, data))
    }
    
    /// Encrypt data with AES-256-CTR
    pub fn encrypt(&self, nonce: &[u8; IV_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.process(nonce, plaintext)
    }
    
    /// Decrypt data with AES-256-CTR (same as encrypt for CTR mode)
    pub fn decrypt(&self, nonce: &[u8; IV_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.process(nonce, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Aes256Key;
    use hex_literal::hex;

    #[test]
    fn test_ctr_roundtrip() {
        let key = Aes256Key::from_bytes(&[0x42; 32]).unwrap();
        let cipher = Aes256CtrCipher::new(&key).unwrap();
        let nonce = [0u8; IV_SIZE];

        let plaintext = b"Hello, AES-256-CTR! This is a test message.";
        let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_ctr_stream_property() {
        let key = Aes256Key::from_bytes(&[0x42; 32]).unwrap();
        let cipher = Aes256CtrCipher::new(&key).unwrap();
        let nonce = [0u8; IV_SIZE];

        // CTR mode should produce same result when applied twice
        let data = b"Stream cipher test";
        let once = cipher.process(&nonce, data).unwrap();
        let twice = cipher.process(&nonce, &once).unwrap();

        assert_eq!(data, &twice[..]);
    }

    /// NIST SP 800-38A Section F.5.5 — AES-256-CTR Encryption
    /// Verifies the first block of CTR encryption against NIST test vectors.
    #[test]
    fn test_nist_sp800_38a_f55_ctr() {
        let key = Aes256Key::from_bytes(&hex!(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        )).unwrap();
        let cipher = Aes256CtrCipher::new(&key).unwrap();

        // NIST SP 800-38A F.5.5: Initial counter = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
        let init_counter = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

        // Block 1: PT -> expected CT
        let pt1 = hex!("6bc1bee22e409f96e93d7e117393172a");
        let expected_ct1 = hex!("601ec313775789a5b7a7f504bbf3d228");

        let ct = cipher.encrypt(&init_counter, &pt1).unwrap();
        assert_eq!(&ct[..16], &expected_ct1[..],
            "NIST SP 800-38A F.5.5 CTR block 1 failed");
    }
}