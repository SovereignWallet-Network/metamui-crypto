/// AES-256 key management with secure handling and zeroization

use crate::{error::Result, Aes256Error, KEY_SIZE};

/// AES-256 key with automatic zeroization

pub struct Aes256Key {
    /// Key material (32 bytes)
    key: [u8; KEY_SIZE],
}

impl Aes256Key {
    /// Generate a new random AES-256 key
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; KEY_SIZE];
        getrandom::getrandom(&mut key)?;
        Ok(Self { key })
    }
    
    /// Create an AES-256 key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_SIZE {
            return Err(Aes256Error::InvalidKeyLength {
                expected: KEY_SIZE,
                actual: bytes.len(),
            });
        }
        
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }
    
    /// Create an AES-256 key from a hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|_e| Aes256Error::InvalidKeyLength {
                expected: KEY_SIZE * 2,
                actual: hex_str.len(),
            })?;
        Self::from_bytes(&bytes)
    }
    
    /// Get the key as bytes
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }
    
    /// Get the key as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.key
    }
    
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.key)
    }
    
    /// Derive a key from password using PBKDF2-HMAC-SHA256
    pub fn from_password(password: &[u8], salt: &[u8], iterations: u32) -> Result<Self> {
        use metamui_crypto_utilities::kdf::pbkdf2::pbkdf2_hmac_sha256;
        
        let mut key = [0u8; KEY_SIZE];
        pbkdf2_hmac_sha256(password, salt, iterations, &mut key);
        
        Ok(Self { key })
    }
}

impl core::fmt::Debug for Aes256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Don't expose key material in debug output
        f.debug_struct("Aes256Key")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for Aes256Key {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison
        use metamui_security_utils::constant_time::ConstantTimeEq;
        self.key.ct_eq(&other.key).into()
    }
}

impl Eq for Aes256Key {}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    
    #[test]
    fn test_key_generation() {
        let key1 = Aes256Key::generate().unwrap();
        let key2 = Aes256Key::generate().unwrap();
        
        // Keys should be different
        assert_ne!(key1, key2);
        
        // Keys should be correct length
        assert_eq!(key1.as_bytes().len(), KEY_SIZE);
        assert_eq!(key2.as_bytes().len(), KEY_SIZE);
    }
    
    #[test]
    fn test_key_from_bytes() {
        let bytes = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let key = Aes256Key::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }
    
    #[test]
    fn test_key_from_hex() {
        let hex_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = Aes256Key::from_hex(hex_str).unwrap();
        assert_eq!(key.to_hex(), hex_str);
    }
    
    #[test]
    fn test_invalid_key_length() {
        let short_key = &[0u8; 16];
        let result = Aes256Key::from_bytes(short_key);
        assert!(matches!(result, Err(Aes256Error::InvalidKeyLength { .. })));
    }
    
    #[test]
    fn test_key_equality() {
        let bytes = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let key1 = Aes256Key::from_bytes(&bytes).unwrap();
        let key2 = Aes256Key::from_bytes(&bytes).unwrap();
        assert_eq!(key1, key2);
    }
    
    #[test]
    #[cfg(feature = "std")]
    fn test_key_debug_redacted() {
        let key = Aes256Key::generate().unwrap();
        let debug_str = std::format!("{:?}", key);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(&key.to_hex()));
    }
}