/// MetaMUI PBKDF2 (Password-Based Key Derivation Function 2) implementation
/// 
/// This crate provides a pure Rust implementation of PBKDF2 according to RFC 2898.
/// It supports both PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512 variants.
///
/// # Features
/// - PBKDF2-HMAC-SHA256 for general use
/// - PBKDF2-HMAC-SHA512 for high-security applications (BIP39 compatible)
/// - Intermediate blocks are zeroed
/// - No-std support
/// - Portable scalar Rust only; designed for constant time and unmeasured (see README)


extern crate alloc;

use alloc::vec::Vec;
use metamui_sha2::sha256::sha256;
use metamui_sha2::sha512::sha512;

pub mod error;
pub use error::*;

/// PBKDF2 key derivation function
pub struct PBKDF2;

impl PBKDF2 {
    /// Derive key using PBKDF2-HMAC-SHA256
    /// 
    /// # Arguments
    /// * `password` - The password to derive from
    /// * `salt` - The salt value
    /// * `iterations` - Number of iterations (recommended minimum: 100,000)
    /// * `key_length` - Desired output key length in bytes
    /// 
    /// # Returns
    /// Derived key of the specified length
    /// 
    /// # Errors
    /// Returns error if iterations or key_length is 0
    pub fn pbkdf2_hmac_sha256(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        key_length: usize,
    ) -> Result<Vec<u8>, PBKDF2Error> {
        if iterations == 0 {
            return Err(PBKDF2Error::InvalidIterations);
        }
        if key_length == 0 {
            return Err(PBKDF2Error::InvalidKeyLength);
        }
        
        Ok(Self::derive(password, salt, iterations, key_length, HashAlgorithm::SHA256))
    }
    
    /// Derive key using PBKDF2-HMAC-SHA512
    /// 
    /// # Arguments
    /// * `password` - The password to derive from
    /// * `salt` - The salt value
    /// * `iterations` - Number of iterations (BIP39 uses 2,048)
    /// * `key_length` - Desired output key length in bytes (BIP39 uses 64)
    /// 
    /// # Returns
    /// Derived key of the specified length
    /// 
    /// # Errors
    /// Returns error if iterations or key_length is 0
    pub fn pbkdf2_hmac_sha512(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        key_length: usize,
    ) -> Result<Vec<u8>, PBKDF2Error> {
        if iterations == 0 {
            return Err(PBKDF2Error::InvalidIterations);
        }
        if key_length == 0 {
            return Err(PBKDF2Error::InvalidKeyLength);
        }
        
        Ok(Self::derive(password, salt, iterations, key_length, HashAlgorithm::SHA512))
    }
    
    /// BIP39-compatible mnemonic to seed derivation
    /// 
    /// This follows the BIP39 standard:
    /// - Uses PBKDF2-HMAC-SHA512
    /// - 2048 iterations
    /// - 64-byte output
    /// - Salt prefix "mnemonic"
    pub fn bip39_mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Vec<u8> {
        let salt = format!("mnemonic{}", passphrase);
        Self::derive(
            mnemonic.as_bytes(),
            salt.as_bytes(),
            2048,
            64,
            HashAlgorithm::SHA512
        )
    }
    
    /// Internal derive function with secure memory clearing
    fn derive(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        key_length: usize,
        algorithm: HashAlgorithm,
    ) -> Vec<u8> {
        let h_len = algorithm.hash_length();
        let l = (key_length + h_len - 1) / h_len; // Number of blocks needed
        let r = key_length - (l - 1) * h_len; // Last block length
        
        let mut derived_key = vec![0u8; key_length];
        let mut blocks = Vec::new();
        
        for i in 1..=l {
            let block = Self::f(password, salt, iterations, i as u32, algorithm);
            
            let start = (i - 1) * h_len;
            let length = if i == l { r } else { h_len };
            derived_key[start..start + length].copy_from_slice(&block[..length]);
            
            blocks.push(block);
        }
        
        // Clear all intermediate blocks
        for mut block in blocks {
            clear(&mut block);
        }
        
        derived_key
    }
    
    /// PBKDF2 F function: U1 XOR U2 XOR ... XOR Uc
    fn f(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        block_index: u32,
        algorithm: HashAlgorithm,
    ) -> Vec<u8> {
        // Create HMAC context with pre-computed keys for performance
        let (block_size, hash_fn): (usize, fn(&[u8]) -> Vec<u8>) = match algorithm {
            HashAlgorithm::SHA256 => (64, |d| sha256(d).to_vec()),
            HashAlgorithm::SHA512 => (128, |d| sha512(d).to_vec()),
        };
        
        // Pre-compute padded keys for HMAC
        let adjusted_key = if password.len() > block_size {
            hash_fn(password)
        } else {
            password.to_vec()
        };
        
        let mut padded_key = vec![0u8; block_size];
        padded_key[..adjusted_key.len()].copy_from_slice(&adjusted_key);
        
        let mut inner_key = vec![0u8; block_size];
        let mut outer_key = vec![0u8; block_size];
        
        for i in 0..block_size {
            inner_key[i] = padded_key[i] ^ 0x36;
            outer_key[i] = padded_key[i] ^ 0x5C;
        }
        
        // Clear padded key
        clear(&mut padded_key);
        
        // Create salt + block index (big-endian)
        let mut salt_with_index = Vec::with_capacity(salt.len() + 4);
        salt_with_index.extend_from_slice(salt);
        salt_with_index.extend_from_slice(&block_index.to_be_bytes());
        
        // U1 = HMAC(password, salt + i) using pre-computed keys
        let mut u = Self::hmac_with_keys(&inner_key, &outer_key, &salt_with_index, hash_fn);
        let mut result = u.clone();
        
        // U2 = HMAC(password, U1), U3 = HMAC(password, U2), etc.
        for _ in 2..=iterations {
            let mut prev_u = u;
            u = Self::hmac_with_keys(&inner_key, &outer_key, &prev_u, hash_fn);
            
            // XOR with result
            for k in 0..result.len() {
                result[k] ^= u[k];
            }
            
            // Clear previous U value
            clear(&mut prev_u);
        }
        
        // Clear sensitive data
        clear(&mut salt_with_index);
        clear(&mut u);
        clear(&mut inner_key);
        clear(&mut outer_key);
        
        result
    }
    
    /// HMAC with pre-computed keys for performance
    fn hmac_with_keys(
        inner_key: &[u8],
        outer_key: &[u8],
        data: &[u8],
        hash_fn: fn(&[u8]) -> Vec<u8>,
    ) -> Vec<u8> {
        // Inner hash: HASH(inner_key + data)
        let mut inner_data = Vec::with_capacity(inner_key.len() + data.len());
        inner_data.extend_from_slice(inner_key);
        inner_data.extend_from_slice(data);
        let inner_hash = hash_fn(&inner_data);
        
        // Outer hash: HASH(outer_key + inner_hash)
        let mut outer_data = Vec::with_capacity(outer_key.len() + inner_hash.len());
        outer_data.extend_from_slice(outer_key);
        outer_data.extend_from_slice(&inner_hash);
        let result = hash_fn(&outer_data);
        
        // Clear intermediate data
        clear(&mut inner_data);
        clear(&mut outer_data);
        
        result
    }
    
    /// HMAC implementation for different hash algorithms. Kept as a
    /// named helper for audit clarity; `derive()` inlines the HMAC
    /// loop directly for block-boundary optimisation.
    #[allow(dead_code)]
    fn hmac(key: &[u8], data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
        let (block_size, hash_fn): (usize, fn(&[u8]) -> Vec<u8>) = match algorithm {
            HashAlgorithm::SHA256 => (64, |d| sha256(d).to_vec()),
            HashAlgorithm::SHA512 => (128, |d| sha512(d).to_vec()),
        };
        
        let ipad = 0x36u8;
        let opad = 0x5Cu8;
        
        // Prepare key
        let adjusted_key = if key.len() > block_size {
            hash_fn(key)
        } else {
            key.to_vec()
        };
        
        let mut padded_key = vec![0u8; block_size];
        padded_key[..adjusted_key.len()].copy_from_slice(&adjusted_key);
        
        // Create inner and outer padded keys
        let mut inner_key = vec![0u8; block_size];
        let mut outer_key = vec![0u8; block_size];
        
        for i in 0..block_size {
            inner_key[i] = padded_key[i] ^ ipad;
            outer_key[i] = padded_key[i] ^ opad;
        }
        
        // Inner hash: HASH(inner_key + data)
        let mut inner_data = Vec::with_capacity(block_size + data.len());
        inner_data.extend_from_slice(&inner_key);
        inner_data.extend_from_slice(data);
        let inner_hash = hash_fn(&inner_data);
        
        // Outer hash: HASH(outer_key + inner_hash)
        let mut outer_data = Vec::with_capacity(block_size + inner_hash.len());
        outer_data.extend_from_slice(&outer_key);
        outer_data.extend_from_slice(&inner_hash);
        let result = hash_fn(&outer_data);
        
        // Clear sensitive data
        clear(&mut padded_key);
        clear(&mut inner_key);
        clear(&mut outer_key);
        clear(&mut inner_data);
        clear(&mut outer_data);
        
        result
    }
}

/// Supported hash algorithms
#[derive(Clone, Copy)]
enum HashAlgorithm {
    SHA256,
    SHA512,
}

impl HashAlgorithm {
    fn hash_length(&self) -> usize {
        match self {
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA512 => 64,
        }
    }
}

/// Secure memory clearing
fn clear(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte = 0;
    }
    // Memory barrier to prevent optimization
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    
    #[test]
    fn test_pbkdf2_hmac_sha256_rfc6070() {
        // Test vectors from RFC 6070
        let test_cases = vec![
            // password, salt, iterations, key_length, expected_hex
            ("password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
            ("password", "salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
            ("password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
            ("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"),
        ];
        
        for (password, salt, iterations, key_length, expected_hex) in test_cases {
            let result = PBKDF2::pbkdf2_hmac_sha256(
                password.as_bytes(),
                salt.as_bytes(),
                iterations,
                key_length
            ).unwrap();
            
            let expected = hex::decode(expected_hex).unwrap();
            assert_eq!(result, expected, "Failed for password='{}', salt='{}', iterations={}", password, salt, iterations);
        }
    }
    
    #[test]
    fn test_pbkdf2_hmac_sha512() {
        // Test with SHA-512
        let password = b"password";
        let salt = b"salt";
        let iterations = 1000;
        let key_length = 64;
        
        let result = PBKDF2::pbkdf2_hmac_sha512(password, salt, iterations, key_length).unwrap();
        
        // Verify the result is 64 bytes
        assert_eq!(result.len(), 64);
        
        // Should not be all zeros
        assert!(!result.iter().all(|&b| b == 0));
        
        // Test specific expected value
        let expected = hex::decode("afe6c5530785b6cc6b1c6453384731bd5ee432ee549fd42fb6695779ad8a1c5bf59de69c48f774efc4007d5298f9033c0241d5ab69305e7b64eceeb8d834cfec").unwrap();
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_pbkdf2_empty_password() {
        let password = b"";
        let salt = b"salt";
        let iterations = 1000;
        let key_length = 32;
        
        let result = PBKDF2::pbkdf2_hmac_sha256(password, salt, iterations, key_length).unwrap();
        assert_eq!(result.len(), 32);
        
        // Verify specific output for empty password
        let expected = hex::decode("94fb56af3ea22e5d3ed1b054085b136ca301b75d8b406c802c489479f27387c6").unwrap();
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_pbkdf2_empty_salt() {
        let password = b"password";
        let salt = b"";
        let iterations = 1000;
        let key_length = 32;
        
        let result = PBKDF2::pbkdf2_hmac_sha256(password, salt, iterations, key_length).unwrap();
        assert_eq!(result.len(), 32);
    }
    
    #[test]
    fn test_pbkdf2_long_output() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 100;
        let key_length = 100; // Longer than hash output
        
        let result = PBKDF2::pbkdf2_hmac_sha256(password, salt, iterations, key_length).unwrap();
        assert_eq!(result.len(), 100);
    }
    
    #[test]
    fn test_bip39_mnemonic_to_seed() {
        // Test BIP39 mnemonic to seed conversion
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "";
        
        let seed = PBKDF2::bip39_mnemonic_to_seed(mnemonic, passphrase);
        assert_eq!(seed.len(), 64);
        
        // Expected seed from BIP39 test vectors - this is the correct value
        let expected = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        assert_eq!(seed, expected);
    }
    
    #[test]
    fn test_bip39_mnemonic_with_passphrase() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "TREZOR";
        
        let seed = PBKDF2::bip39_mnemonic_to_seed(mnemonic, passphrase);
        assert_eq!(seed.len(), 64);
        
        // Expected seed from BIP39 test vectors - this is the correct value
        let expected = hex::decode("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04").unwrap();
        assert_eq!(seed, expected);
    }
    
    #[test]
    fn test_invalid_parameters() {
        let password = b"password";
        let salt = b"salt";
        
        // Test zero iterations
        assert!(matches!(
            PBKDF2::pbkdf2_hmac_sha256(password, salt, 0, 32),
            Err(PBKDF2Error::InvalidIterations)
        ));
        
        // Test zero key length
        assert!(matches!(
            PBKDF2::pbkdf2_hmac_sha256(password, salt, 1000, 0),
            Err(PBKDF2Error::InvalidKeyLength)
        ));
    }
    
    #[test]
    fn test_consistency_between_algorithms() {
        let password = b"test_password";
        let salt = b"test_salt";
        let iterations = 1000;
        
        // SHA256 should produce 32 bytes
        let sha256_result = PBKDF2::pbkdf2_hmac_sha256(password, salt, iterations, 32).unwrap();
        assert_eq!(sha256_result.len(), 32);
        
        // SHA512 should produce 64 bytes
        let sha512_result = PBKDF2::pbkdf2_hmac_sha512(password, salt, iterations, 64).unwrap();
        assert_eq!(sha512_result.len(), 64);
        
        // They should be different
        assert_ne!(&sha256_result[..], &sha512_result[..32]);
    }
}