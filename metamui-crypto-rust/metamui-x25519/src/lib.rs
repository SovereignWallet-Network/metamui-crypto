// MetaMUI metamui x25519
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


use thiserror::Error;
use serde::{Serialize, Deserialize};
use rand::rngs::OsRng;
use rand::RngCore;

mod x25519;

/// X25519 error types
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum X25519Error {
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    
    #[error("Invalid key material: {0}")]
    InvalidKey(String),
    
    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),
    
    #[error("Random generation failed: {0}")]
    RandomGenerationFailed(String),
    
    #[error("Hex decoding error: {0}")]
    HexDecodingError(String),
}

impl From<hex::FromHexError> for X25519Error {
    fn from(e: hex::FromHexError) -> Self {
        X25519Error::HexDecodingError(e.to_string())
    }
}

/// X25519 key pair structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// X25519 shared secret structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedSecret {
    pub bytes: Vec<u8>,
}

/// X25519 key exchange implementation
pub struct MetaMUIX25519;

impl MetaMUIX25519 {
    /// Generate a new X25519 key pair
    pub fn generate_keypair() -> Result<KeyPair, X25519Error> {
        let mut random_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut random_bytes);
        
        let (public_key, private_key) = x25519::native_x25519_keypair(&random_bytes);
        
        Ok(KeyPair {
            public_key: public_key.to_vec(),
            private_key: private_key.to_vec(),
        })
    }
    
    /// Create a key pair from a private key seed
    pub fn keypair_from_seed(seed: &[u8]) -> Result<KeyPair, X25519Error> {
        if seed.len() != 32 {
            return Err(X25519Error::InvalidPrivateKey("Private key must be 32 bytes".to_string()));
        }
        
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed);
        
        let (public_key, private_key) = x25519::native_x25519_keypair(&seed_array);
        
        Ok(KeyPair {
            public_key: public_key.to_vec(),
            private_key: private_key.to_vec(),
        })
    }
    
    /// Get public key from private key
    pub fn public_key_from_private(private_key: &[u8]) -> Result<Vec<u8>, X25519Error> {
        if private_key.len() != 32 {
            return Err(X25519Error::InvalidPrivateKey("Private key must be 32 bytes".to_string()));
        }
        
        let mut private_key_array = [0u8; 32];
        private_key_array.copy_from_slice(private_key);
        
        let (public_key, _) = x25519::native_x25519_keypair(&private_key_array);
        
        Ok(public_key.to_vec())
    }
    
    /// Perform X25519 key exchange
    pub fn key_exchange(
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<SharedSecret, X25519Error> {
        if private_key.len() != 32 {
            return Err(X25519Error::InvalidPrivateKey("Private key must be 32 bytes".to_string()));
        }
        
        if public_key.len() != 32 {
            return Err(X25519Error::InvalidPublicKey("Public key must be 32 bytes".to_string()));
        }
        
        let mut private_key_array = [0u8; 32];
        private_key_array.copy_from_slice(private_key);
        
        let mut public_key_array = [0u8; 32];
        public_key_array.copy_from_slice(public_key);
        
        let shared_secret = x25519::native_x25519_diffie_hellman(&private_key_array, &public_key_array);
        
        // Check for weak keys (all-zero shared secret)
        if shared_secret == [0u8; 32] {
            return Err(X25519Error::KeyExchangeFailed("Weak public key detected".to_string()));
        }
        
        Ok(SharedSecret {
            bytes: shared_secret.to_vec(),
        })
    }
    
    /// Validate a private key
    pub fn is_valid_private_key(private_key: &[u8]) -> bool {
        private_key.len() == 32
    }
    
    /// Validate a public key
    pub fn is_valid_public_key(public_key: &[u8]) -> bool {
        if public_key.len() != 32 {
            return false;
        }
        
        #[cfg(not(feature = "native"))]
        {
            // Check if it's a valid point on the curve
            let key_array: [u8; 32] = match public_key.try_into() {
                Ok(arr) => arr,
                Err(_) => return false,
            };
            let point = MontgomeryPoint(key_array);
            
            // Montgomery points are always valid in curve25519-dalek, but we check for weak keys
            point.as_bytes() != &[0u8; 32] && 
            point.as_bytes() != &[1u8; 32] &&
            point.as_bytes()[31] < 128 // Valid coordinate
        }
        
        #[cfg(feature = "native")]
        {
            // Check for weak keys
            public_key != &[0u8; 32] && 
            public_key != &[1u8; 32] &&
            public_key[31] < 128 // Valid coordinate
        }
    }
    
    /// Validate a shared secret
    pub fn is_valid_shared_secret(shared_secret: &[u8]) -> bool {
        shared_secret.len() == 32 && shared_secret != &[0u8; 32]
    }
}

/// Simple function-based API
/// Generate a new X25519 key pair
pub fn generate_keypair() -> Result<KeyPair, X25519Error> {
    MetaMUIX25519::generate_keypair()
}

/// Create key pair from seed
pub fn keypair_from_seed(seed: Vec<u8>) -> Result<KeyPair, X25519Error> {
    MetaMUIX25519::keypair_from_seed(&seed)
}

/// Get public key from private key
pub fn public_key_from_private(private_key: Vec<u8>) -> Result<Vec<u8>, X25519Error> {
    MetaMUIX25519::public_key_from_private(&private_key)
}

/// Perform X25519 key exchange
pub fn key_exchange(
    private_key: Vec<u8>,
    public_key: Vec<u8>,
) -> Result<Vec<u8>, X25519Error> {
    let shared_secret = MetaMUIX25519::key_exchange(&private_key, &public_key)?;
    Ok(shared_secret.bytes)
}

/// Validate a private key
pub fn is_valid_private_key(private_key: &[u8]) -> bool {
    MetaMUIX25519::is_valid_private_key(private_key)
}

/// Validate a public key
pub fn is_valid_public_key(public_key: &[u8]) -> bool {
    MetaMUIX25519::is_valid_public_key(public_key)
}

/// Validate a shared secret
pub fn is_valid_shared_secret(shared_secret: &[u8]) -> bool {
    MetaMUIX25519::is_valid_shared_secret(shared_secret)
}

/// Utility functions
/// Format bytes as hex string with 0x prefix
pub fn format_hex(bytes: Vec<u8>) -> String {
    format!("0x{}", hex::encode(&bytes))
}

/// Parse hex string (with or without 0x prefix) to bytes
pub fn parse_hex(hex_str: String) -> Result<Vec<u8>, X25519Error> {
    let cleaned = if hex_str.starts_with("0x") {
        &hex_str[2..]
    } else {
        &hex_str
    };
    
    hex::decode(cleaned).map_err(X25519Error::from)
}

/// Hex versions of main functions
pub fn generate_keypair_hex() -> Result<(String, String), X25519Error> {
    let keypair = generate_keypair()?;
    Ok((
        format_hex(keypair.public_key),
        format_hex(keypair.private_key),
    ))
}

pub fn keypair_from_seed_hex(seed_hex: String) -> Result<(String, String), X25519Error> {
    let seed = parse_hex(seed_hex)?;
    let keypair = keypair_from_seed(seed)?;
    Ok((
        format_hex(keypair.public_key),
        format_hex(keypair.private_key),
    ))
}

pub fn public_key_from_private_hex(private_key_hex: String) -> Result<String, X25519Error> {
    let private_key = parse_hex(private_key_hex)?;
    let public_key = public_key_from_private(private_key)?;
    Ok(format_hex(public_key))
}

pub fn key_exchange_hex(
    private_key_hex: String,
    public_key_hex: String,
) -> Result<String, X25519Error> {
    let private_key = parse_hex(private_key_hex)?;
    let public_key = parse_hex(public_key_hex)?;
    let shared_secret = key_exchange(private_key, public_key)?;
    Ok(format_hex(shared_secret))
}

pub fn is_valid_private_key_hex(private_key_hex: &str) -> bool {
    match parse_hex(private_key_hex.to_string()) {
        Ok(bytes) => is_valid_private_key(&bytes),
        Err(_) => false,
    }
}

pub fn is_valid_public_key_hex(public_key_hex: &str) -> bool {
    match parse_hex(public_key_hex.to_string()) {
        Ok(bytes) => is_valid_public_key(&bytes),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair().unwrap();
        assert_eq!(keypair.public_key.len(), 32);
        assert_eq!(keypair.private_key.len(), 32);
    }
    
    #[test]
    fn test_deterministic_keypair() {
        let seed = [42u8; 32];
        
        let keypair1 = keypair_from_seed(seed.to_vec()).unwrap();
        let keypair2 = keypair_from_seed(seed.to_vec()).unwrap();
        
        assert_eq!(keypair1.public_key, keypair2.public_key);
        assert_eq!(keypair1.private_key, keypair2.private_key);
    }
    
    #[test]
    fn test_public_key_derivation() {
        let keypair = generate_keypair().unwrap();
        let derived_public = public_key_from_private(keypair.private_key.clone()).unwrap();
        
        assert_eq!(keypair.public_key, derived_public);
    }
    
    #[test]
    fn test_key_exchange() {
        let alice_keypair = generate_keypair().unwrap();
        let bob_keypair = generate_keypair().unwrap();
        
        let alice_shared = key_exchange(
            alice_keypair.private_key.clone(),
            bob_keypair.public_key.clone(),
        ).unwrap();
        
        let bob_shared = key_exchange(
            bob_keypair.private_key.clone(),
            alice_keypair.public_key.clone(),
        ).unwrap();
        
        assert_eq!(alice_shared, bob_shared);
        assert_eq!(alice_shared.len(), 32);
    }
    
    #[test]
    fn test_key_validation() {
        let keypair = generate_keypair().unwrap();
        
        assert!(is_valid_private_key(&keypair.private_key));
        assert!(is_valid_public_key(&keypair.public_key));
        
        // Test invalid keys
        assert!(!is_valid_private_key(&[0u8; 31])); // Wrong length
        assert!(!is_valid_public_key(&[0u8; 31])); // Wrong length
        assert!(!is_valid_public_key(&[0u8; 32])); // All zeros
    }
    
    #[test]
    fn test_hex_functions() {
        let keypair = generate_keypair().unwrap();
        let hex_private = format_hex(keypair.private_key.clone());
        let hex_public = format_hex(keypair.public_key.clone());
        
        assert!(hex_private.starts_with("0x"));
        assert!(hex_public.starts_with("0x"));
        
        let parsed_private = parse_hex(hex_private).unwrap();
        assert_eq!(parsed_private, keypair.private_key);
    }
    
    #[test]
    fn test_rfc7748_test_vector() {
        // RFC 7748 test vector
        let alice_private = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
        let alice_public = hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a").unwrap();
        let bob_public = hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f").unwrap();
        let expected_shared = hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742").unwrap();
        
        // Verify Alice's public key
        let derived_alice_public = public_key_from_private(alice_private.clone()).unwrap();
        assert_eq!(derived_alice_public, alice_public);
        
        // Perform key exchange
        let shared_secret = key_exchange(alice_private, bob_public).unwrap();
        assert_eq!(shared_secret, expected_shared);
    }
    
    #[test]
    fn test_weak_public_key_rejection() {
        let private_key = [1u8; 32];
        let weak_public_key = [0u8; 32]; // All-zero public key
        
        let result = key_exchange(private_key.to_vec(), weak_public_key.to_vec());
        assert!(result.is_err());
    }
}
