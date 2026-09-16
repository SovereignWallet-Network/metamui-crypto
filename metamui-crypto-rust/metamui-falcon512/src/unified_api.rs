//! Unified API for Falcon-512 and Falcon-1024
//! 
//! This module provides a single interface that can work with both
//! Falcon-512 and Falcon-1024 variants.

use crate::error::{Result, Falcon512Error};
use crate::falcon_variants::FalconVariant;
use crate::{falcon1024, PublicKey, PrivateKey};
use alloc::vec::Vec;
use rand::RngCore;

/// Unified public key that can be either Falcon-512 or Falcon-1024
#[derive(Clone, Debug)]
pub enum UnifiedPublicKey {
    Falcon512(PublicKey),
    Falcon1024(falcon1024::PublicKey1024),
}

impl UnifiedPublicKey {
    /// Get the variant of this key
    pub fn variant(&self) -> FalconVariant {
        match self {
            Self::Falcon512(_) => FalconVariant::Falcon512,
            Self::Falcon1024(_) => FalconVariant::Falcon1024,
        }
    }
    
    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Falcon512(pk) => {
                let mut bytes = vec![0x00]; // Variant identifier
                for &coeff in &pk.h.coeffs {
                    bytes.extend_from_slice(&coeff.to_le_bytes());
                }
                bytes
            }
            Self::Falcon1024(pk) => {
                let mut bytes = vec![0x01]; // Variant identifier
                bytes.extend_from_slice(&pk.to_bytes());
                bytes
            }
        }
    }
    
    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Falcon512Error::InvalidPublicKey);
        }
        
        match bytes[0] {
            0x00 => {
                // Falcon-512
                let pk = PublicKey::from_bytes(&bytes[1..])?;
                Ok(Self::Falcon512(pk))
            }
            0x01 => {
                // Falcon-1024
                let pk = falcon1024::PublicKey1024::from_bytes(&bytes[1..])?;
                Ok(Self::Falcon1024(pk))
            }
            _ => Err(Falcon512Error::InvalidPublicKey),
        }
    }
}

/// Unified private key that can be either Falcon-512 or Falcon-1024
#[derive(Clone, Debug)]
pub enum UnifiedPrivateKey {
    Falcon512(PrivateKey),
    Falcon1024(falcon1024::PrivateKey1024),
}

impl Drop for UnifiedPrivateKey {
    fn drop(&mut self) {
        match self {
            Self::Falcon512(sk) => {
                // Falcon512 PrivateKey already implements Drop
            }
            Self::Falcon1024(sk) => {
                // Falcon1024 PrivateKey1024 already implements Drop
            }
        }
    }
}

impl UnifiedPrivateKey {
    /// Get the variant of this key
    pub fn variant(&self) -> FalconVariant {
        match self {
            Self::Falcon512(_) => FalconVariant::Falcon512,
            Self::Falcon1024(_) => FalconVariant::Falcon1024,
        }
    }
}

/// Unified key pair
#[derive(Clone, Debug)]
pub struct UnifiedKeyPair {
    pub public_key: UnifiedPublicKey,
    pub private_key: UnifiedPrivateKey,
}

/// Generate a key pair for the specified variant
pub fn generate_keypair_variant<R: RngCore + Send>(
    variant: FalconVariant,
    rng: &mut R,
) -> Result<UnifiedKeyPair> {
    match variant {
        FalconVariant::Falcon512 => {
            let keypair = crate::generate_keypair(rng)?;
            Ok(UnifiedKeyPair {
                public_key: UnifiedPublicKey::Falcon512(keypair.public_key),
                private_key: UnifiedPrivateKey::Falcon512(keypair.private_key),
            })
        }
        FalconVariant::Falcon1024 => {
            let keypair = falcon1024::generate_keypair_1024(rng)?;
            Ok(UnifiedKeyPair {
                public_key: UnifiedPublicKey::Falcon1024(keypair.public_key),
                private_key: UnifiedPrivateKey::Falcon1024(keypair.private_key),
            })
        }
    }
}

/// Sign a message with the appropriate variant
pub fn sign_variant<R: RngCore + Send>(
    message: &[u8],
    private_key: &UnifiedPrivateKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    match private_key {
        UnifiedPrivateKey::Falcon512(sk) => {
            crate::sign(message, sk, rng)
        }
        UnifiedPrivateKey::Falcon1024(sk) => {
            falcon1024::sign_1024(message, sk, rng)
        }
    }
}

/// Verify a signature with the appropriate variant
pub fn verify_variant(
    message: &[u8],
    signature: &[u8],
    public_key: &UnifiedPublicKey,
) -> Result<bool> {
    // Determine variant from signature header
    if signature.is_empty() {
        return Ok(false);
    }
    
    match (signature[0], public_key) {
        (0x39, UnifiedPublicKey::Falcon512(pk)) => {
            crate::verify(message, signature, pk)
        }
        (0x3A, UnifiedPublicKey::Falcon1024(pk)) => {
            falcon1024::verify_1024(message, signature, pk)
        }
        _ => Ok(false), // Mismatched variant
    }
}

/// Auto-detect variant from signature and verify
pub fn verify_auto(
    message: &[u8],
    signature: &[u8],
    public_key_bytes: &[u8],
) -> Result<bool> {
    if signature.is_empty() {
        return Ok(false);
    }
    
    // Detect variant from signature header
    let variant = match signature[0] {
        0x39 => FalconVariant::Falcon512,
        0x3A => FalconVariant::Falcon1024,
        _ => return Ok(false),
    };
    
    // Parse public key for the detected variant
    let public_key = match variant {
        FalconVariant::Falcon512 => {
            let pk = PublicKey::from_bytes(public_key_bytes)?;
            UnifiedPublicKey::Falcon512(pk)
        }
        FalconVariant::Falcon1024 => {
            let pk = falcon1024::PublicKey1024::from_bytes(public_key_bytes)?;
            UnifiedPublicKey::Falcon1024(pk)
        }
    };
    
    verify_variant(message, signature, &public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    
    #[test]
    fn test_unified_falcon512() {
        let mut rng = ChaCha20Rng::from_seed([44u8; 32]);
        let keypair = generate_keypair_variant(FalconVariant::Falcon512, &mut rng)
            .expect("Key generation should succeed");
        
        assert_eq!(keypair.public_key.variant(), FalconVariant::Falcon512);
        assert_eq!(keypair.private_key.variant(), FalconVariant::Falcon512);
        
        let message = b"Test unified API with Falcon-512";
        let signature = sign_variant(message, &keypair.private_key, &mut rng)
            .expect("Signing should succeed");
        
        assert_eq!(signature[0], 0x39); // Falcon-512 header
        
        let valid = verify_variant(message, &signature, &keypair.public_key)
            .expect("Verification should succeed");
        assert!(valid);
    }
    
    #[test]
    fn test_unified_falcon1024() {
        let mut rng = ChaCha20Rng::from_seed([45u8; 32]);
        let keypair = generate_keypair_variant(FalconVariant::Falcon1024, &mut rng)
            .expect("Key generation should succeed");
        
        assert_eq!(keypair.public_key.variant(), FalconVariant::Falcon1024);
        assert_eq!(keypair.private_key.variant(), FalconVariant::Falcon1024);
        
        let message = b"Test unified API with Falcon-1024";
        let signature = sign_variant(message, &keypair.private_key, &mut rng)
            .expect("Signing should succeed");
        
        assert_eq!(signature[0], 0x3A); // Falcon-1024 header
        
        let valid = verify_variant(message, &signature, &keypair.public_key)
            .expect("Verification should succeed");
        assert!(valid);
    }
    
    #[test]
    fn test_cross_variant_rejection() {
        let mut rng = ChaCha20Rng::from_seed([46u8; 32]);
        
        // Generate Falcon-512 key pair
        let keypair_512 = generate_keypair_variant(FalconVariant::Falcon512, &mut rng)
            .expect("Key generation should succeed");
        
        // Generate Falcon-1024 key pair  
        let keypair_1024 = generate_keypair_variant(FalconVariant::Falcon1024, &mut rng)
            .expect("Key generation should succeed");
        
        let message = b"Test cross-variant";
        
        // Sign with Falcon-512
        let sig_512 = sign_variant(message, &keypair_512.private_key, &mut rng)
            .expect("Signing should succeed");
        
        // Try to verify Falcon-512 signature with Falcon-1024 key (should fail)
        let invalid = verify_variant(message, &sig_512, &keypair_1024.public_key)
            .expect("Verification should succeed");
        assert!(!invalid, "Cross-variant verification should fail");
    }
}