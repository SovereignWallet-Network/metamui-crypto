//! Main Falcon512 implementation
//! 
//! IMPORTANT: Falcon signatures are NON-DETERMINISTIC by design.
//! Each signature includes a random nonce and uses Gaussian sampling.
//! This means the same message signed twice will produce different signatures.
//! This is CORRECT behavior and required for security.

use crate::constants::N;
use crate::error::{Result, Falcon512Error};
use crate::falcon_complete;
use rand::RngCore;
use alloc::vec::Vec;

// Re-export types from the root module to avoid duplication
pub use crate::{PublicKey, PrivateKey, KeyPair};

/// Generate a Falcon512 key pair
/// 
/// This may require multiple attempts due to rejection sampling.
/// This is NORMAL behavior for lattice-based cryptography.
pub fn generate_keypair<R: RngCore + Send>(rng: &mut R) -> Result<KeyPair> {
    // Use the complete implementation with proper NTRU solving
    let (pk, sk) = falcon_complete::keygen_complete_simple(rng)?;
    
    Ok(KeyPair {
        public_key: pk,
        private_key: sk,
    })
}

/// Sign a message with Falcon-512
/// 
/// # Important: Non-Deterministic Behavior
/// 
/// This function generates a DIFFERENT signature each time it's called,
/// even with the same message and key. This is CORRECT and REQUIRED
/// for security. The signature includes a random 40-byte nonce.
/// 
/// The function may need to retry internally due to rejection sampling.
/// This is NORMAL behavior for lattice-based signatures.
pub fn sign<R: RngCore>(
    message: &[u8],
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    // Use the complete signing implementation with:
    // - Random nonce generation
    // - Discrete Gaussian sampling  
    // - Proper norm checking
    // - Signature compression
    falcon_complete::sign_complete(message, private_key, rng)
}

/// Verify a Falcon-512 signature
/// 
/// Verifies that the signature was created by the holder of the
/// private key corresponding to the given public key.
pub fn verify(
    message: &[u8],
    signature: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    // Use the complete verification with:
    // - Proper decompression
    // - Equation checking: z0 = c - h*z1 (mod q)
    // - Norm bound verification
    falcon_complete::verify_complete(message, signature, public_key)
}

/// Falcon512 struct for compatibility
pub struct Falcon512;

impl Falcon512 {
    pub fn keygen<R: RngCore + Send>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
        let keypair = generate_keypair(rng)?;
        
        // Serialize public key
        let mut pk = Vec::with_capacity(N * 2);
        for &coeff in keypair.public_key.h.coeffs.iter() {
            pk.extend_from_slice(&coeff.to_le_bytes());
        }
        
        // Serialize private key
        let mut sk = Vec::with_capacity(N * 8);
        for &coeff in keypair.private_key.f.coeffs.iter() {
            sk.extend_from_slice(&coeff.to_le_bytes());
        }
        for &coeff in keypair.private_key.g.coeffs.iter() {
            sk.extend_from_slice(&coeff.to_le_bytes());
        }
        for &coeff in keypair.private_key.big_f.coeffs.iter() {
            sk.extend_from_slice(&coeff.to_le_bytes());
        }
        for &coeff in keypair.private_key.big_g.coeffs.iter() {
            sk.extend_from_slice(&coeff.to_le_bytes());
        }
        
        Ok((pk, sk))
    }
    
    pub fn sign<R: RngCore>(_message: &[u8], _private_key: &[u8], _rng: &mut R) -> Result<Vec<u8>> {
        Err(Falcon512Error::NotImplemented)
    }
    
    pub fn verify(_message: &[u8], _signature: &[u8], _public_key: &[u8]) -> Result<bool> {
        Err(Falcon512Error::NotImplemented)
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn byte_surface_fails_closed() {
        let mut rng = thread_rng();

        match Falcon512::sign(b"message", b"secret", &mut rng) {
            Ok(_) => panic!("byte-slice sign adapter should fail closed"),
            Err(err) => assert!(matches!(err, Falcon512Error::NotImplemented)),
        }

        match Falcon512::verify(b"message", b"sig", b"public") {
            Ok(_) => panic!("byte-slice verify adapter should fail closed"),
            Err(err) => assert!(matches!(err, Falcon512Error::NotImplemented)),
        }
    }
}

// Export for compatibility
pub fn keygen<R: RngCore + Send>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
    Falcon512::keygen(rng)
}
