//! NIST API compatibility layer for Falcon-512
//! 
//! Provides functions compatible with the NIST submission API format.
//! This includes support for the signed message format used in NIST KAT vectors.

use crate::{error::{Result, Falcon512Error as FalconError}, PrivateKey, PublicKey};
use crate::constants::{NIST_CRYPTO_BYTES, NONCE_SIZE, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};
use crate::nist_encoding::{modq_encode, modq_decode};
use crate::nist_signature::{create_signed_message_nist, extract_from_signed_message_nist};
use alloc::vec::Vec;

/// NIST API: Generate a key pair
/// 
/// Compatible with crypto_sign_keypair from NIST submission
pub fn crypto_sign_keypair<R: rand::RngCore + Send>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
    let keypair = crate::generate_keypair(rng)?;
    
    // Serialize to NIST format
    let pk = serialize_public_key_nist(&keypair.public_key);
    let sk = serialize_private_key_nist(&keypair.private_key)?;
    
    Ok((pk, sk))
}

// Helper function to serialize public key in NIST format
fn serialize_public_key_nist(pk: &PublicKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CRYPTO_PUBLICKEYBYTES);
    
    // Add header byte (0x00 + logn for Falcon-512)
    bytes.push(0x00 + 9);
    
    // Encode h polynomial using modq encoding
    let encoded = modq_encode(&pk.h.coeffs, 9);
    bytes.extend_from_slice(&encoded);
    
    bytes
}

// Helper function to serialize private key in NIST format
fn serialize_private_key_nist(sk: &PrivateKey) -> Result<Vec<u8>> {
    // Use tree-based encoding for NIST compliance
    use crate::nist_tree_encoding::encode_private_key_tree;

    encode_private_key_tree(
        &sk.f.coeffs,
        &sk.g.coeffs,
        &sk.big_f.coeffs,
        &sk.big_g.coeffs,
    ).map_err(|_| FalconError::NotImplemented)
}

// Helper function to deserialize public key from NIST format
fn deserialize_public_key_nist(bytes: &[u8]) -> Result<PublicKey> {
    if bytes.len() != CRYPTO_PUBLICKEYBYTES {
        return Err(FalconError::InvalidPublicKey);
    }
    
    // Check header byte
    if bytes[0] != 0x00 + 9 {
        return Err(FalconError::InvalidPublicKey);
    }
    
    // Decode h polynomial
    let h_coeffs = modq_decode(&bytes[1..], 9)?;
    
    Ok(PublicKey {
        h: crate::poly::Poly::new(h_coeffs)
    })
}

// Helper function to deserialize private key from NIST format
fn deserialize_private_key_nist(bytes: &[u8]) -> Result<PrivateKey> {
    if bytes.len() != CRYPTO_SECRETKEYBYTES {
        return Err(FalconError::InvalidPrivateKey);
    }
    
    // Check header byte
    if bytes[0] != 0x50 + 9 {
        return Err(FalconError::InvalidPrivateKey);
    }
    
    // Try tree-based decoding first
    use crate::nist_tree_encoding::decode_private_key_tree;
    
    decode_private_key_tree(bytes)
        .map(|(f, g, big_f, big_g)| PrivateKey {
            f: crate::poly::Poly::new(f),
            g: crate::poly::Poly::new(g),
            big_f: crate::poly::Poly::new(big_f),
            big_g: crate::poly::Poly::new(big_g),
        })
        .map_err(|_| FalconError::InvalidPrivateKey)
}

/// NIST API: Sign a message, producing signed message format
/// 
/// Compatible with crypto_sign from NIST submission.
/// 
/// Output format:
/// - 2 bytes: signature length (big-endian)
/// - 40 bytes: nonce
/// - mlen bytes: original message
/// - sig_len bytes: signature (header + compressed data)
pub fn crypto_sign<R: rand::RngCore>(
    message: &[u8],
    secret_key: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    // Parse secret key from NIST format
    let private_key = deserialize_private_key_nist(secret_key)?;
    
    // Use NIST-compliant signing
    let (signature, nonce) = crate::falcon_complete::sign_nist(message, &private_key, rng)?;
    
    // Build signed message in NIST format
    create_signed_message_nist(&nonce, message, &signature)
}

/// NIST API: Verify a signed message
/// 
/// Compatible with crypto_sign_open from NIST submission.
/// 
/// Input format:
/// - 2 bytes: signature length (big-endian)
/// - 40 bytes: nonce
/// - mlen bytes: original message
/// - sig_len bytes: signature
/// 
/// Returns the original message if verification succeeds
pub fn crypto_sign_open(
    signed_message: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>> {
    // Extract components from signed message
    let (nonce, message, signature) = extract_from_signed_message_nist(signed_message)?;
    
    // Parse public key from NIST format
    let public_key = deserialize_public_key_nist(public_key)?;

    // Reconstruct the full NIST-format signature for verify_complete:
    // verify_complete expects: header(0x39) + nonce(40) + compressed_s1
    // extract_from_signed_message_nist returns: signature = compressed_s1 (no header/nonce)
    let mut full_sig = Vec::with_capacity(1 + nonce.len() + signature.len());
    full_sig.push(0x30 | crate::constants::LOGN as u8); // header = 0x39
    full_sig.extend_from_slice(&nonce);
    full_sig.extend_from_slice(&signature);

    match crate::falcon_complete::verify_complete(&message, &full_sig, &public_key) {
        Ok(true) => Ok(message),
        Ok(false) => Err(FalconError::InvalidSignature),
        Err(_) => Err(FalconError::InvalidSignature),
    }
}

/// Reconstruct s1 from c and s2 using s1 = c - s2*h (mod q)
fn reconstruct_s1(c: &[i16], s2: &[i16], h: &[i16]) -> Result<Vec<i16>> {
    // Compute s2*h using NTT
    let s2h = crate::ntt_falcon::multiply_ntt(s2, h);
    
    // Compute s1 = c - s2*h mod q
    let mut s1 = vec![0i16; crate::constants::N];
    for i in 0..crate::constants::N {
        let diff = (c[i] as i32 - s2h[i] as i32 + crate::constants::Q as i32) % crate::constants::Q as i32;
        // Center reduce to [-q/2, q/2)
        s1[i] = if diff >= (crate::constants::Q as i32 + 1) / 2 {
            (diff - crate::constants::Q as i32) as i16
        } else {
            diff as i16
        };
    }
    
    Ok(s1)
}

/// Extract signature from NIST signed message format
/// 
/// Returns (nonce, signature, message) if successful
pub fn extract_from_signed_message(signed_message: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Minimum size check
    if signed_message.len() < 2 + NONCE_SIZE {
        return Err(FalconError::InvalidSignature);
    }
    
    // Extract signature length
    let sig_len = ((signed_message[0] as usize) << 8) | (signed_message[1] as usize);
    
    // Verify total length
    if signed_message.len() < 2 + NONCE_SIZE + sig_len {
        return Err(FalconError::InvalidSignature);
    }
    
    // Extract components
    let nonce = signed_message[2..2 + NONCE_SIZE].to_vec();
    let msg_start = 2 + NONCE_SIZE;
    let msg_end = signed_message.len() - sig_len;
    let message = signed_message[msg_start..msg_end].to_vec();
    let signature = signed_message[msg_end..].to_vec();
    
    Ok((nonce, signature, message))
}

/// Create signed message format from components
/// 
/// Combines nonce, message, and signature into NIST format
pub fn create_signed_message(
    nonce: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_SIZE {
        return Err(FalconError::InvalidNonce);
    }
    
    let sig_len = signature.len();
    if sig_len > NIST_CRYPTO_BYTES {
        return Err(FalconError::SignatureTooLarge);
    }
    
    let total_len = 2 + NONCE_SIZE + message.len() + sig_len;
    let mut signed_message = Vec::with_capacity(total_len);
    
    // Add signature length (big-endian)
    signed_message.push((sig_len >> 8) as u8);
    signed_message.push((sig_len & 0xFF) as u8);
    
    // Add components
    signed_message.extend_from_slice(nonce);
    signed_message.extend_from_slice(message);
    signed_message.extend_from_slice(signature);
    
    Ok(signed_message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_nist_api_roundtrip() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        // Generate keypair
        let (pk, sk) = crypto_sign_keypair(&mut rng).unwrap();

        // Sign a message
        let message = b"Test message for NIST API";
        let signed_msg = crypto_sign(message, &sk, &mut rng).unwrap();

        // Verify and recover message
        let recovered = crypto_sign_open(&signed_msg, &pk).unwrap();
        assert_eq!(recovered, message);
    }
    
    #[test]
    fn test_extract_from_signed_message() {
        let _rng = ChaCha20Rng::from_seed([42u8; 32]);
        let nonce = vec![0x24u8; NONCE_SIZE];
        let message = b"Test message";
        let signature = vec![0x29, 1, 2, 3, 4, 5];
        let signed_msg = create_signed_message(&nonce, message, &signature).unwrap();
        
        // Extract components
        let (nonce, signature, extracted_msg) = extract_from_signed_message(&signed_msg).unwrap();
        
        assert_eq!(nonce.len(), NONCE_SIZE);
        assert_eq!(extracted_msg, message);
        assert_eq!(signature, vec![0x29, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_crypto_sign_rejects_simplified_secret_key_fallback() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let mut old_fallback_key = vec![0u8; CRYPTO_SECRETKEYBYTES];
        old_fallback_key[0] = 0x50 + 9;

        let result = crypto_sign(b"message", &old_fallback_key, &mut rng);

        assert!(matches!(result, Err(FalconError::InvalidPrivateKey)));
    }
}
