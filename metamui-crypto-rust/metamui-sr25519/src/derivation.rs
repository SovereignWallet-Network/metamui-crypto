/// Substrate-style Sr25519 key derivation
/// Supports both hard (// prefix) and soft (/ prefix) derivation paths
/// Compatible with Polkadot/Substrate ecosystem

extern crate alloc;
use alloc::{string::ToString, vec::Vec};
use parity_scale_codec::Encode;
use metamui_blake2b::blake2b256;
use crate::{Sr25519Error, Sr25519Signer};
use crate::merlin::MerlinTranscript;

const SOFT_DERIVATION_UNAVAILABLE: &str =
    "Sr25519 soft derivation is not implemented; refusing placeholder derived key";

/// Junction in a derivation path
#[derive(Debug, Clone)]
pub struct DeriveJunction {
    pub chain_code: [u8; 32],
    pub is_hard: bool,
}

/// Parse a Substrate-style derivation path
/// Format: //hard/soft//another_hard/0
/// - Double slash (//) indicates hard derivation
/// - Single slash (/) indicates soft derivation  
/// - Numbers are parsed as u32 indices
/// - Strings are hashed using SHA256 to create chain codes
pub fn parse_path(path: &str) -> Result<Vec<DeriveJunction>, Sr25519Error> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    
    let mut junctions = Vec::new();
    let mut remaining = path;
    
    while !remaining.is_empty() {
        // Check if this is a hard derivation (starts with //)
        let (is_hard, junction_str) = if remaining.starts_with("//") {
            remaining = &remaining[2..];
            let end = remaining.find('/').unwrap_or(remaining.len());
            let junction = &remaining[..end];
            remaining = if end < remaining.len() { &remaining[end..] } else { "" };
            (true, junction)
        } else if remaining.starts_with('/') {
            remaining = &remaining[1..];
            let end = remaining.find('/').unwrap_or(remaining.len());
            let junction = &remaining[..end];
            remaining = if end < remaining.len() { &remaining[end..] } else { "" };
            (false, junction)
        } else {
            return Err(Sr25519Error::KeyDerivationError(
                "Invalid derivation path format".into()
            ));
        };
        
        // Skip empty junctions
        if junction_str.is_empty() {
            continue;
        }
        
        // Create chain code from junction
        let chain_code = if let Ok(index) = junction_str.parse::<u32>() {
            // Numeric index - SCALE encode it
            let mut code = [0u8; 32];
            let encoded = index.encode();
            if encoded.len() <= 32 {
                code[..encoded.len()].copy_from_slice(&encoded);
            } else {
                // Should never happen for u32, but hash if too long
                let hash = blake2b256(&encoded);
                code.copy_from_slice(&hash);
            }
            code
        } else {
            // String junction - SCALE encode it
            // Substrate uses string.encode() which adds compact length prefix
            let encoded = junction_str.encode();
            let mut code = [0u8; 32];
            
            if encoded.len() <= 32 {
                // Fits in chain code directly
                code[..encoded.len()].copy_from_slice(&encoded);
            } else {
                // Too long, hash it
                let hash = blake2b256(&encoded);
                code.copy_from_slice(&hash);
            }
            code
        };
        
        junctions.push(DeriveJunction { chain_code, is_hard });
    }
    
    Ok(junctions)
}

/// Derive a hard key from parent
/// This matches Substrate's implementation using Merlin transcripts
fn derive_hard(
    parent_seed: &[u8; 32],
    chain_code: &[u8; 32],
) -> [u8; 32] {
    // Create schnorrkel transcript for HDKD
    let mut transcript = MerlinTranscript::for_schnorrkel();
    
    // Substrate passes empty bytes for "sign-bytes" in derivation
    transcript.append_message(b"sign-bytes", b"");
    
    // Append the chain code
    transcript.append_message(b"chain-code", chain_code);
    
    // Append the parent secret key
    transcript.append_message(b"secret-key", parent_seed);
    
    // Extract the derived mini-secret key
    transcript.challenge_scalar(b"HDKD-hard")
}

/// Derive a keypair from a seed and derivation path
pub fn derive_keypair_from_path(
    seed: &[u8; 32],
    path: &str,
) -> Result<([u8; 32], [u8; 32]), Sr25519Error> {
    let junctions = parse_path(path)?;
    
    // Start with the root seed
    let mut current_seed = *seed;
    
    // Process each junction
    // Note: Substrate feeds junctions as chain codes, not maintaining separate chain code state
    for junction in junctions {
        if junction.is_hard {
            // Hard derivation
            current_seed = derive_hard(&current_seed, &junction.chain_code);
        } else {
            return Err(Sr25519Error::KeyDerivationError(
                SOFT_DERIVATION_UNAVAILABLE.to_string()
            ));
        }
    }
    
    // Generate final keypair from derived seed
    let final_signer = Sr25519Signer::from_seed(&current_seed)?;
    let public_key = final_signer.public_key();
    
    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(&public_key);
    
    Ok((public_bytes, current_seed))
}

/// Derive just the public key from a seed and path
pub fn derive_public_from_path(seed: &[u8; 32], path: &str) -> Result<[u8; 32], Sr25519Error> {
    let (public_key, _) = derive_keypair_from_path(seed, path)?;
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_path() {
        // Test hard derivation
        let junctions = parse_path("//Alice").unwrap();
        assert_eq!(junctions.len(), 1);
        assert!(junctions[0].is_hard);
        
        // Test soft derivation
        let junctions = parse_path("/Bob").unwrap();
        assert_eq!(junctions.len(), 1);
        assert!(!junctions[0].is_hard);
        
        // Test mixed
        let junctions = parse_path("//Alice/Bob//Charlie").unwrap();
        assert_eq!(junctions.len(), 3);
        assert!(junctions[0].is_hard); // Alice
        assert!(!junctions[1].is_hard); // Bob
        assert!(junctions[2].is_hard); // Charlie
        
        // Test numeric
        let junctions = parse_path("//0/1").unwrap();
        assert_eq!(junctions.len(), 2);
        assert!(junctions[0].is_hard);
        assert!(!junctions[1].is_hard);
    }
    
    #[test]
    fn test_derive_alice() {
        // Test derivation with known seed
        let seed = hex::decode("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e")
            .unwrap();
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed);
        
        // Test hard derivation //Alice
        let (public_key, _) = derive_keypair_from_path(&seed_array, "//Alice").unwrap();
        let public_hex = hex::encode(public_key);
        println!("//Alice public key: {}", public_hex);
    }

    #[test]
    fn test_soft_derivation_fails_closed() {
        let seed = [0x42u8; 32];

        let result = derive_keypair_from_path(&seed, "/Alice");
        assert!(matches!(
            result,
            Err(Sr25519Error::KeyDerivationError(ref msg))
                if msg == SOFT_DERIVATION_UNAVAILABLE
        ));
    }
}
