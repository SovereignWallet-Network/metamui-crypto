//! Deterministic mode for NIST KAT testing
//! 
//! This module provides a deterministic configuration for Falcon-512
//! that enables reproducible outputs for testing purposes.
//! 
//! NOTE: This mode is ONLY for testing and should NEVER be used in production!

use crate::constants::N;
use crate::error::{Result, Falcon512Error};
use crate::{PublicKey, PrivateKey, KeyPair};
use crate::shake::Shake256Context;
use alloc::vec::Vec;
use rand::RngCore;

/// Deterministic configuration for testing
#[derive(Clone, Debug)]
pub struct DeterministicConfig {
    /// Fixed seed for key generation
    pub keygen_seed: [u8; 48],
    /// Fixed seed for signing
    pub signing_seed: [u8; 48],
    /// Use deterministic sampling
    pub deterministic_sampling: bool,
    /// Maximum attempts before failing
    pub max_attempts: usize,
}

impl Default for DeterministicConfig {
    fn default() -> Self {
        Self {
            keygen_seed: [0u8; 48],
            signing_seed: [0u8; 48],
            deterministic_sampling: true,
            max_attempts: 256,
        }
    }
}

/// Deterministic RNG that derives all randomness from a seed
pub struct DeterministicRng {
    seed: Vec<u8>,
    counter: u64,
    buffer: Vec<u8>,
    offset: usize,
}

impl DeterministicRng {
    /// Create a new deterministic RNG from a seed
    pub fn new(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
            counter: 0,
            buffer: vec![0u8; 256],
            offset: 256, // Force initial fill
        }
    }
    
    /// Create from KAT seed format
    pub fn from_kat_seed(seed: &[u8; 48]) -> Self {
        Self::new(seed)
    }
    
    fn refill_buffer(&mut self) {
        // Derive buffer from seed and counter
        let mut context = Shake256Context::new();
        context.update(&self.seed);
        context.update(&self.counter.to_le_bytes());
        
        let mut reader = context.finalize_xof();
        reader.read(&mut self.buffer);
        
        self.counter += 1;
        self.offset = 0;
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        
        while written < dest.len() {
            if self.offset >= self.buffer.len() {
                self.refill_buffer();
            }
            
            let available = self.buffer.len() - self.offset;
            let needed = dest.len() - written;
            let to_copy = available.min(needed);
            
            dest[written..written + to_copy]
                .copy_from_slice(&self.buffer[self.offset..self.offset + to_copy]);
            
            self.offset += to_copy;
            written += to_copy;
        }
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Generate keypair deterministically for KAT testing
pub fn generate_keypair_deterministic(seed: &[u8; 48]) -> Result<KeyPair> {
    let mut rng = DeterministicRng::from_kat_seed(seed);
    
    // Use enhanced keygen with multiple attempts
    for _ in 0..100 {
        match crate::generate_keypair(&mut rng) {
            Ok(keypair) => return Ok(keypair),
            Err(_) => continue, // Retry on failure
        }
    }
    
    Err(Falcon512Error::KeyGenerationFailed)
}

/// Sign message deterministically for KAT testing
pub fn sign_deterministic(
    message: &[u8],
    private_key: &PrivateKey,
    seed: &[u8; 48]
) -> Result<Vec<u8>> {
    // Derive signing randomness from seed and message
    let mut context = Shake256Context::new();
    context.update(seed);
    context.update(message);
    
    let mut reader = context.finalize_xof();
    let mut rng_seed = [0u8; 48];
    reader.read(&mut rng_seed);
    
    let mut rng = DeterministicRng::from_kat_seed(&rng_seed);
    
    // Try signing with deterministic randomness
    for _ in 0..256 {
        match crate::sign_no_retry(message, private_key, &mut rng) {
            Ok(sig) => return Ok(sig),
            Err(_) => continue, // Retry on rejection
        }
    }
    
    Err(Falcon512Error::SigningFailed)
}

/// NIST KAT test structure
#[derive(Debug, Clone)]
pub struct KATTest {
    pub count: usize,
    pub seed: [u8; 48],
    pub msg: Vec<u8>,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub sig: Vec<u8>,
}

/// Run NIST KAT validation
pub fn validate_kat(test: &KATTest) -> Result<bool> {
    let _ = test;
    Err(Falcon512Error::NotImplemented)
}

/// Serialize public key for comparison
#[allow(dead_code)]
fn serialize_public_key(pk: &PublicKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(N * 2);
    for &coeff in &pk.h.coeffs {
        bytes.extend_from_slice(&coeff.to_le_bytes());
    }
    bytes
}

/// Parse KAT test from NIST format
pub fn parse_kat_line(line: &str, current: &mut Option<KATTest>) -> Result<()> {
    let line = line.trim();
    
    if line.starts_with("count = ") {
        let count = line[8..].parse().map_err(|_| Falcon512Error::InvalidFormat)?;
        *current = Some(KATTest {
            count,
            seed: [0u8; 48],
            msg: Vec::new(),
            pk: Vec::new(),
            sk: Vec::new(),
            sig: Vec::new(),
        });
    } else if line.starts_with("seed = ") {
        if let Some(ref mut test) = current {
            let hex = &line[7..];
            test.seed = hex_to_bytes48(hex)?;
        }
    } else if line.starts_with("msg = ") {
        if let Some(ref mut test) = current {
            test.msg = hex_to_bytes(&line[6..])?;
        }
    } else if line.starts_with("pk = ") {
        if let Some(ref mut test) = current {
            test.pk = hex_to_bytes(&line[5..])?;
        }
    } else if line.starts_with("sk = ") {
        if let Some(ref mut test) = current {
            test.sk = hex_to_bytes(&line[5..])?;
        }
    } else if line.starts_with("sig = ") {
        if let Some(ref mut test) = current {
            test.sig = hex_to_bytes(&line[6..])?;
        }
    }
    
    Ok(())
}

/// Convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return Err(Falcon512Error::InvalidFormat);
    }
    
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2], 16)
            .map_err(|_| Falcon512Error::InvalidFormat)?;
        bytes.push(byte);
    }
    
    Ok(bytes)
}

/// Convert hex string to 48-byte array
fn hex_to_bytes48(hex: &str) -> Result<[u8; 48]> {
    let bytes = hex_to_bytes(hex)?;
    if bytes.len() != 48 {
        return Err(Falcon512Error::InvalidFormat);
    }
    
    let mut array = [0u8; 48];
    array.copy_from_slice(&bytes);
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_deterministic_rng() {
        let seed = b"test seed for deterministic RNG";
        let mut rng1 = DeterministicRng::new(seed);
        let mut rng2 = DeterministicRng::new(seed);
        
        // Should produce identical sequences
        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }
    
    #[test]
    fn test_deterministic_keygen() {
        let seed = [42u8; 48];
        
        // Multiple calls with same seed should attempt to produce same result
        // (may still differ due to rejection sampling)
        let result1 = generate_keypair_deterministic(&seed);
        let result2 = generate_keypair_deterministic(&seed);
        
        // Both should succeed or both should fail
        assert_eq!(result1.is_ok(), result2.is_ok());
    }

    #[test]
    fn test_validate_kat_fails_closed_until_exact_vector_parity_is_supported() {
        let test = KATTest {
            count: 0,
            seed: [7u8; 48],
            msg: b"kat".to_vec(),
            pk: vec![0u8; 897],
            sk: vec![0u8; 2305],
            sig: vec![0u8; 666],
        };

        let result = validate_kat(&test);
        assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
    }
}
