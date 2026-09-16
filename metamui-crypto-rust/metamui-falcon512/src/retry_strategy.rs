//! Retry strategy for Falcon-512 signing operations
//! 
//! This module provides robust retry mechanisms to handle the non-deterministic
//! nature of Falcon-512's rejection sampling.

use crate::error::{Result, Falcon512Error};
use crate::PrivateKey;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use alloc::vec::Vec;

#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
use std::time::Duration;
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
use std::thread::sleep;

/// Signing mode presets for different use cases
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SigningMode {
    /// Fast mode: 10 attempts, no backoff
    Fast,
    /// Standard mode: 30 attempts, 10ms backoff (default)
    Standard,
    /// Persistent mode: 100 attempts, exponential backoff with seed rotation
    Persistent,
    /// NIST mode: 256 attempts as per NIST specification
    Nist,
    /// Custom mode: use provided configuration
    Custom,
}

impl Default for SigningMode {
    fn default() -> Self {
        SigningMode::Standard
    }
}

/// Configuration for signing retry strategy
#[derive(Debug, Clone)]
pub struct SigningConfig {
    /// Signing mode preset
    pub mode: SigningMode,
    /// Maximum number of attempts
    pub max_attempts: usize,
    /// Enable seed rotation on retry
    pub seed_rotation: bool,
    /// Initial backoff in milliseconds
    pub backoff_ms: u64,
    /// Maximum backoff in milliseconds
    pub max_backoff_ms: u64,
    /// Track failure statistics
    pub track_stats: bool,
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self::from_mode(SigningMode::Standard)
    }
}

impl SigningConfig {
    /// Create configuration from a signing mode preset
    pub fn from_mode(mode: SigningMode) -> Self {
        match mode {
            SigningMode::Fast => Self {
                mode,
                max_attempts: 10,
                seed_rotation: false,
                backoff_ms: 0,
                max_backoff_ms: 0,
                track_stats: false,
            },
            SigningMode::Standard => Self {
                mode,
                max_attempts: 30,
                seed_rotation: false,
                backoff_ms: 10,
                max_backoff_ms: 100,
                track_stats: false,
            },
            SigningMode::Persistent => Self {
                mode,
                max_attempts: 100,
                seed_rotation: true,
                backoff_ms: 10,
                max_backoff_ms: 1000,
                track_stats: true,
            },
            SigningMode::Nist => Self {
                mode,
                max_attempts: 256,  // NIST requirement
                seed_rotation: false,
                backoff_ms: 0,
                max_backoff_ms: 0,
                track_stats: true,
            },
            SigningMode::Custom => Self {
                mode,
                max_attempts: 50,
                seed_rotation: true,
                backoff_ms: 10,
                max_backoff_ms: 500,
                track_stats: false,
            },
        }
    }
}

/// Statistics for signing attempts
#[derive(Debug, Clone, Default)]
pub struct SigningStats {
    /// Total number of attempts made
    pub total_attempts: usize,
    /// Number of successful attempts
    pub successful_attempts: usize,
    /// Number of failed attempts
    pub failed_attempts: usize,
    /// Number of seed rotations performed
    pub seed_rotations: usize,
    /// Total backoff time in milliseconds
    pub total_backoff_ms: u64,
}

/// Result of a signing operation with retry
pub struct SigningResult {
    /// The generated signature
    pub signature: Vec<u8>,
    /// Statistics about the signing process
    pub stats: SigningStats,
}

/// Sign a message with retry strategy
pub fn sign_with_retry<R: RngCore>(
    message: &[u8],
    private_key: &PrivateKey,
    rng: &mut R,
    config: &SigningConfig,
) -> Result<SigningResult> {
    let mut stats = SigningStats::default();
    
    // Get base seed for potential rotation
    let base_seed = if config.seed_rotation {
        let mut seed_bytes = [0u8; 32];
        rng.fill_bytes(&mut seed_bytes);
        u64::from_le_bytes(seed_bytes[0..8].try_into().unwrap())
    } else {
        0
    };
    
    // Calculate attempts per batch
    let batch_size = 10;
    let num_batches = (config.max_attempts + batch_size - 1) / batch_size;
    
    for batch in 0..num_batches {
        // Try signing within this batch
        let batch_attempts = batch_size.min(config.max_attempts - batch * batch_size);
        
        // Rotate seed if enabled
        if config.seed_rotation && batch > 0 {
            stats.seed_rotations += 1;
            let derived_seed = base_seed.wrapping_add(batch as u64);
            let mut seed = [0u8; 32];
            seed[0..8].copy_from_slice(&derived_seed.to_le_bytes());
            let mut batch_rng = ChaCha20Rng::from_seed(seed);
            
            // Try with rotated seed
            for _ in 0..batch_attempts {
                stats.total_attempts += 1;
                
                match crate::falcon_complete::sign_complete(message, private_key, &mut batch_rng) {
                    Ok(signature) => {
                        // Verify the signature is properly formed
                        if verify_signature_quality(&signature, message, private_key) {
                            stats.successful_attempts += 1;
                            return Ok(SigningResult { signature, stats });
                        } else {
                            stats.failed_attempts += 1;
                            #[cfg(feature = "std")]
                            eprintln!("Warning: Generated signature failed quality check");
                        }
                    }
                    // A band violation is a deterministic property of the key
                    // (pre-#141 keygen) — no retry or seed rotation can clear
                    // it, so surface it typed instead of burning the budget.
                    Err(e @ Falcon512Error::LdlSigmaOutOfBand) => return Err(e),
                    Err(_) => {
                        stats.failed_attempts += 1;
                    }
                }
            }
        } else {
            // Use original RNG
            for _ in 0..batch_attempts {
                stats.total_attempts += 1;
                
                match crate::falcon_complete::sign_complete(message, private_key, rng) {
                    Ok(signature) => {
                        // Verify the signature is properly formed
                        if verify_signature_quality(&signature, message, private_key) {
                            stats.successful_attempts += 1;
                            return Ok(SigningResult { signature, stats });
                        } else {
                            stats.failed_attempts += 1;
                            #[cfg(feature = "std")]
                            eprintln!("Warning: Generated signature failed quality check");
                        }
                    }
                    // Deterministic key defect — see the seed-rotation arm.
                    Err(e @ Falcon512Error::LdlSigmaOutOfBand) => return Err(e),
                    Err(_) => {
                        stats.failed_attempts += 1;
                    }
                }
            }
        }

        // Apply backoff between batches (if not the last batch)
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        if batch < num_batches - 1 && config.backoff_ms > 0 {
            let backoff = calculate_backoff(batch, config.backoff_ms, config.max_backoff_ms);
            stats.total_backoff_ms += backoff;
            sleep(Duration::from_millis(backoff));
        }
    }
    
    Err(Falcon512Error::SigningFailed)
}

/// Calculate exponential backoff with maximum limit
fn calculate_backoff(attempt: usize, base_ms: u64, max_ms: u64) -> u64 {
    let exponential = base_ms.saturating_mul(2_u64.saturating_pow(attempt as u32));
    exponential.min(max_ms)
}

/// Verify that a signature is properly formed
fn verify_signature_quality(signature: &[u8], message: &[u8], private_key: &PrivateKey) -> bool {
    let public_key = match crate::ntt_falcon::compute_public_key_ntt(
        &private_key.f.coeffs,
        &private_key.g.coeffs,
    ) {
        Ok(h) => crate::PublicKey {
            h: crate::poly::Poly::new(h),
        },
        Err(_) => return false,
    };

    matches!(
        crate::falcon_complete::verify_complete(message, signature, &public_key),
        Ok(true)
    )
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_modes() {
        let fast = SigningConfig::from_mode(SigningMode::Fast);
        assert_eq!(fast.max_attempts, 10);
        assert!(!fast.seed_rotation);
        
        let standard = SigningConfig::from_mode(SigningMode::Standard);
        assert_eq!(standard.max_attempts, 30);
        
        let persistent = SigningConfig::from_mode(SigningMode::Persistent);
        assert_eq!(persistent.max_attempts, 100);
        assert!(persistent.seed_rotation);
    }
    
    #[test]
    fn test_backoff_calculation() {
        assert_eq!(calculate_backoff(0, 10, 1000), 10);
        assert_eq!(calculate_backoff(1, 10, 1000), 20);
        assert_eq!(calculate_backoff(2, 10, 1000), 40);
        assert_eq!(calculate_backoff(3, 10, 1000), 80);
        assert_eq!(calculate_backoff(10, 10, 1000), 1000); // Capped at max
    }
    
    #[test]
    fn test_signature_quality_check() {
        // Create a dummy private key for testing
        let dummy_key = crate::PrivateKey {
            f: crate::poly::Poly::new(vec![0i16; 512]),
            g: crate::poly::Poly::new(vec![0i16; 512]),
            big_f: crate::poly::Poly::new(vec![0i16; 512]),
            big_g: crate::poly::Poly::new(vec![0i16; 512]),
        };
        
        // Empty signature should fail
        assert!(!verify_signature_quality(&[], b"test", &dummy_key));
        
        // Too large signature should fail
        let huge = vec![0u8; 3000];
        assert!(!verify_signature_quality(&huge, b"test", &dummy_key));
        
        // Length/header-only heuristics are no longer accepted.
        let mut nist_sig = vec![0x29];
        nist_sig.extend_from_slice(&[1u8; 100]);
        assert!(!verify_signature_quality(&nist_sig, b"test", &dummy_key));
        
        // Arbitrary bytes should not be treated as a valid signature.
        let valid = vec![1, 2, 3, 4, 5];
        assert!(!verify_signature_quality(&valid, b"test", &dummy_key));
    }

    #[test]
    fn test_signature_quality_check_accepts_real_signature() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let (public_key, private_key) = crate::falcon_complete::keygen_complete_simple(&mut rng)
            .expect("key generation should succeed");
        let message = b"retry strategy verification";
        let signature = crate::falcon_complete::sign_complete(message, &private_key, &mut rng)
            .expect("signing should succeed");

        assert!(crate::falcon_complete::verify_complete(message, &signature, &public_key)
            .expect("reference verification should succeed"));
        assert!(verify_signature_quality(&signature, message, &private_key));
    }
}
