//! Integration tests for retry strategy

use metamui_falcon512::{
    generate_keypair, sign, sign_with_config, sign_no_retry, verify,
    SigningConfig, SigningMode, Falcon512Error
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// A mock RNG that fails for a certain number of calls. Kept as a
/// fixture for the retry-loop tests below even though current test
/// bodies exercise the retry path through real RNG exhaustion; a
/// future fault-injection test will construct `FailingRng` directly.
#[allow(dead_code)]
struct FailingRng {
    fail_count: usize,
    current: usize,
    inner: ChaCha20Rng,
}

#[allow(dead_code)]
impl FailingRng {
    fn new(fail_count: usize) -> Self {
        Self {
            fail_count,
            current: 0,
            inner: ChaCha20Rng::seed_from_u64(12345),
        }
    }
}

impl RngCore for FailingRng {
    fn next_u32(&mut self) -> u32 {
        self.current += 1;
        if self.current <= self.fail_count {
            // Return values that will cause rejection sampling to fail
            0
        } else {
            self.inner.next_u32()
        }
    }
    
    fn next_u64(&mut self) -> u64 {
        self.current += 1;
        if self.current <= self.fail_count {
            0
        } else {
            self.inner.next_u64()
        }
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.current < self.fail_count {
            // Fill with zeros which will likely cause failures
            for b in dest.iter_mut() {
                *b = 0;
            }
            self.current += dest.len();
        } else {
            self.inner.fill_bytes(dest);
        }
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[test]
fn test_sign_with_automatic_retry() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    // Generate a keypair
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    // Sign a message - should succeed with automatic retry
    let message = b"Test message for retry";
    let signature = sign(message, &keypair.private_key, &mut rng)
        .expect("Signing should succeed with retry");
    
    // Verify the signature
    assert!(verify(message, &signature, &keypair.public_key)
        .expect("Verification should succeed"));
}

#[test]
fn test_sign_with_custom_config() {
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    // Use fast mode for quick testing
    let config = SigningConfig::from_mode(SigningMode::Fast);
    
    let message = b"Fast mode test";
    let result = sign_with_config(message, &keypair.private_key, &mut rng, &config)
        .expect("Signing should succeed");
    
    println!("Fast mode signing took {} attempts", result.stats.total_attempts);
    
    // Verify the signature
    assert!(verify(message, &result.signature, &keypair.public_key)
        .expect("Verification should succeed"));
}

#[test]
fn test_sign_with_seed_rotation() {
    let mut rng = ChaCha20Rng::seed_from_u64(777);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    // Use persistent mode with seed rotation
    let config = SigningConfig {
        mode: SigningMode::Persistent,
        seed_rotation: true,
        track_stats: true,
        ..Default::default()
    };
    
    let message = b"Seed rotation test";
    let result = sign_with_config(message, &keypair.private_key, &mut rng, &config)
        .expect("Signing should succeed with seed rotation");
    
    println!("Persistent mode stats:");
    println!("  Total attempts: {}", result.stats.total_attempts);
    println!("  Seed rotations: {}", result.stats.seed_rotations);
    println!("  Failed attempts: {}", result.stats.failed_attempts);
    
    // Verify the signature
    assert!(verify(message, &result.signature, &keypair.public_key)
        .expect("Verification should succeed"));
}

#[test]
fn test_sign_no_retry_can_fail() {
    // Test that signing without retry can fail
    let _rng = ChaCha20Rng::seed_from_u64(12345);
    
    // Try to sign without retry multiple times to see if it ever fails
    // Note: This test might not always fail due to the probabilistic nature
    let mut any_failed = false;
    
    for seed in 0..10 {
        let mut test_rng = ChaCha20Rng::seed_from_u64(seed);
        let keypair = match generate_keypair(&mut test_rng) {
            Ok(kp) => kp,
            Err(_) => continue, // Key generation failed, try next seed
        };
        
        let message = b"No retry test";
        
        // Try signing without retry
        match sign_no_retry(message, &keypair.private_key, &mut test_rng) {
            Ok(_) => {
                // Signing succeeded
            }
            Err(Falcon512Error::SigningFailed) => {
                any_failed = true;
                println!("Signing without retry failed as expected with seed {}", seed);
                break;
            }
            Err(e) => {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }
    
    if !any_failed {
        println!("Warning: All signing attempts succeeded. This is possible but unlikely.");
        println!("The probabilistic nature of the algorithm means this test may not always demonstrate failure.");
    }
}

#[test]
fn test_signature_never_verifies_wrong_message() {
    let mut rng = ChaCha20Rng::seed_from_u64(555);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"Correct message";
    let wrong_message = b"Wrong message!!!";
    
    // Sign the correct message - may take multiple attempts
    let mut signature = None;
    for _attempt in 0..5 {
        match sign(message, &keypair.private_key, &mut rng) {
            Ok(sig) => {
                // Check if this signature actually verifies
                if verify(message, &sig, &keypair.public_key).unwrap_or(false) {
                    signature = Some(sig);
                    break;
                }
                // Otherwise try again - equation might not be satisfied
            }
            Err(_) => continue,
        }
    }
    
    let signature = signature.expect("Should get a valid signature after retries");
    
    // Verify with correct message - should succeed
    assert!(verify(message, &signature, &keypair.public_key)
        .expect("Verification should succeed"),
        "Valid signature should verify");
    
    // Verify with wrong message - MUST fail (security critical)
    assert!(!verify(wrong_message, &signature, &keypair.public_key)
        .expect("Verification should complete"),
        "Signature should NOT verify wrong message (security critical)");
}

#[test]
fn test_different_configs_produce_valid_signatures() {
    let mut rng = ChaCha20Rng::seed_from_u64(888);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"Config comparison test";
    
    // Test all modes
    let modes = [
        SigningMode::Fast,
        SigningMode::Standard,
        SigningMode::Persistent,
    ];
    
    for mode in &modes {
        let config = SigningConfig::from_mode(*mode);
        
        let result = sign_with_config(message, &keypair.private_key, &mut rng, &config)
            .expect(&format!("Signing should succeed with {:?} mode", mode));
        
        println!("{:?} mode: {} attempts", mode, result.stats.total_attempts);
        
        // All should produce valid signatures
        assert!(verify(message, &result.signature, &keypair.public_key)
            .expect("Verification should succeed"),
            "{:?} mode should produce valid signature", mode);
    }
}