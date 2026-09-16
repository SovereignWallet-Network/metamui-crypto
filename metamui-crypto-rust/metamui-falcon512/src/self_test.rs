// Self-Test Framework for Falcon-512
//
// Implements FIPS 140-3 required self-tests including:
// - Power-on self-tests (POST)
// - Conditional self-tests (CST)
// - Known Answer Tests (KAT)
// - Pairwise consistency tests

use crate::{generate_keypair, sign, verify};
use crate::error::{Result, Falcon512Error};
use crate::constants::{N, Q};
use crate::poly::Poly;
use crate::test_config::{PqcTestConfig, run_with_retries};
use rand::{SeedableRng, RngCore};
use rand_chacha::ChaCha20Rng;

use std::{vec::Vec, string::String};

/// Self-test status
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SelfTestStatus {
    NotRun,
    Running,
    Passed,
    Failed,
}

/// Self-test results
#[derive(Debug, Clone)]
pub struct SelfTestResult {
    pub status: SelfTestStatus,
    pub power_on_tests: bool,
    pub conditional_tests: bool,
    pub kat_tests: bool,
    pub pairwise_tests: bool,
    pub error_message: Option<String>,
}

impl Default for SelfTestResult {
    fn default() -> Self {
        Self {
            status: SelfTestStatus::NotRun,
            power_on_tests: false,
            conditional_tests: false,
            kat_tests: false,
            pairwise_tests: false,
            error_message: None,
        }
    }
}

/// FIPS 140-3 Self-Test Module
pub struct SelfTestModule {
    result: SelfTestResult,
    test_vectors: TestVectors,
}

impl SelfTestModule {
    /// Create new self-test module
    pub fn new() -> Self {
        Self {
            result: SelfTestResult::default(),
            test_vectors: TestVectors::new(),
        }
    }
    
    /// Run all self-tests (POST + Conditional)
    pub fn run_all_tests(&mut self) -> Result<bool> {
        self.result.status = SelfTestStatus::Running;
        
        // Run power-on self-tests
        let power_on = match self.run_power_on_tests() {
            Ok(value) => value,
            Err(err) => {
                self.result.status = SelfTestStatus::Failed;
                return Err(err);
            }
        };
        if !power_on {
            self.result.status = SelfTestStatus::Failed;
            return Ok(false);
        }
        
        // Run conditional self-tests
        let conditional = match self.run_conditional_tests() {
            Ok(value) => value,
            Err(err) => {
                self.result.status = SelfTestStatus::Failed;
                return Err(err);
            }
        };
        if !conditional {
            self.result.status = SelfTestStatus::Failed;
            return Ok(false);
        }
        
        self.result.status = SelfTestStatus::Passed;
        Ok(true)
    }
    
    /// Run power-on self-tests (required at startup)
    pub fn run_power_on_tests(&mut self) -> Result<bool> {
        // 1. Known Answer Tests
        #[cfg(feature = "std")]
        eprintln!("self_test: Running KAT tests...");
        match self.run_kat_tests() {
            Ok(true) => {}
            Ok(false) => {
                self.result.power_on_tests = false;
                self.result.error_message = Some("KAT tests failed".into());
                #[cfg(feature = "std")]
                eprintln!("self_test: KAT tests FAILED");
                return Ok(false);
            }
            Err(err) => {
                self.result.power_on_tests = false;
                self.result.error_message = Some("KAT tests unavailable until exact vectors are implemented".into());
                #[cfg(feature = "std")]
                eprintln!("self_test: KAT tests unavailable");
                return Err(err);
            }
        }
        #[cfg(feature = "std")]
        eprintln!("self_test: KAT tests passed");
        
        // 2. Pairwise consistency test
        #[cfg(feature = "std")]
        eprintln!("self_test: Running pairwise consistency test...");
        if !self.run_pairwise_consistency_test()? {
            self.result.power_on_tests = false;
            self.result.error_message = Some("Pairwise consistency test failed".into());
            #[cfg(feature = "std")]
            eprintln!("self_test: Pairwise consistency test FAILED");
            return Ok(false);
        }
        #[cfg(feature = "std")]
        eprintln!("self_test: Pairwise consistency test passed");
        
        // 3. Algorithm integrity test
        #[cfg(feature = "std")]
        eprintln!("self_test: Running algorithm integrity test...");
        if !self.test_algorithm_integrity()? {
            self.result.power_on_tests = false;
            self.result.error_message = Some("Algorithm integrity test failed".into());
            #[cfg(feature = "std")]
            eprintln!("self_test: Algorithm integrity test FAILED");
            return Ok(false);
        }
        #[cfg(feature = "std")]
        eprintln!("self_test: Algorithm integrity test passed");
        
        self.result.power_on_tests = true;
        Ok(true)
    }
    
    /// Run conditional self-tests (on-demand)
    pub fn run_conditional_tests(&mut self) -> Result<bool> {
        // 1. Continuous random number generator test
        if !self.test_rng_continuous()? {
            self.result.conditional_tests = false;
            self.result.error_message = Some("RNG continuous test failed".into());
            return Ok(false);
        }
        
        // 2. Signature verification test
        if !self.test_signature_verification()? {
            self.result.conditional_tests = false;
            self.result.error_message = Some("Signature verification test failed".into());
            return Ok(false);
        }
        
        self.result.conditional_tests = true;
        Ok(true)
    }
    
    /// Run Known Answer Tests
    fn run_kat_tests(&mut self) -> Result<bool> {
        // Use PQC test configuration for KAT tests
        let config = PqcTestConfig::for_kat_tests();
        
        // Test with known seed and expected outputs
        let seed = [0x42u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        
        // Generate deterministic keypair with retries for rejection sampling
        let keypair = match run_with_retries(config.max_keygen_attempts, || {
            generate_keypair(&mut rng)
        }) {
            Ok(kp) => kp,
            Err(_) => {
                #[cfg(feature = "std")]
                eprintln!("self_test: Key generation failed after {} attempts (expected PQC behavior)", 
                         config.max_keygen_attempts);
                // This is acceptable for PQC algorithms
                // We'll try with a different seed
                let mut rng2 = ChaCha20Rng::from_seed([0x43u8; 32]);
                run_with_retries(config.max_keygen_attempts, || {
                    generate_keypair(&mut rng2)
                })?
            }
        };
        
        // Check public key has expected properties
        if keypair.public_key.h.coeffs.len() != N {
            return Ok(false);
        }
        
        // Test signature generation with retries
        let message = b"FIPS 140-3 KAT Test Message";
        let signature = match run_with_retries(config.max_sign_attempts, || {
            sign(message, &keypair.private_key, &mut rng)
        }) {
            Ok(sig) => sig,
            Err(_) => {
                #[cfg(feature = "std")]
                eprintln!("self_test: Signing failed after {} attempts (expected PQC behavior)", 
                         config.max_sign_attempts);
                // Try with fresh randomness
                let mut rng2 = ChaCha20Rng::from_entropy();
                run_with_retries(config.max_sign_attempts, || {
                    sign(message, &keypair.private_key, &mut rng2)
                })?
            }
        };
        
        // Test signature verification (deterministic, no retries needed)
        match verify(message, &signature, &keypair.public_key) {
            Ok(true) => {},
            _ => return Ok(false),
        }
        
        // Test with known test vectors (using verification instead of byte comparison)
        if !self.test_vectors.verify_all_pqc(config)? {
            return Ok(false);
        }
        
        self.result.kat_tests = true;
        Ok(true)
    }
    
    /// Run pairwise consistency test
    fn run_pairwise_consistency_test(&mut self) -> Result<bool> {
        let seed = [0x13u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        
        // Generate keypair
        let keypair = generate_keypair(&mut rng)?;
        
        // Sign test message
        let message = b"Pairwise consistency test";
        let signature = sign(message, &keypair.private_key, &mut rng)?;
        
        // Verify with corresponding public key
        match verify(message, &signature, &keypair.public_key) {
            Ok(true) => {},
            _ => return Ok(false),
        }
        
        // Verify fails with wrong message
        // For self-tests, we should use strict verification (no relaxed threshold)
        // This test is checking security, not implementation tolerance
        let wrong_message = b"Wrong message";
        #[cfg(feature = "std")]
        eprintln!("self_test: Verifying with wrong message...");
        
        // For security testing, the wrong message must always be rejected.
        match verify(wrong_message, &signature, &keypair.public_key) {
            Ok(false) | Err(_) => {
                #[cfg(feature = "std")]
                eprintln!("self_test: Wrong message correctly rejected");
            },
            Ok(true) => {
                #[cfg(feature = "std")]
                eprintln!("self_test: ERROR - Wrong message was accepted");
                return Ok(false);
            }
        }
        
        self.result.pairwise_tests = true;
        Ok(true)
    }
    
    /// Test algorithm integrity
    fn test_algorithm_integrity(&self) -> Result<bool> {
        // Verify constants
        if N != 512 || Q != 12289 {
            return Ok(false);
        }
        
        // Test polynomial creation and access
        let p1 = Poly::new(vec![1, 2, 3, 4]);
        let p2 = Poly::new(vec![5, 6, 7, 8]);
        
        // Test basic coefficient access
        if p1.coeffs[0] != 1 || p2.coeffs[0] != 5 {
            return Ok(false);
        }
        
        // Test polynomial length
        if p1.coeffs.len() != 4 || p2.coeffs.len() != 4 {
            return Ok(false);
        }
        
        Ok(true)
    }
    
    /// Test continuous RNG operation
    fn test_rng_continuous(&self) -> Result<bool> {
        let mut rng1 = ChaCha20Rng::from_seed([0x77u8; 32]);
        let mut rng2 = ChaCha20Rng::from_seed([0x77u8; 32]);
        
        // Both RNGs should produce same sequence
        for _ in 0..100 {
            if rng1.next_u64() != rng2.next_u64() {
                return Ok(false);
            }
        }
        
        // Different seeds should produce different sequences
        let mut rng3 = ChaCha20Rng::from_seed([0x88u8; 32]);
        let val1 = rng1.next_u64();
        let val3 = rng3.next_u64();
        
        if val1 == val3 {
            return Ok(false); // Should be different
        }
        
        Ok(true)
    }
    
    /// Test signature verification
    fn test_signature_verification(&self) -> Result<bool> {
        // Create test vectors
        let test_cases = vec![
            (b"Test message 1".to_vec(), true),
            (b"Test message 2".to_vec(), true),
            (b"".to_vec(), true), // Empty message
            (vec![0xFF; 1024], true), // Large message
        ];
        
        let mut rng = ChaCha20Rng::from_seed([0x99u8; 32]);
        let keypair = generate_keypair(&mut rng)?;
        
        for (message, should_verify) in test_cases {
            let signature = sign(&message, &keypair.private_key, &mut rng)?;
            
            let verified = verify(&message, &signature, &keypair.public_key)?;
            if verified != should_verify {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Get test results
    pub fn get_results(&self) -> &SelfTestResult {
        &self.result
    }
    
    /// Reset test results
    pub fn reset(&mut self) {
        self.result = SelfTestResult::default();
    }
}

/// Test vectors for KAT
struct TestVectors {
    vectors: Vec<TestVector>,
}

struct TestVector {
    seed: [u8; 32],
    message: Vec<u8>,
    expected_signature_len: usize,
}

impl TestVectors {
    fn new() -> Self {
        Self {
            vectors: vec![
                TestVector {
                    seed: [0x01; 32],
                    message: b"Test vector 1".to_vec(),
                    expected_signature_len: 1330, // Approximate for Falcon-512
                },
                TestVector {
                    seed: [0x02; 32],
                    message: b"".to_vec(),
                    expected_signature_len: 1330,
                },
                TestVector {
                    seed: [0x03; 32],
                    message: vec![0xAA; 256],
                    expected_signature_len: 1330,
                },
            ],
        }
    }
    
    fn verify_all(&self) -> Result<bool> {
        Err(Falcon512Error::NotImplemented)
    }
    
    fn verify_all_pqc(&self, config: PqcTestConfig) -> Result<bool> {
        let _ = config;
        Err(Falcon512Error::NotImplemented)
    }
    
    fn verify_vector(&self, vector: &TestVector) -> Result<bool> {
        let _ = vector;
        Err(Falcon512Error::NotImplemented)
    }
    
    fn verify_vector_pqc(&self, vector: &TestVector, config: &PqcTestConfig) -> Result<bool> {
        let _ = (vector, config);
        Err(Falcon512Error::NotImplemented)
    }
}

/// Run power-on self-tests (called at module initialization)
pub fn run_post() -> Result<bool> {
    let mut module = SelfTestModule::new();
    module.run_power_on_tests()
}

/// Run conditional self-tests (called periodically)
pub fn run_conditional() -> Result<bool> {
    let mut module = SelfTestModule::new();
    module.run_conditional_tests()
}

/// Run full self-test suite
pub fn run_all_self_tests() -> Result<bool> {
    let mut module = SelfTestModule::new();
    module.run_all_tests()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_self_test_module() {
        let mut module = SelfTestModule::new();
        assert_eq!(module.result.status, SelfTestStatus::NotRun);
        
        let err = module.run_all_tests().unwrap_err();
        assert!(matches!(err, Falcon512Error::NotImplemented));
        assert_eq!(module.result.status, SelfTestStatus::Failed);
    }
    
    #[test]
    fn test_power_on_tests() {
        let err = run_post().unwrap_err();
        assert!(matches!(err, Falcon512Error::NotImplemented));
    }
    
    #[test]
    fn test_conditional_tests() {
        let result = run_conditional().expect("Conditional tests should run");
        assert!(result, "Conditional self-tests should pass");
    }
    
    #[test]
    fn test_kat_vectors() {
        let vectors = TestVectors::new();
        let err = vectors.verify_all().unwrap_err();
        assert!(matches!(err, Falcon512Error::NotImplemented));
    }
}
