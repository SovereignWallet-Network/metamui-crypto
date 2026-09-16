//! Differential testing framework for Falcon-512
//! 
//! This module provides tools to compare our implementation against
//! reference implementations or test vectors to ensure correctness.

use crate::error::{Result, Falcon512Error};
use crate::PublicKey;
use crate::nist_vectors::NistVector;
use alloc::vec::Vec;
use alloc::string::{String, ToString};

/// Result of differential testing
#[derive(Debug, Clone)]
pub enum DiffTestResult {
    /// Both implementations agree
    Pass,
    /// Implementations disagree on key generation
    KeyGenMismatch(String),
    /// Implementations disagree on signing
    SigningMismatch(String),
    /// Implementations disagree on verification
    VerificationMismatch(String),
    /// One implementation failed where other succeeded
    FailureMismatch(String),
}

/// Differential test case
#[derive(Debug, Clone)]
pub struct DiffTestCase {
    /// Test case ID
    pub id: String,
    /// Seed for deterministic operations
    pub seed: Vec<u8>,
    /// Message to sign
    pub message: Vec<u8>,
    /// Expected results (if available)
    pub expected: Option<ExpectedResults>,
}

/// Expected results from reference implementation
#[derive(Debug, Clone)]
pub struct ExpectedResults {
    /// Expected public key
    pub public_key: Option<Vec<u8>>,
    /// Expected signature
    pub signature: Option<Vec<u8>>,
    /// Expected verification result
    pub verify_result: Option<bool>,
}

/// Differential testing engine
pub struct DiffTestEngine {
    /// Test cases to run
    test_cases: Vec<DiffTestCase>,
    /// Results of testing
    results: Vec<(String, DiffTestResult)>,
}

impl DiffTestEngine {
    /// Create a new differential testing engine
    pub fn new() -> Self {
        Self {
            test_cases: Vec::new(),
            results: Vec::new(),
        }
    }
    
    /// Add a test case
    pub fn add_test_case(&mut self, test_case: DiffTestCase) {
        self.test_cases.push(test_case);
    }
    
    /// Load NIST test vectors
    pub fn load_nist_vectors(&mut self, vectors: &[NistVector]) {
        for (i, vector) in vectors.iter().enumerate() {
            let test_case = DiffTestCase {
                id: format!("NIST_{}", i),
                seed: vector.seed.clone(),
                message: vector.msg.clone(),
                expected: Some(ExpectedResults {
                    public_key: Some(vector.pk.clone()),
                    signature: Some(vector.sig.clone()),
                    verify_result: Some(true), // NIST vectors should always verify
                }),
            };
            self.add_test_case(test_case);
        }
    }
    
    /// Run all test cases
    pub fn run_all(&mut self) -> Result<DiffTestReport> {
        Err(Falcon512Error::NotImplemented)
    }
    
    /// Run a single test case
    fn run_single(&self, _test_case: &DiffTestCase) -> Result<DiffTestResult> {
        Err(Falcon512Error::NotImplemented)
    }
    
    /// Encode public key for comparison (simplified)
    fn encode_public_key(&self, pk: &PublicKey) -> Vec<u8> {
        let mut encoded = Vec::new();
        for &coeff in &pk.h.coeffs {
            encoded.push((coeff & 0xff) as u8);
            encoded.push(((coeff >> 8) & 0xff) as u8);
        }
        encoded
    }
}

/// Report from differential testing
#[derive(Debug)]
pub struct DiffTestReport {
    /// Total test cases
    pub total: usize,
    /// Passed test cases
    pub passed: usize,
    /// Failed test cases
    pub failed: usize,
    /// Breakdown by failure type
    pub failure_breakdown: FailureBreakdown,
    /// Detailed results
    pub details: Vec<(String, DiffTestResult)>,
}

#[derive(Debug, Default)]
pub struct FailureBreakdown {
    pub keygen_mismatches: usize,
    pub signing_mismatches: usize,
    pub verification_mismatches: usize,
    pub failure_mismatches: usize,
}

impl DiffTestReport {
    fn from_results(results: &[(String, DiffTestResult)]) -> Self {
        let total = results.len();
        let passed = results.iter()
            .filter(|(_, r)| matches!(r, DiffTestResult::Pass))
            .count();
        let failed = total - passed;
        
        let mut breakdown = FailureBreakdown::default();
        for (_, result) in results {
            match result {
                DiffTestResult::KeyGenMismatch(_) => breakdown.keygen_mismatches += 1,
                DiffTestResult::SigningMismatch(_) => breakdown.signing_mismatches += 1,
                DiffTestResult::VerificationMismatch(_) => breakdown.verification_mismatches += 1,
                DiffTestResult::FailureMismatch(_) => breakdown.failure_mismatches += 1,
                DiffTestResult::Pass => {}
            }
        }
        
        Self {
            total,
            passed,
            failed,
            failure_breakdown: breakdown,
            details: results.to_vec(),
        }
    }
    
    /// Print a summary of the report
    pub fn print_summary(&self) {
        println!("\n=== Differential Testing Report ===");
        println!("Total test cases: {}", self.total);
        println!("Passed: {} ({:.1}%)", self.passed, 
                 100.0 * self.passed as f64 / self.total as f64);
        println!("Failed: {} ({:.1}%)", self.failed,
                 100.0 * self.failed as f64 / self.total as f64);
        
        if self.failed > 0 {
            println!("\n--- Failure Breakdown ---");
            if self.failure_breakdown.keygen_mismatches > 0 {
                println!("KeyGen mismatches: {}", self.failure_breakdown.keygen_mismatches);
            }
            if self.failure_breakdown.signing_mismatches > 0 {
                println!("Signing mismatches: {}", self.failure_breakdown.signing_mismatches);
            }
            if self.failure_breakdown.verification_mismatches > 0 {
                println!("Verification mismatches: {}", self.failure_breakdown.verification_mismatches);
            }
            if self.failure_breakdown.failure_mismatches > 0 {
                println!("Failure mismatches: {}", self.failure_breakdown.failure_mismatches);
            }
            
            // Show first few failures
            println!("\n--- Sample Failures ---");
            for (id, result) in self.details.iter().take(5) {
                if !matches!(result, DiffTestResult::Pass) {
                    println!("  {}: {:?}", id, result);
                }
            }
        }
    }
}

/// Cross-validation with different parameter sets
pub struct CrossValidator {
    /// Different configurations to test
    configs: Vec<ValidationConfig>,
}

#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Configuration name
    pub name: String,
    /// Whether to use compressed signatures
    pub use_compression: bool,
    /// Max attempts for signing
    pub max_attempts: usize,
    /// Norm bound to use
    pub norm_bound: f64,
}

impl CrossValidator {
    /// Create a new cross-validator
    pub fn new() -> Self {
        let configs = vec![
            ValidationConfig {
                name: "Standard".to_string(),
                use_compression: false,
                max_attempts: 30,
                norm_bound: 34034726.0_f64.sqrt(),
            },
            ValidationConfig {
                name: "Compressed".to_string(),
                use_compression: true,
                max_attempts: 30,
                norm_bound: 34034726.0_f64.sqrt(),
            },
            ValidationConfig {
                name: "HighSecurity".to_string(),
                use_compression: false,
                max_attempts: 256,
                norm_bound: 30000000.0_f64.sqrt(),
            },
        ];
        
        Self { configs }
    }
    
    /// Validate across all configurations
    pub fn validate_all(&self, _message: &[u8]) -> Result<CrossValidationReport> {
        Err(Falcon512Error::NotImplemented)
    }
}

/// Report from cross-validation
#[derive(Debug)]
pub struct CrossValidationReport {
    /// Results for each configuration
    pub results: Vec<(String, bool)>,
}

impl CrossValidationReport {
    /// Print the report
    pub fn print(&self) {
        println!("\n=== Cross-Validation Report ===");
        for (config, valid) in &self.results {
            println!("{}: {}", config, if *valid { "✓ PASS" } else { "✗ FAIL" });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_differential_engine_basic() {
        let mut engine = DiffTestEngine::new();
        
        // Add a simple test case
        let test_case = DiffTestCase {
            id: "test_1".to_string(),
            seed: vec![0x42; 48],
            message: b"Test message".to_vec(),
            expected: None, // No reference to compare against
        };
        
        engine.add_test_case(test_case);
        
        assert!(matches!(
            engine.run_all(),
            Err(Falcon512Error::NotImplemented)
        ));
    }
    
    #[test]
    fn test_cross_validation_fails_closed_until_exact_reference_support_exists() {
        let validator = CrossValidator::new();
        let message = b"Cross-validation test message";

        assert!(matches!(
            validator.validate_all(message),
            Err(Falcon512Error::NotImplemented)
        ));
    }

    #[test]
    fn test_load_nist_vectors_records_expected_results() {
        let mut engine = DiffTestEngine::new();
        let vector = NistVector {
            count: 7,
            seed: vec![0x11; 48],
            msg: b"vector message".to_vec(),
            pk: vec![0x22; 32],
            sk: vec![0x33; 32],
            sig: vec![0x44; 64],
        };

        engine.load_nist_vectors(&[vector]);

        assert_eq!(engine.test_cases.len(), 1);
        assert_eq!(engine.test_cases[0].id, "NIST_0");
        assert_eq!(engine.test_cases[0].seed, vec![0x11; 48]);
        assert_eq!(engine.test_cases[0].message, b"vector message".to_vec());
        let expected = engine.test_cases[0]
            .expected
            .as_ref()
            .expect("expected results should be recorded");
        assert_eq!(expected.public_key.as_ref(), Some(&vec![0x22; 32]));
        assert_eq!(expected.signature.as_ref(), Some(&vec![0x44; 64]));
        assert_eq!(expected.verify_result, Some(true));
    }
}
