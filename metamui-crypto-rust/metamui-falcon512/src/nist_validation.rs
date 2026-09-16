//! NIST test vector validation for Falcon-512 and Falcon-1024
//! 
//! This module validates our implementation against official NIST test vectors
//! to ensure compliance with the specification.

use crate::error::{Result, Falcon512Error};
use crate::{generate_keypair, sign, verify, PublicKey};
use crate::falcon1024;
use crate::falcon_variants::FalconVariant;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// NIST test vector structure
#[derive(Debug, Deserialize, Serialize)]
pub struct NistTestVector {
    /// Test vector count/index
    pub count: usize,
    
    /// Seed for key generation (hex)
    pub seed: String,
    
    /// Message to sign (hex)
    pub msg: String,
    
    /// Public key (hex)
    pub pk: String,
    
    /// Secret/private key (hex)
    pub sk: String,
    
    /// Signature (hex)
    pub sig: String,
    
    /// Expected verification result
    #[serde(default = "default_true")]
    pub valid: bool,
}

fn default_true() -> bool {
    true
}

/// Collection of NIST test vectors
#[derive(Debug, Deserialize, Serialize)]
pub struct NistTestVectors {
    /// Algorithm name (e.g., "Falcon-512", "Falcon-1024")
    pub algorithm: String,
    
    /// Test vectors
    pub tests: Vec<NistTestVector>,
}

/// Load test vectors from JSON file
pub fn load_test_vectors(path: &str) -> Result<NistTestVectors> {
    #[cfg(feature = "std")]
    {
        use std::fs;
        let content = fs::read_to_string(path)
            .map_err(|_| Falcon512Error::InvalidSignature)?;
        serde_json::from_str(&content)
            .map_err(|_| Falcon512Error::InvalidSignature)
    }
    
    #[cfg(not(feature = "std"))]
    {
        // In no_std environment, vectors must be embedded
        Err(Falcon512Error::InvalidSignature)
    }
}

/// Validate a single test vector for Falcon-512
pub fn validate_falcon512_vector(vector: &NistTestVector) -> Result<bool> {
    // Decode hex strings
    let message = hex_decode(&vector.msg)?;
    let signature = hex_decode(&vector.sig)?;
    let pk_bytes = hex_decode(&vector.pk)?;
    
    // Parse public key
    let public_key = PublicKey::from_bytes(&pk_bytes)?;
    
    // Verify signature
    let result = verify(&message, &signature, &public_key)?;
    
    // Check if result matches expected
    Ok(result == vector.valid)
}

/// Validate a single test vector for Falcon-1024
pub fn validate_falcon1024_vector(vector: &NistTestVector) -> Result<bool> {
    // Decode hex strings
    let message = hex_decode(&vector.msg)?;
    let signature = hex_decode(&vector.sig)?;
    let pk_bytes = hex_decode(&vector.pk)?;
    
    // Parse public key
    let public_key = falcon1024::PublicKey1024::from_bytes(&pk_bytes)?;
    
    // Verify signature
    let result = falcon1024::verify_1024(&message, &signature, &public_key)?;
    
    // Check if result matches expected
    Ok(result == vector.valid)
}

/// Run validation against all test vectors
pub fn validate_all_vectors(vectors: &NistTestVectors) -> ValidationReport {
    let mut report = ValidationReport::new(&vectors.algorithm);
    
    for (i, vector) in vectors.tests.iter().enumerate() {
        let result = if vectors.algorithm.contains("1024") {
            validate_falcon1024_vector(vector)
        } else {
            validate_falcon512_vector(vector)
        };
        
        match result {
            Ok(passed) => {
                if passed {
                    report.passed += 1;
                } else {
                    report.failed += 1;
                    report.failed_indices.push(i);
                }
            }
            Err(e) => {
                report.errors += 1;
                report.error_indices.push((i, format!("{:?}", e)));
            }
        }
    }
    
    report.total = vectors.tests.len();
    report
}

/// Validation report
#[derive(Debug)]
pub struct ValidationReport {
    pub algorithm: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub errors: usize,
    pub failed_indices: Vec<usize>,
    pub error_indices: Vec<(usize, String)>,
}

impl ValidationReport {
    fn new(algorithm: &str) -> Self {
        ValidationReport {
            algorithm: algorithm.to_string(),
            total: 0,
            passed: 0,
            failed: 0,
            errors: 0,
            failed_indices: Vec::new(),
            error_indices: Vec::new(),
        }
    }
    
    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.errors == 0 && self.passed == self.total
    }
    
    /// Get pass rate as percentage
    pub fn pass_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.passed as f64 / self.total as f64) * 100.0
        }
    }
    
    /// Print summary
    pub fn print_summary(&self) {
        println!("=== NIST Test Vector Validation Report ===");
        println!("Algorithm: {}", self.algorithm);
        println!("Total tests: {}", self.total);
        println!("Passed: {} ({:.1}%)", self.passed, self.pass_rate());
        println!("Failed: {}", self.failed);
        println!("Errors: {}", self.errors);
        
        if !self.failed_indices.is_empty() {
            println!("\nFailed test indices: {:?}", self.failed_indices);
        }
        
        if !self.error_indices.is_empty() {
            println!("\nErrors:");
            for (idx, err) in &self.error_indices {
                println!("  Test {}: {}", idx, err);
            }
        }
        
        if self.all_passed() {
            println!("\n??All tests PASSED!");
        } else {
            println!("\n??Some tests FAILED");
        }
    }
}

/// Decode hex string to bytes
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(Falcon512Error::InvalidSignature);
    }
    
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i+2], 16)
            .map_err(|_| Falcon512Error::InvalidSignature)?;
        bytes.push(byte);
    }
    
    Ok(bytes)
}

/// Generate test vectors for validation
pub fn generate_test_vectors(variant: FalconVariant, count: usize) -> NistTestVectors {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    
    let algorithm = match variant {
        FalconVariant::Falcon512 => "Falcon-512",
        FalconVariant::Falcon1024 => "Falcon-1024",
    };
    
    let mut vectors = NistTestVectors {
        algorithm: algorithm.to_string(),
        tests: Vec::new(),
    };
    
    for i in 0..count {
        let seed = [i as u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        
        // Generate message
        let msg_len = (i * 7 + 13) % 256; // Vary message length
        let mut message = vec![0u8; msg_len];
        
        // Use RngCore trait method
        use rand::RngCore;
        rng.fill_bytes(&mut message);
        
        // Generate keypair and sign
        let (pk_bytes, sk_bytes, sig_bytes) = match variant {
            FalconVariant::Falcon512 => {
                let keypair = generate_keypair(&mut rng).unwrap();
                let signature = sign(&message, &keypair.private_key, &mut rng).unwrap();

                let pk = keypair.public_key.to_bytes();
                let sk = keypair.private_key.to_bytes();

                (pk, sk, signature)
            }
            FalconVariant::Falcon1024 => {
                let keypair = falcon1024::generate_keypair_1024(&mut rng).unwrap();
                let signature = falcon1024::sign_1024(&message, &keypair.private_key, &mut rng).unwrap();

                let pk = keypair.public_key.to_bytes();
                let sk = keypair.private_key.to_bytes();

                (pk, sk, signature)
            }
        };
        
        vectors.tests.push(NistTestVector {
            count: i,
            seed: hex_encode(&seed),
            msg: hex_encode(&message),
            pk: hex_encode(&pk_bytes),
            sk: hex_encode(&sk_bytes),
            sig: hex_encode(&sig_bytes),
            valid: true,
        });
    }
    
    vectors
}

/// Encode bytes to hex string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hex_encoding() {
        let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "0123456789abcdef");
        
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }
    
    #[test]
    fn test_generate_vectors_falcon512() {
        let vectors = generate_test_vectors(FalconVariant::Falcon512, 5);
        assert_eq!(vectors.algorithm, "Falcon-512");
        assert_eq!(vectors.tests.len(), 5);
        
        // Validate generated vectors
        for vector in &vectors.tests {
            let result = validate_falcon512_vector(vector).unwrap();
            assert!(result, "Generated vector should be valid");
            let sk = hex_decode(&vector.sk).unwrap();
            assert!(!sk.iter().all(|&byte| byte == 0), "secret key must not be placeholder zeros");
        }
    }
    
    #[test]
    fn test_generate_vectors_falcon1024() {
        let vectors = generate_test_vectors(FalconVariant::Falcon1024, 3);
        assert_eq!(vectors.algorithm, "Falcon-1024");
        assert_eq!(vectors.tests.len(), 3);
        
        // Validate generated vectors
        for vector in &vectors.tests {
            let result = validate_falcon1024_vector(vector).unwrap();
            assert!(result, "Generated vector should be valid");
            let sk = hex_decode(&vector.sk).unwrap();
            assert!(!sk.iter().all(|&byte| byte == 0), "secret key must not be placeholder zeros");
        }
    }
    
    #[test]
    fn test_validation_report() {
        let mut report = ValidationReport::new("Test");
        report.total = 10;
        report.passed = 8;
        report.failed = 1;
        report.errors = 1;
        
        assert_eq!(report.pass_rate(), 80.0);
        assert!(!report.all_passed());
        
        let mut perfect_report = ValidationReport::new("Perfect");
        perfect_report.total = 5;
        perfect_report.passed = 5;
        
        assert_eq!(perfect_report.pass_rate(), 100.0);
        assert!(perfect_report.all_passed());
    }
}
