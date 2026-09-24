//! ML-DSA Test Vector Generator (Refactored with metamui-acvp-core)
//!
//! This module generates comprehensive FIPS 204 compliant test vectors for ML-DSA.
//! It creates test vectors for key generation, signature generation, and signature verification.
//!
//! Refactored to use generic metamui-acvp-core infrastructure with deterministic ChaCha20Rng.

use crate::{MlDsa44, MlDsa65, MlDsa87};
use metamui_acvp_core::{AcvpTestSuite, AcvpTestGroup, AcvpTestCase, FieldValue};
use rand_core::{SeedableRng, RngCore};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;

/// Test vector generator for ML-DSA implementations
pub struct MlDsaTestVectorGenerator {
    rng: ChaCha20Rng,
    tc_id_counter: u32,
    tg_id_counter: u32,
}

/// Test vector generation options
#[derive(Debug, Clone)]
pub struct TestVectorOptions {
    pub num_keygen_tests: usize,
    pub num_siggen_tests: usize,
    pub num_sigver_valid_tests: usize,
    pub num_sigver_invalid_tests: usize,
    pub include_edge_cases: bool,
    pub deterministic_signing: bool,
}

impl Default for TestVectorOptions {
    fn default() -> Self {
        Self {
            num_keygen_tests: 10,
            num_siggen_tests: 15,
            num_sigver_valid_tests: 10,
            num_sigver_invalid_tests: 10,
            include_edge_cases: true,
            deterministic_signing: true,
        }
    }
}

/// Message patterns for test vector generation
#[derive(Debug, Clone)]
pub enum MessagePattern {
    Empty,
    Short(usize),      // Specific short length
    Medium(usize),     // Medium length (100-1000 bytes)
    Long(usize),       // Long length (1000+ bytes)
    Pattern(Vec<u8>),  // Specific pattern
    Random(usize),     // Random bytes of specific length
}

impl MlDsaTestVectorGenerator {
    /// Create a new test vector generator with deterministic RNG
    pub fn new() -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(0x1234567890ABCDEF),
            tc_id_counter: 1,
            tg_id_counter: 1,
        }
    }

    /// Get next test case ID
    fn next_tc_id(&mut self) -> u32 {
        let id = self.tc_id_counter;
        self.tc_id_counter += 1;
        id
    }

    /// Get next test group ID
    fn next_tg_id(&mut self) -> u32 {
        let id = self.tg_id_counter;
        self.tg_id_counter += 1;
        id
    }

    /// Generate comprehensive ML-DSA test vectors for all parameter sets
    pub fn generate_comprehensive_test_suite(&mut self, options: &TestVectorOptions) -> AcvpTestSuite {
        let mut test_groups = Vec::new();

        // Generate test vectors for each ML-DSA parameter set
        for param_set in &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
            test_groups.extend(self.generate_parameter_set_tests(param_set, options));
        }

        AcvpTestSuite {
            vs_id: None,
            algorithm: "ML-DSA".to_string(),
            mode: Some("sigGen".to_string()),
            revision: Some("FIPS204".to_string()),
            is_sample: Some(false),
            test_groups,
            metadata: HashMap::new(),
        }
    }

    /// Generate test vectors for a specific parameter set
    fn generate_parameter_set_tests(&mut self, param_set: &str, options: &TestVectorOptions) -> Vec<AcvpTestGroup> {
        let mut groups = Vec::new();

        // Key Generation Tests
        if options.num_keygen_tests > 0 {
            groups.push(self.generate_keygen_tests(param_set, options.num_keygen_tests));
        }

        // Signature Generation Tests
        if options.num_siggen_tests > 0 {
            groups.push(self.generate_siggen_tests(param_set, options.num_siggen_tests, options.deterministic_signing));
        }

        // Signature Verification Tests (Valid)
        if options.num_sigver_valid_tests > 0 {
            groups.push(self.generate_sigver_tests(param_set, options.num_sigver_valid_tests, true));
        }

        // Signature Verification Tests (Invalid)
        if options.num_sigver_invalid_tests > 0 {
            groups.push(self.generate_sigver_tests(param_set, options.num_sigver_invalid_tests, false));
        }

        // Edge Case Tests
        if options.include_edge_cases {
            groups.push(self.generate_edge_case_tests(param_set));
        }

        groups
    }

    /// Generate key generation test vectors
    fn generate_keygen_tests(&mut self, param_set: &str, num_tests: usize) -> AcvpTestGroup {
        let mut tests = Vec::new();

        for _ in 0..num_tests {
            let tc_id = self.next_tc_id();

            let (pk_hex, sk_hex) = match param_set {
                "ML-DSA-44" => {
                    let (pk, sk) = MlDsa44::generate_keypair();
                    (hex::encode(pk), hex::encode(sk))
                },
                "ML-DSA-65" => {
                    let (pk, sk) = MlDsa65::generate_keypair();
                    (hex::encode(pk), hex::encode(sk))
                },
                "ML-DSA-87" => {
                    let (pk, sk) = MlDsa87::generate_keypair();
                    (hex::encode(pk), hex::encode(sk))
                },
                _ => panic!("Unknown parameter set: {}", param_set),
            };

            let mut test_case = AcvpTestCase::new(tc_id);
            test_case.fields.insert("sk".to_string(), FieldValue::String(sk_hex));
            test_case.fields.insert("pk".to_string(), FieldValue::String(pk_hex));
            test_case.fields.insert("testPassed".to_string(), FieldValue::Bool(true));

            tests.push(test_case);
        }

        let tg_id = self.next_tg_id();
        let mut parameters = HashMap::new();
        parameters.insert("deterministic".to_string(), FieldValue::Bool(false));

        AcvpTestGroup {
            tg_id,
            test_type: "keyGen".to_string(),
            parameter_set: param_set.to_string(),
            tests,
            parameters,
        }
    }

    /// Generate signature generation test vectors
    fn generate_siggen_tests(&mut self, param_set: &str, num_tests: usize, deterministic: bool) -> AcvpTestGroup {
        let mut tests = Vec::new();
        let message_patterns = self.get_test_message_patterns();

        for i in 0..num_tests {
            let tc_id = self.next_tc_id();
            let pattern_idx = i % message_patterns.len();
            let message = self.generate_message(&message_patterns[pattern_idx]);

            let (pk_hex, sk_hex, sig_hex) = match param_set {
                "ML-DSA-44" => {
                    let (pk, sk) = MlDsa44::generate_keypair();
                    let signature = MlDsa44::sign(&sk, &message);
                    (hex::encode(pk), hex::encode(sk), hex::encode(signature))
                },
                "ML-DSA-65" => {
                    let (pk, sk) = MlDsa65::generate_keypair();
                    let signature = MlDsa65::sign(&sk, &message);
                    (hex::encode(pk), hex::encode(sk), hex::encode(signature))
                },
                "ML-DSA-87" => {
                    let (pk, sk) = MlDsa87::generate_keypair();
                    let signature = MlDsa87::sign(&sk, &message);
                    (hex::encode(pk), hex::encode(sk), hex::encode(signature))
                },
                _ => panic!("Unknown parameter set: {}", param_set),
            };

            let mut test_case = AcvpTestCase::new(tc_id);
            test_case.fields.insert("sk".to_string(), FieldValue::String(sk_hex));
            test_case.fields.insert("pk".to_string(), FieldValue::String(pk_hex));
            test_case.fields.insert("message".to_string(), FieldValue::String(hex::encode(&message)));
            test_case.fields.insert("context".to_string(), FieldValue::String("00".to_string())); // Empty context
            test_case.fields.insert("signature".to_string(), FieldValue::String(sig_hex));
            test_case.fields.insert("testPassed".to_string(), FieldValue::Bool(true));

            tests.push(test_case);
        }

        let tg_id = self.next_tg_id();
        let mut parameters = HashMap::new();
        parameters.insert("sigType".to_string(), FieldValue::String("standard".to_string()));
        parameters.insert("deterministic".to_string(), FieldValue::Bool(deterministic));

        AcvpTestGroup {
            tg_id,
            test_type: "sigGen".to_string(),
            parameter_set: param_set.to_string(),
            tests,
            parameters,
        }
    }

    /// Generate signature verification test vectors
    fn generate_sigver_tests(&mut self, param_set: &str, num_tests: usize, valid: bool) -> AcvpTestGroup {
        let mut tests = Vec::new();
        let message_patterns = self.get_test_message_patterns();

        for i in 0..num_tests {
            let tc_id = self.next_tc_id();
            let pattern_idx = i % message_patterns.len();
            let message = self.generate_message(&message_patterns[pattern_idx]);

            let (pk_hex, mut sig_bytes) = match param_set {
                "ML-DSA-44" => {
                    let (pk, sk) = MlDsa44::generate_keypair();
                    let signature = MlDsa44::sign(&sk, &message);
                    (hex::encode(pk), signature.to_vec())
                },
                "ML-DSA-65" => {
                    let (pk, sk) = MlDsa65::generate_keypair();
                    let signature = MlDsa65::sign(&sk, &message);
                    (hex::encode(pk), signature.to_vec())
                },
                "ML-DSA-87" => {
                    let (pk, sk) = MlDsa87::generate_keypair();
                    let signature = MlDsa87::sign(&sk, &message);
                    (hex::encode(pk), signature.to_vec())
                },
                _ => panic!("Unknown parameter set: {}", param_set),
            };

            // For invalid tests, corrupt the signature
            if !valid {
                let len = sig_bytes.len();
                match i % 3 {
                    0 => sig_bytes[0] ^= 0xFF, // Corrupt first byte
                    1 => sig_bytes[len / 2] ^= 0xFF, // Corrupt middle byte
                    2 => sig_bytes[len - 1] ^= 0xFF, // Corrupt last byte
                    _ => unreachable!(),
                }
            }

            let mut test_case = AcvpTestCase::new(tc_id);
            test_case.fields.insert("pk".to_string(), FieldValue::String(pk_hex));
            test_case.fields.insert("message".to_string(), FieldValue::String(hex::encode(&message)));
            test_case.fields.insert("context".to_string(), FieldValue::String("00".to_string()));
            test_case.fields.insert("signature".to_string(), FieldValue::String(hex::encode(sig_bytes)));
            test_case.fields.insert("testPassed".to_string(), FieldValue::Bool(valid));

            if !valid {
                test_case.fields.insert("reason".to_string(), FieldValue::String("Modified signature".to_string()));
            }

            tests.push(test_case);
        }

        let tg_id = self.next_tg_id();
        let mut parameters = HashMap::new();
        parameters.insert("sigType".to_string(), FieldValue::String("standard".to_string()));
        parameters.insert("deterministic".to_string(), FieldValue::Bool(true));

        AcvpTestGroup {
            tg_id,
            test_type: "sigVer".to_string(),
            parameter_set: param_set.to_string(),
            tests,
            parameters,
        }
    }

    /// Generate edge case test vectors
    fn generate_edge_case_tests(&mut self, param_set: &str) -> AcvpTestGroup {
        let mut tests = Vec::new();

        let edge_cases = vec![
            ("Empty message", vec![]),
            ("Single byte", vec![0x42]),
            ("All zeros", vec![0x00; 100]),
            ("All ones", vec![0xFF; 100]),
            ("ASCII text", b"The quick brown fox jumps over the lazy dog".to_vec()),
            ("Binary pattern", (0..256).map(|i| i as u8).collect()),
            ("Large message", vec![0xAB; 2048]),
        ];

        for (description, message) in edge_cases.iter() {
            let tc_id = self.next_tc_id();

            let (pk_hex, sig_hex) = match param_set {
                "ML-DSA-44" => {
                    let (pk, sk) = MlDsa44::generate_keypair();
                    let signature = MlDsa44::sign(&sk, message);
                    (hex::encode(pk), hex::encode(signature))
                },
                "ML-DSA-65" => {
                    let (pk, sk) = MlDsa65::generate_keypair();
                    let signature = MlDsa65::sign(&sk, message);
                    (hex::encode(pk), hex::encode(signature))
                },
                "ML-DSA-87" => {
                    let (pk, sk) = MlDsa87::generate_keypair();
                    let signature = MlDsa87::sign(&sk, message);
                    (hex::encode(pk), hex::encode(signature))
                },
                _ => panic!("Unknown parameter set: {}", param_set),
            };

            let mut test_case = AcvpTestCase::new(tc_id);
            test_case.fields.insert("pk".to_string(), FieldValue::String(pk_hex));
            test_case.fields.insert("message".to_string(), FieldValue::String(hex::encode(message)));
            test_case.fields.insert("context".to_string(), FieldValue::String("00".to_string()));
            test_case.fields.insert("signature".to_string(), FieldValue::String(sig_hex));
            test_case.fields.insert("testPassed".to_string(), FieldValue::Bool(true));
            test_case.fields.insert("reason".to_string(), FieldValue::String(format!("Edge case: {}", description)));

            tests.push(test_case);
        }

        let tg_id = self.next_tg_id();
        let mut parameters = HashMap::new();
        parameters.insert("sigType".to_string(), FieldValue::String("edge-cases".to_string()));
        parameters.insert("deterministic".to_string(), FieldValue::Bool(true));

        AcvpTestGroup {
            tg_id,
            test_type: "sigVer".to_string(),
            parameter_set: param_set.to_string(),
            tests,
            parameters,
        }
    }

    /// Get predefined message patterns for testing
    fn get_test_message_patterns(&self) -> Vec<MessagePattern> {
        vec![
            MessagePattern::Empty,
            MessagePattern::Short(3),
            MessagePattern::Short(16),
            MessagePattern::Short(32),
            MessagePattern::Medium(100),
            MessagePattern::Medium(256),
            MessagePattern::Medium(512),
            MessagePattern::Long(1024),
            MessagePattern::Long(2048),
            MessagePattern::Pattern(b"abc".to_vec()),
            MessagePattern::Pattern(b"Hello, ML-DSA!".to_vec()),
            MessagePattern::Random(64),
            MessagePattern::Random(128),
        ]
    }

    /// Generate a message based on the pattern
    fn generate_message(&mut self, pattern: &MessagePattern) -> Vec<u8> {
        match pattern {
            MessagePattern::Empty => vec![],
            MessagePattern::Short(len) | MessagePattern::Medium(len) | MessagePattern::Long(len) => {
                let mut bytes = vec![0u8; *len];
                self.rng.fill_bytes(&mut bytes);
                bytes
            },
            MessagePattern::Pattern(bytes) => bytes.clone(),
            MessagePattern::Random(len) => {
                let mut bytes = vec![0u8; *len];
                self.rng.fill_bytes(&mut bytes);
                bytes
            },
        }
    }

    /// Export test suite to JSON
    pub fn export_to_json(&self, test_suite: &AcvpTestSuite) -> String {
        serde_json::to_string_pretty(test_suite)
            .expect("Failed to serialize test suite to JSON")
    }

    /// Generate and save test vectors to file
    pub fn generate_and_save<P: AsRef<std::path::Path>>(
        &mut self,
        path: P,
        options: &TestVectorOptions
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_suite = self.generate_comprehensive_test_suite(options);
        let json = self.export_to_json(&test_suite);
        std::fs::write(path, json)?;
        Ok(())
    }
}

impl Default for MlDsaTestVectorGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_creation() {
        let _generator = MlDsaTestVectorGenerator::new();
        // Test passes if creation succeeds
    }

    #[test]
    fn test_deterministic_generation() {
        let mut gen1 = MlDsaTestVectorGenerator::new();
        let mut gen2 = MlDsaTestVectorGenerator::new();

        let msg1 = gen1.generate_message(&MessagePattern::Random(32));
        let msg2 = gen2.generate_message(&MessagePattern::Random(32));

        // Should be identical due to same seed
        assert_eq!(msg1, msg2);
    }

    #[test]
    fn test_message_generation() {
        let mut generator = MlDsaTestVectorGenerator::new();

        assert_eq!(generator.generate_message(&MessagePattern::Empty), Vec::<u8>::new());

        let short = generator.generate_message(&MessagePattern::Short(5));
        assert_eq!(short.len(), 5);

        let pattern = generator.generate_message(&MessagePattern::Pattern(vec![1, 2, 3]));
        assert_eq!(pattern, vec![1, 2, 3]);
    }

    #[test]
    fn test_comprehensive_test_generation() {
        let mut generator = MlDsaTestVectorGenerator::new();
        let options = TestVectorOptions {
            num_keygen_tests: 2,
            num_siggen_tests: 2,
            num_sigver_valid_tests: 2,
            num_sigver_invalid_tests: 2,
            include_edge_cases: true,
            deterministic_signing: true,
        };

        let test_suite = generator.generate_comprehensive_test_suite(&options);

        assert_eq!(test_suite.algorithm, "ML-DSA");
        assert!(!test_suite.test_groups.is_empty());

        // Should have test groups for all three parameter sets
        let param_sets: std::collections::HashSet<String> = test_suite.test_groups
            .iter()
            .map(|g| g.parameter_set.clone())
            .collect();

        assert!(param_sets.contains("ML-DSA-44"));
        assert!(param_sets.contains("ML-DSA-65"));
        assert!(param_sets.contains("ML-DSA-87"));
    }

    #[test]
    fn test_keygen_test_generation() {
        let mut generator = MlDsaTestVectorGenerator::new();
        let group = generator.generate_keygen_tests("ML-DSA-44", 3);

        assert_eq!(group.test_type, "keyGen");
        assert_eq!(group.parameter_set, "ML-DSA-44");
        assert_eq!(group.tests.len(), 3);

        for test in &group.tests {
            assert!(test.get_string("pk").is_some());
            assert!(test.get_string("sk").is_some());
            assert_eq!(test.get_bool("testPassed"), Some(true));
        }
    }

    #[test]
    fn test_siggen_test_generation() {
        let mut generator = MlDsaTestVectorGenerator::new();
        let group = generator.generate_siggen_tests("ML-DSA-44", 3, true);

        assert_eq!(group.test_type, "sigGen");
        assert_eq!(group.parameter_set, "ML-DSA-44");
        assert_eq!(group.tests.len(), 3);

        for test in &group.tests {
            assert!(test.get_string("pk").is_some());
            assert!(test.get_string("sk").is_some());
            assert!(test.get_string("message").is_some());
            assert!(test.get_string("signature").is_some());
            assert_eq!(test.get_bool("testPassed"), Some(true));
        }
    }

    #[test]
    fn test_sigver_test_generation() {
        let mut generator = MlDsaTestVectorGenerator::new();

        // Valid signatures
        let valid_group = generator.generate_sigver_tests("ML-DSA-44", 3, true);
        assert_eq!(valid_group.test_type, "sigVer");
        assert_eq!(valid_group.tests.len(), 3);

        for test in &valid_group.tests {
            assert_eq!(test.get_bool("testPassed"), Some(true));
            assert!(test.get_string("reason").is_none());
        }

        // Invalid signatures
        let invalid_group = generator.generate_sigver_tests("ML-DSA-44", 3, false);
        assert_eq!(invalid_group.tests.len(), 3);

        for test in &invalid_group.tests {
            assert_eq!(test.get_bool("testPassed"), Some(false));
            assert!(test.get_string("reason").is_some());
        }
    }

    #[test]
    fn test_json_export() {
        let mut generator = MlDsaTestVectorGenerator::new();
        let options = TestVectorOptions {
            num_keygen_tests: 1,
            num_siggen_tests: 1,
            num_sigver_valid_tests: 1,
            num_sigver_invalid_tests: 1,
            include_edge_cases: false,
            deterministic_signing: true,
        };

        let test_suite = generator.generate_comprehensive_test_suite(&options);
        let json_str = generator.export_to_json(&test_suite);

        assert!(json_str.contains("ML-DSA"));
        assert!(json_str.contains("ML-DSA-44"));

        // Verify it's valid JSON by parsing it back
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["algorithm"], "ML-DSA");
    }
}
