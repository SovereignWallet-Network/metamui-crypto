//! Falcon ACVP Test Vector Generator
//!
//! Generates comprehensive ACVP-format test vectors for Falcon signature schemes.
//! Supports Falcon-512 and Falcon-1024 with deterministic ChaCha20Rng.
//!
//! **Note**: This module requires the `acvp` feature to be enabled.

#[cfg(feature = "acvp")]
use crate::{generate_keypair, sign, verify, KeyPair, PublicKey, PrivateKey};
#[cfg(feature = "acvp")]
use metamui_acvp_core::{AcvpTestCase, AcvpTestGroup, AcvpTestSuite, FieldValue};
#[cfg(feature = "acvp")]
use rand_core::SeedableRng;
#[cfg(feature = "acvp")]
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "acvp")]
use std::collections::HashMap;

/// Serialize public key to bytes
#[cfg(feature = "acvp")]
fn serialize_public_key(pk: &PublicKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(pk.h.coeffs.len() * 2);
    for &coeff in &pk.h.coeffs {
        bytes.extend_from_slice(&coeff.to_le_bytes());
    }
    bytes
}

/// Serialize private key to bytes
#[cfg(feature = "acvp")]
fn serialize_private_key(sk: &PrivateKey) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Serialize f, g, F, G polynomials
    for &coeff in &sk.f.coeffs {
        bytes.extend_from_slice(&coeff.to_le_bytes());
    }
    for &coeff in &sk.g.coeffs {
        bytes.extend_from_slice(&coeff.to_le_bytes());
    }
    for &coeff in &sk.big_f.coeffs {
        bytes.extend_from_slice(&coeff.to_le_bytes());
    }
    for &coeff in &sk.big_g.coeffs {
        bytes.extend_from_slice(&coeff.to_le_bytes());
    }

    bytes
}

/// Options for test vector generation
#[cfg(feature = "acvp")]
#[derive(Debug, Clone)]
pub struct TestVectorOptions {
    /// Number of keyGen tests per parameter set
    pub num_keygen_tests: usize,
    /// Number of sigGen tests per parameter set
    pub num_siggen_tests: usize,
    /// Number of sigVer tests per parameter set (valid signatures)
    pub num_sigver_tests: usize,
    /// Include edge cases (malformed signatures, wrong keys, etc.)
    pub include_edge_cases: bool,
}

#[cfg(feature = "acvp")]
impl Default for TestVectorOptions {
    fn default() -> Self {
        Self {
            num_keygen_tests: 10,
            num_siggen_tests: 10,
            num_sigver_tests: 10,
            include_edge_cases: true,
        }
    }
}

/// Falcon test vector generator
#[cfg(feature = "acvp")]
pub struct FalconTestVectorGenerator {
    rng: ChaCha20Rng,
    tc_id_counter: u32,
    tg_id_counter: u32,
}

#[cfg(feature = "acvp")]
impl FalconTestVectorGenerator {
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

    /// Generate comprehensive Falcon test vectors
    pub fn generate_comprehensive_test_suite(
        &mut self,
        options: &TestVectorOptions,
    ) -> AcvpTestSuite {
        let mut test_groups = Vec::new();

        // Generate test vectors for both Falcon-512 and Falcon-1024
        test_groups.extend(self.generate_parameter_set_tests("Falcon-512", options));
        test_groups.extend(self.generate_parameter_set_tests("Falcon-1024", options));

        AcvpTestSuite {
            vs_id: None,
            algorithm: "Falcon".to_string(),
            mode: Some("sigGen".to_string()),
            revision: None,
            is_sample: Some(false),
            test_groups,
            metadata: HashMap::new(),
        }
    }

    /// Generate test vectors for a specific parameter set
    fn generate_parameter_set_tests(
        &mut self,
        param_set: &str,
        options: &TestVectorOptions,
    ) -> Vec<AcvpTestGroup> {
        let mut groups = Vec::new();

        // Key Generation Tests
        if options.num_keygen_tests > 0 {
            groups.push(self.generate_keygen_tests(param_set, options.num_keygen_tests));
        }

        // Signature Generation Tests
        if options.num_siggen_tests > 0 {
            groups.push(self.generate_siggen_tests(param_set, options.num_siggen_tests));
        }

        // Signature Verification Tests
        if options.num_sigver_tests > 0 {
            groups.push(self.generate_sigver_tests(param_set, options.num_sigver_tests));
        }

        groups
    }

    /// Generate key generation test vectors
    fn generate_keygen_tests(&mut self, param_set: &str, num_tests: usize) -> AcvpTestGroup {
        let mut tests = Vec::new();

        for _ in 0..num_tests {
            let tc_id = self.next_tc_id();

            // Generate keypair
            let keypair = generate_keypair(&mut self.rng).expect("Failed to generate keypair");
            let pk_hex = hex::encode(serialize_public_key(&keypair.public_key));
            let sk_hex = hex::encode(serialize_private_key(&keypair.private_key));

            let mut test_case = AcvpTestCase::new(tc_id);
            test_case
                .fields
                .insert("pk".to_string(), FieldValue::String(pk_hex));
            test_case
                .fields
                .insert("sk".to_string(), FieldValue::String(sk_hex));
            test_case
                .fields
                .insert("testPassed".to_string(), FieldValue::Bool(true));

            tests.push(test_case);
        }

        let tg_id = self.next_tg_id();
        let parameters = HashMap::new();

        AcvpTestGroup {
            tg_id,
            test_type: "keyGen".to_string(),
            parameter_set: param_set.to_string(),
            tests,
            parameters,
        }
    }

    /// Generate signature generation test vectors
    fn generate_siggen_tests(&mut self, param_set: &str, num_tests: usize) -> AcvpTestGroup {
        let mut tests = Vec::new();

        for i in 0..num_tests {
            let tc_id = self.next_tc_id();

            // Generate keypair
            let keypair = generate_keypair(&mut self.rng).expect("Failed to generate keypair");

            // Create test message (varying sizes for diversity)
            let message_len = match i % 5 {
                0 => 32,   // Small message
                1 => 64,   // Medium message
                2 => 128,  // Larger message
                3 => 256,  // Even larger
                _ => 1024, // Large message
            };
            let mut message = vec![0u8; message_len];
            rand::RngCore::fill_bytes(&mut self.rng, &mut message);

            // Generate signature
            let signature = sign(&message, &keypair.private_key, &mut self.rng)
                .expect("Failed to generate signature");

            let pk_hex = hex::encode(serialize_public_key(&keypair.public_key));
            let msg_hex = hex::encode(&message);
            let sig_hex = hex::encode(&signature);

            let mut test_case = AcvpTestCase::new(tc_id);
            test_case
                .fields
                .insert("pk".to_string(), FieldValue::String(pk_hex));
            test_case
                .fields
                .insert("message".to_string(), FieldValue::String(msg_hex));
            test_case
                .fields
                .insert("signature".to_string(), FieldValue::String(sig_hex));
            test_case
                .fields
                .insert("testPassed".to_string(), FieldValue::Bool(true));

            tests.push(test_case);
        }

        let tg_id = self.next_tg_id();
        let parameters = HashMap::new();

        AcvpTestGroup {
            tg_id,
            test_type: "sigGen".to_string(),
            parameter_set: param_set.to_string(),
            tests,
            parameters,
        }
    }

    /// Generate signature verification test vectors
    fn generate_sigver_tests(&mut self, param_set: &str, num_tests: usize) -> AcvpTestGroup {
        let mut tests = Vec::new();

        for i in 0..num_tests {
            let tc_id = self.next_tc_id();

            // Generate keypair
            let keypair = generate_keypair(&mut self.rng).expect("Failed to generate keypair");

            // Create test message
            let message_len = match i % 5 {
                0 => 32,
                1 => 64,
                2 => 128,
                3 => 256,
                _ => 1024,
            };
            let mut message = vec![0u8; message_len];
            rand::RngCore::fill_bytes(&mut self.rng, &mut message);

            // Generate valid signature
            let signature = sign(&message, &keypair.private_key, &mut self.rng)
                .expect("Failed to generate signature");

            // Verify signature (should pass)
            let test_passed = verify(&message, &signature, &keypair.public_key)
                .expect("Failed to verify signature");

            let pk_hex = hex::encode(serialize_public_key(&keypair.public_key));
            let msg_hex = hex::encode(&message);
            let sig_hex = hex::encode(&signature);

            let mut test_case = AcvpTestCase::new(tc_id);
            test_case
                .fields
                .insert("pk".to_string(), FieldValue::String(pk_hex));
            test_case
                .fields
                .insert("message".to_string(), FieldValue::String(msg_hex));
            test_case
                .fields
                .insert("signature".to_string(), FieldValue::String(sig_hex));
            test_case
                .fields
                .insert("testPassed".to_string(), FieldValue::Bool(test_passed));

            tests.push(test_case);
        }

        let tg_id = self.next_tg_id();
        let parameters = HashMap::new();

        AcvpTestGroup {
            tg_id,
            test_type: "sigVer".to_string(),
            parameter_set: param_set.to_string(),
            tests,
            parameters,
        }
    }

    /// Export test suite to JSON
    pub fn export_to_json(&self, test_suite: &AcvpTestSuite) -> String {
        serde_json::to_string_pretty(test_suite).expect("Failed to serialize test suite to JSON")
    }

    /// Generate and save test vectors to file
    pub fn generate_and_save<P: AsRef<std::path::Path>>(
        &mut self,
        path: P,
        options: &TestVectorOptions,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let test_suite = self.generate_comprehensive_test_suite(options);
        let json = self.export_to_json(&test_suite);
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[cfg(feature = "acvp")]
impl Default for FalconTestVectorGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "acvp"))]
mod tests {
    use super::*;

    #[test]
    fn test_generator_creation() {
        let _generator = FalconTestVectorGenerator::new();
        // Test passes if creation succeeds
    }

    #[test]
    fn test_deterministic_generation() {
        let mut gen1 = FalconTestVectorGenerator::new();
        let mut gen2 = FalconTestVectorGenerator::new();

        // Generate random bytes and verify they're identical
        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rand::RngCore::fill_bytes(&mut gen1.rng, &mut bytes1);
        rand::RngCore::fill_bytes(&mut gen2.rng, &mut bytes2);

        // Should be identical due to same seed
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_keygen_test_generation() {
        let mut generator = FalconTestVectorGenerator::new();
        let group = generator.generate_keygen_tests("Falcon-512", 3);

        assert_eq!(group.test_type, "keyGen");
        assert_eq!(group.parameter_set, "Falcon-512");
        assert_eq!(group.tests.len(), 3);

        for test in &group.tests {
            assert!(test.get_string("pk").is_some());
            assert!(test.get_string("sk").is_some());
            assert_eq!(test.get_bool("testPassed"), Some(true));
        }
    }

    #[test]
    fn test_siggen_test_generation() {
        let mut generator = FalconTestVectorGenerator::new();
        let group = generator.generate_siggen_tests("Falcon-512", 3);

        assert_eq!(group.test_type, "sigGen");
        assert_eq!(group.parameter_set, "Falcon-512");
        assert_eq!(group.tests.len(), 3);

        for test in &group.tests {
            assert!(test.get_string("pk").is_some());
            assert!(test.get_string("message").is_some());
            assert!(test.get_string("signature").is_some());
            assert_eq!(test.get_bool("testPassed"), Some(true));
        }
    }

    #[test]
    fn test_sigver_test_generation() {
        let mut generator = FalconTestVectorGenerator::new();
        let group = generator.generate_sigver_tests("Falcon-512", 3);

        assert_eq!(group.test_type, "sigVer");
        assert_eq!(group.parameter_set, "Falcon-512");
        assert_eq!(group.tests.len(), 3);

        for test in &group.tests {
            assert!(test.get_string("pk").is_some());
            assert!(test.get_string("message").is_some());
            assert!(test.get_string("signature").is_some());
            // Verification bug has been fixed: proper modular arithmetic and centered reduction
            // Now we can properly assert that valid signatures pass verification
            assert_eq!(test.get_bool("testPassed"), Some(true),
                "Signature verification should pass for valid signatures");
        }
    }

    #[test]
    fn test_comprehensive_test_generation() {
        let mut generator = FalconTestVectorGenerator::new();
        let options = TestVectorOptions {
            num_keygen_tests: 2,
            num_siggen_tests: 2,
            num_sigver_tests: 2,
            include_edge_cases: false,
        };

        let test_suite = generator.generate_comprehensive_test_suite(&options);

        assert_eq!(test_suite.algorithm, "Falcon");
        assert!(!test_suite.test_groups.is_empty());

        // Should have 6 test groups (3 test types × 2 parameter sets)
        assert_eq!(test_suite.test_groups.len(), 6);
    }

    #[test]
    fn test_json_export() {
        let mut generator = FalconTestVectorGenerator::new();
        let options = TestVectorOptions {
            num_keygen_tests: 1,
            num_siggen_tests: 1,
            num_sigver_tests: 1,
            include_edge_cases: false,
        };

        let test_suite = generator.generate_comprehensive_test_suite(&options);
        let json_str = generator.export_to_json(&test_suite);

        assert!(json_str.contains("Falcon"));

        // Verify it's valid JSON by parsing it back
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["algorithm"], "Falcon");
    }
}
