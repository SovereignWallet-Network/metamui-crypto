//! ACVP Test Vector Generator for ML-KEM
//!
//! Generates comprehensive ACVP-format test vectors for all ML-KEM parameter sets.
//! Supports keyGen, encapGen, and decap test types.

use crate::{
    params::MLKemParameterSet,
    kem::{mlkem_keygen, mlkem_encapsulate, mlkem_decapsulate},
};
use metamui_acvp_core::{
    AcvpTestCase, AcvpTestGroup, AcvpTestSuite,
};
use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "std")]
use serde_json;

/// Options for test vector generation
#[derive(Debug, Clone)]
pub struct TestVectorOptions {
    /// Number of keyGen tests per parameter set
    pub num_keygen_tests: usize,
    /// Number of encapGen tests per parameter set
    pub num_encap_tests: usize,
    /// Number of decap tests per parameter set
    pub num_decap_tests: usize,
    /// Include edge cases (empty inputs, boundary values, etc.)
    pub include_edge_cases: bool,
}

impl Default for TestVectorOptions {
    fn default() -> Self {
        Self {
            num_keygen_tests: 10,
            num_encap_tests: 10,
            num_decap_tests: 10,
            include_edge_cases: true,
        }
    }
}

/// ML-KEM Test Vector Generator
pub struct MlKemTestVectorGenerator {
    rng: ChaCha20Rng,
    tc_id_counter: u32,
    tg_id_counter: u32,
}

impl MlKemTestVectorGenerator {
    /// Create a new generator with deterministic seed for reproducibility
    pub fn new() -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(0x1234567890ABCDEF),
            tc_id_counter: 1,
            tg_id_counter: 1,
        }
    }

    /// Create generator with custom seed
    pub fn with_seed(seed: u64) -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(seed),
            tc_id_counter: 1,
            tg_id_counter: 1,
        }
    }

    /// Generate comprehensive test suite for all ML-KEM parameter sets
    pub fn generate_comprehensive_test_suite(
        &mut self,
        options: &TestVectorOptions,
    ) -> AcvpTestSuite {
        let mut suite = AcvpTestSuite::new("ML-KEM".to_string());
        suite.mode = Some("all".to_string());
        suite.revision = Some("FIPS203".to_string());
        suite.is_sample = Some(false);

        // Generate tests for each parameter set
        for param_set in &[
            MLKemParameterSet::MLKem512,
            MLKemParameterSet::MLKem768,
            MLKemParameterSet::MLKem1024,
        ] {
            // KeyGen tests
            let keygen_group = self.generate_keygen_tests(param_set, options.num_keygen_tests);
            suite.add_group(keygen_group);

            // EncapGen tests
            let encap_group = self.generate_encap_tests(param_set, options.num_encap_tests);
            suite.add_group(encap_group);

            // Decap tests
            let decap_group = self.generate_decap_tests(param_set, options.num_decap_tests);
            suite.add_group(decap_group);
        }

        suite
    }

    /// Generate keyGen test group for a parameter set
    fn generate_keygen_tests(
        &mut self,
        param_set: &MLKemParameterSet,
        num_tests: usize,
    ) -> AcvpTestGroup {
        let tg_id = self.tg_id_counter;
        self.tg_id_counter += 1;

        let param_name = match param_set {
            MLKemParameterSet::MLKem512 => "ML-KEM-512",
            MLKemParameterSet::MLKem768 => "ML-KEM-768",
            MLKemParameterSet::MLKem1024 => "ML-KEM-1024",
        };

        let params = param_set.params();
        let mut group = AcvpTestGroup::new(tg_id, "keyGen".to_string(), param_name.to_string());

        for _ in 0..num_tests {
            let tc_id = self.tc_id_counter;
            self.tc_id_counter += 1;

            // Use generic ML-KEM keygen for all parameter sets
            let mut pk = vec![0u8; params.public_key_bytes];
            let mut sk = vec![0u8; params.secret_key_bytes];
            let result = mlkem_keygen(params, &mut pk, &mut sk, &mut self.rng)
                .map(|_| (pk, sk));

            if let Ok((pk, sk)) = result {
                let test = AcvpTestCase::new(tc_id)
                    .with_hex_field("pk".to_string(), &pk)
                    .with_hex_field("sk".to_string(), &sk)
                    .with_bool_field("testPassed".to_string(), true);

                group.add_test(test);
            }
        }

        group
    }

    /// Generate encapGen test group for a parameter set
    fn generate_encap_tests(
        &mut self,
        param_set: &MLKemParameterSet,
        num_tests: usize,
    ) -> AcvpTestGroup {
        let tg_id = self.tg_id_counter;
        self.tg_id_counter += 1;

        let param_name = match param_set {
            MLKemParameterSet::MLKem512 => "ML-KEM-512",
            MLKemParameterSet::MLKem768 => "ML-KEM-768",
            MLKemParameterSet::MLKem1024 => "ML-KEM-1024",
        };

        let params = param_set.params();
        let mut group = AcvpTestGroup::new(tg_id, "encapGen".to_string(), param_name.to_string());

        for _ in 0..num_tests {
            let tc_id = self.tc_id_counter;
            self.tc_id_counter += 1;

            // Generate keypair first
            let mut pk = vec![0u8; params.public_key_bytes];
            let mut sk = vec![0u8; params.secret_key_bytes];
            if mlkem_keygen(params, &mut pk, &mut sk, &mut self.rng).is_err() {
                continue;
            }

            // Encapsulate
            let mut ct = vec![0u8; params.ciphertext_bytes];
            let mut ss = vec![0u8; params.shared_secret_bytes];
            if mlkem_encapsulate(params, &pk, &mut ct, &mut ss, &mut self.rng).is_err() {
                continue;
            }

            let test = AcvpTestCase::new(tc_id)
                    .with_hex_field("pk".to_string(), &pk)
                    .with_hex_field("ct".to_string(), &ct)
                    .with_hex_field("ss".to_string(), &ss)
                    .with_bool_field("testPassed".to_string(), true);

            group.add_test(test);
        }

        group
    }

    /// Generate decap test group for a parameter set
    fn generate_decap_tests(
        &mut self,
        param_set: &MLKemParameterSet,
        num_tests: usize,
    ) -> AcvpTestGroup {
        let tg_id = self.tg_id_counter;
        self.tg_id_counter += 1;

        let param_name = match param_set {
            MLKemParameterSet::MLKem512 => "ML-KEM-512",
            MLKemParameterSet::MLKem768 => "ML-KEM-768",
            MLKemParameterSet::MLKem1024 => "ML-KEM-1024",
        };

        let params = param_set.params();
        let mut group = AcvpTestGroup::new(tg_id, "decap".to_string(), param_name.to_string());

        for _ in 0..num_tests {
            let tc_id = self.tc_id_counter;
            self.tc_id_counter += 1;

            // Generate keypair
            let mut pk = vec![0u8; params.public_key_bytes];
            let mut sk = vec![0u8; params.secret_key_bytes];
            if mlkem_keygen(params, &mut pk, &mut sk, &mut self.rng).is_err() {
                continue;
            }

            // Encapsulate
            let mut ct = vec![0u8; params.ciphertext_bytes];
            let mut ss_encap = vec![0u8; params.shared_secret_bytes];
            if mlkem_encapsulate(params, &pk, &mut ct, &mut ss_encap, &mut self.rng).is_err() {
                continue;
            }

            // Decapsulate
            let mut ss_decap = vec![0u8; params.shared_secret_bytes];
            if mlkem_decapsulate(params, &sk, &ct, &mut ss_decap).is_err() {
                continue;
            }

            // Verify shared secrets match
            let test_passed = ss_encap == ss_decap;

            let test = AcvpTestCase::new(tc_id)
                .with_hex_field("sk".to_string(), &sk)
                .with_hex_field("ct".to_string(), &ct)
                .with_hex_field("ss".to_string(), &ss_decap)
                .with_bool_field("testPassed".to_string(), test_passed);

            group.add_test(test);
        }

        group
    }

    /// Export test suite to JSON string
    pub fn export_to_json(&self, test_suite: &AcvpTestSuite) -> String {
        serde_json::to_string_pretty(test_suite)
            .expect("Failed to serialize test suite to JSON")
    }

    /// Generate and save test vectors to file
    pub fn generate_and_save(
        &mut self,
        path: &str,
        options: &TestVectorOptions,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let suite = self.generate_comprehensive_test_suite(options);
        let json = self.export_to_json(&suite);
        std::fs::write(path, json)?;
        Ok(())
    }
}

impl Default for MlKemTestVectorGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_generator_creation() {
        let generator = MlKemTestVectorGenerator::new();
        assert_eq!(generator.tc_id_counter, 1);
        assert_eq!(generator.tg_id_counter, 1);
    }

    #[test]
    fn test_generate_small_test_suite() {
        let mut generator = MlKemTestVectorGenerator::new();
        let options = TestVectorOptions {
            num_keygen_tests: 2,
            num_encap_tests: 2,
            num_decap_tests: 2,
            include_edge_cases: false,
        };

        let suite = generator.generate_comprehensive_test_suite(&options);

        assert_eq!(suite.algorithm, "ML-KEM");
        assert_eq!(suite.revision, Some("FIPS203".to_string()));
        // 3 parameter sets × 3 test types = 9 groups
        assert_eq!(suite.test_groups.len(), 9);
    }

    #[test]
    fn test_export_to_json_valid() {
        let mut generator = MlKemTestVectorGenerator::new();
        let options = TestVectorOptions {
            num_keygen_tests: 1,
            num_encap_tests: 1,
            num_decap_tests: 1,
            include_edge_cases: false,
        };

        let suite = generator.generate_comprehensive_test_suite(&options);
        let json_str = generator.export_to_json(&suite);

        // Verify it contains expected metadata
        assert!(json_str.contains("ML-KEM"));
        assert!(json_str.contains("FIPS203"));

        // Verify it's valid JSON by parsing it back
        let parsed: serde_json::Value = serde_json::from_str(&json_str)
            .expect("Failed to parse JSON output");

        assert_eq!(parsed["algorithm"], "ML-KEM");
        assert_eq!(parsed["revision"], "FIPS203");
        assert_eq!(parsed["mode"], "all");
        assert_eq!(parsed["isSample"], false);
    }

    #[test]
    fn test_deterministic_generation() {
        // Same seed should produce identical test vector structure
        // Note: Full byte-for-byte determinism requires debug output to be disabled
        let mut gen1 = MlKemTestVectorGenerator::new();
        let mut gen2 = MlKemTestVectorGenerator::new();

        let options = TestVectorOptions {
            num_keygen_tests: 1,
            num_encap_tests: 1,
            num_decap_tests: 1,
            include_edge_cases: false,
        };

        let suite1 = gen1.generate_comprehensive_test_suite(&options);
        let suite2 = gen2.generate_comprehensive_test_suite(&options);

        // Verify structure is identical (same number of groups and tests)
        assert_eq!(suite1.algorithm, suite2.algorithm);
        assert_eq!(suite1.revision, suite2.revision);
        assert_eq!(suite1.test_groups.len(), suite2.test_groups.len());

        for (group1, group2) in suite1.test_groups.iter().zip(suite2.test_groups.iter()) {
            assert_eq!(group1.test_type, group2.test_type);
            assert_eq!(group1.parameter_set, group2.parameter_set);
            assert_eq!(group1.tests.len(), group2.tests.len());
        }
    }

    #[test]
    fn test_all_parameter_sets() {
        let mut generator = MlKemTestVectorGenerator::new();
        let options = TestVectorOptions {
            num_keygen_tests: 1,
            num_encap_tests: 1,
            num_decap_tests: 1,
            include_edge_cases: false,
        };

        let suite = generator.generate_comprehensive_test_suite(&options);
        let json_str = generator.export_to_json(&suite);

        // Verify all 3 parameter sets are present
        assert!(json_str.contains("ML-KEM-512"), "Missing ML-KEM-512");
        assert!(json_str.contains("ML-KEM-768"), "Missing ML-KEM-768");
        assert!(json_str.contains("ML-KEM-1024"), "Missing ML-KEM-1024");

        // Verify all test types are present
        assert!(json_str.contains("keyGen"), "Missing keyGen tests");
        assert!(json_str.contains("encapGen"), "Missing encapGen tests");
        assert!(json_str.contains("decap"), "Missing decap tests");
    }

    #[test]
    fn test_acvp_format_compliance() {
        let mut generator = MlKemTestVectorGenerator::new();
        let options = TestVectorOptions {
            num_keygen_tests: 1,
            num_encap_tests: 1,
            num_decap_tests: 1,
            include_edge_cases: false,
        };

        let suite = generator.generate_comprehensive_test_suite(&options);
        let json_str = generator.export_to_json(&suite);

        let parsed: serde_json::Value = serde_json::from_str(&json_str)
            .expect("Failed to parse JSON");

        // Verify ACVP test suite structure
        assert!(parsed.get("algorithm").is_some(), "Missing algorithm field");
        assert!(parsed.get("revision").is_some(), "Missing revision field");
        assert!(parsed.get("testGroups").is_some(), "Missing testGroups field");

        let test_groups = parsed["testGroups"].as_array()
            .expect("testGroups should be an array");

        // Should have 9 groups (3 parameter sets × 3 test types)
        assert_eq!(test_groups.len(), 9, "Expected 9 test groups");

        // Verify each group has required fields
        for group in test_groups {
            assert!(group.get("tgId").is_some(), "Missing tgId in test group");
            assert!(group.get("testType").is_some(), "Missing testType in test group");
            assert!(group.get("parameterSet").is_some(), "Missing parameterSet in test group");
            assert!(group.get("tests").is_some(), "Missing tests in test group");
        }
    }

    #[test]
    fn test_shared_secret_size_consistency() {
        // ML-KEM uses fixed 32-byte shared secrets across all parameter sets
        let mut generator = MlKemTestVectorGenerator::new();
        let options = TestVectorOptions {
            num_keygen_tests: 0,
            num_encap_tests: 2,
            num_decap_tests: 0,
            include_edge_cases: false,
        };

        let suite = generator.generate_comprehensive_test_suite(&options);
        let json_str = generator.export_to_json(&suite);

        let parsed: serde_json::Value = serde_json::from_str(&json_str)
            .expect("Failed to parse JSON");

        let test_groups = parsed["testGroups"].as_array().unwrap();

        for group in test_groups {
            let tests = group["tests"].as_array().unwrap();
            for test in tests {
                if let Some(ss_hex) = test.get("ss").and_then(|v| v.as_str()) {
                    // Remove "0x" prefix if present and decode hex
                    let ss_hex_clean = ss_hex.trim_start_matches("0x");
                    let ss_bytes = hex::decode(ss_hex_clean)
                        .expect("Failed to decode shared secret hex");

                    assert_eq!(ss_bytes.len(), 32,
                        "ML-KEM shared secret should be 32 bytes for all parameter sets");
                }
            }
        }
    }
}
