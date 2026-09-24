//! ACVP Test Vector Generator for SLH-DSA
//!
//! Generates comprehensive ACVP-format test vectors for all SLH-DSA parameter sets.
//! Supports keyGen, sigGen, and sigVer test types.

use crate::{
    params::{SlhDsa128s, SlhDsa128f, SlhDsa192s, SlhDsa192f, SlhDsa256s, SlhDsa256f},
    types::SigningKey,
};
use crate::acvp_parser::SlhDsaParameterSet;
use metamui_acvp_core::{
    AcvpTestCase, AcvpTestGroup, AcvpTestSuite,
};
use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Options for test vector generation
#[derive(Debug, Clone)]
pub struct TestVectorOptions {
    /// Number of keyGen tests per parameter set
    pub num_keygen_tests: usize,
    /// Number of sigGen tests per parameter set
    pub num_siggen_tests: usize,
    /// Number of sigVer tests per parameter set (valid signatures)
    pub num_sigver_valid: usize,
    /// Number of sigVer tests per parameter set (invalid signatures)
    pub num_sigver_invalid: usize,
    /// Include edge cases (empty messages, max length, etc.)
    pub include_edge_cases: bool,
}

impl Default for TestVectorOptions {
    fn default() -> Self {
        Self {
            num_keygen_tests: 10,
            num_siggen_tests: 10,
            num_sigver_valid: 5,
            num_sigver_invalid: 5,
            include_edge_cases: true,
        }
    }
}

/// SLH-DSA Test Vector Generator
pub struct SlhDsaTestVectorGenerator {
    rng: ChaCha20Rng,
    tc_id_counter: u32,
    tg_id_counter: u32,
}

impl SlhDsaTestVectorGenerator {
    /// Create a new generator with deterministic seed for reproducibility
    pub fn new() -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(0xFEDCBA9876543210),
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

    /// Generate comprehensive test suite for all SLH-DSA parameter sets
    pub fn generate_comprehensive_test_suite(
        &mut self,
        options: &TestVectorOptions,
    ) -> AcvpTestSuite {
        let mut suite = AcvpTestSuite::new("SLH-DSA".to_string());
        suite.mode = Some("all".to_string());
        suite.revision = Some("FIPS205".to_string());
        suite.is_sample = Some(false);

        // Generate tests for each parameter set
        for param_set in &[
            SlhDsaParameterSet::SlhDsa128s,
            SlhDsaParameterSet::SlhDsa128f,
            SlhDsaParameterSet::SlhDsa192s,
            SlhDsaParameterSet::SlhDsa192f,
            SlhDsaParameterSet::SlhDsa256s,
            SlhDsaParameterSet::SlhDsa256f,
        ] {
            // KeyGen tests
            let keygen_group = self.generate_keygen_tests(param_set, options.num_keygen_tests);
            suite.add_group(keygen_group);

            // SigGen tests
            let siggen_group = self.generate_siggen_tests(param_set, options.num_siggen_tests);
            suite.add_group(siggen_group);

            // SigVer tests
            let sigver_group = self.generate_sigver_tests(
                param_set,
                options.num_sigver_valid,
                options.num_sigver_invalid,
            );
            suite.add_group(sigver_group);
        }

        suite
    }

    /// Generate keyGen test group for a parameter set
    fn generate_keygen_tests(
        &mut self,
        param_set: &SlhDsaParameterSet,
        num_tests: usize,
    ) -> AcvpTestGroup {
        let tg_id = self.tg_id_counter;
        self.tg_id_counter += 1;

        let param_name = self.param_set_name(param_set);
        let mut group = AcvpTestGroup::new(tg_id, "keyGen".to_string(), param_name.to_string());

        for _ in 0..num_tests {
            let tc_id = self.tc_id_counter;
            self.tc_id_counter += 1;

            // Generate keypair based on parameter set
            let (pk, sk) = self.generate_keypair(param_set);

            let test = AcvpTestCase::new(tc_id)
                .with_hex_field("pk".to_string(), &pk)
                .with_hex_field("sk".to_string(), &sk)
                .with_bool_field("testPassed".to_string(), true);

            group.add_test(test);
        }

        group
    }

    /// Generate sigGen test group for a parameter set
    fn generate_siggen_tests(
        &mut self,
        param_set: &SlhDsaParameterSet,
        num_tests: usize,
    ) -> AcvpTestGroup {
        let tg_id = self.tg_id_counter;
        self.tg_id_counter += 1;

        let param_name = self.param_set_name(param_set);
        let mut group = AcvpTestGroup::new(tg_id, "sigGen".to_string(), param_name.to_string());

        for i in 0..num_tests {
            let tc_id = self.tc_id_counter;
            self.tc_id_counter += 1;

            // Generate keypair
            let (_pk, sk) = self.generate_keypair(param_set);

            // Create test message (vary length for diversity)
            let msg_len = match i % 4 {
                0 => 0,      // Empty message
                1 => 32,     // Short message
                2 => 256,    // Medium message
                _ => 1024,   // Long message
            };
            let message = self.generate_random_bytes(msg_len);

            // Sign the message
            let signature = self.sign_message(param_set, &sk, &message);

            let test = AcvpTestCase::new(tc_id)
                .with_hex_field("sk".to_string(), &sk)
                .with_hex_field("message".to_string(), &message)
                .with_hex_field("signature".to_string(), &signature)
                .with_bool_field("testPassed".to_string(), true);

            group.add_test(test);
        }

        group
    }

    /// Generate sigVer test group for a parameter set
    fn generate_sigver_tests(
        &mut self,
        param_set: &SlhDsaParameterSet,
        num_valid: usize,
        num_invalid: usize,
    ) -> AcvpTestGroup {
        let tg_id = self.tg_id_counter;
        self.tg_id_counter += 1;

        let param_name = self.param_set_name(param_set);
        let mut group = AcvpTestGroup::new(tg_id, "sigVer".to_string(), param_name.to_string());

        // Generate valid signatures
        for i in 0..num_valid {
            let tc_id = self.tc_id_counter;
            self.tc_id_counter += 1;

            let (pk, sk) = self.generate_keypair(param_set);

            let msg_len = match i % 3 {
                0 => 32,
                1 => 256,
                _ => 1024,
            };
            let message = self.generate_random_bytes(msg_len);
            let signature = self.sign_message(param_set, &sk, &message);

            let test = AcvpTestCase::new(tc_id)
                .with_hex_field("pk".to_string(), &pk)
                .with_hex_field("message".to_string(), &message)
                .with_hex_field("signature".to_string(), &signature)
                .with_bool_field("testPassed".to_string(), true);

            group.add_test(test);
        }

        // Generate invalid signatures
        for i in 0..num_invalid {
            let tc_id = self.tc_id_counter;
            self.tc_id_counter += 1;

            let (pk, sk) = self.generate_keypair(param_set);

            let message = self.generate_random_bytes(256);
            let mut signature = self.sign_message(param_set, &sk, &message);

            // Corrupt the signature
            match i % 3 {
                0 => {
                    // Flip a byte in the middle
                    if signature.len() > 100 {
                        signature[100] ^= 0xFF;
                    }
                }
                1 => {
                    // Flip first byte
                    if !signature.is_empty() {
                        signature[0] ^= 0xFF;
                    }
                }
                _ => {
                    // Flip last byte
                    if !signature.is_empty() {
                        let len = signature.len();
                        signature[len - 1] ^= 0xFF;
                    }
                }
            }

            let test = AcvpTestCase::new(tc_id)
                .with_hex_field("pk".to_string(), &pk)
                .with_hex_field("message".to_string(), &message)
                .with_hex_field("signature".to_string(), &signature)
                .with_bool_field("testPassed".to_string(), false);

            group.add_test(test);
        }

        group
    }

    /// Generate a keypair for the given parameter set
    fn generate_keypair(&mut self, param_set: &SlhDsaParameterSet) -> (Vec<u8>, Vec<u8>) {
        match param_set {
            SlhDsaParameterSet::SlhDsa128s => {
                let signing_key = SigningKey::<SlhDsa128s>::generate(&mut self.rng);
                let verifying_key = signing_key.verifying_key();
                (verifying_key.to_bytes(), signing_key.to_bytes())
            }
            SlhDsaParameterSet::SlhDsa128f => {
                let signing_key = SigningKey::<SlhDsa128f>::generate(&mut self.rng);
                let verifying_key = signing_key.verifying_key();
                (verifying_key.to_bytes(), signing_key.to_bytes())
            }
            SlhDsaParameterSet::SlhDsa192s => {
                let signing_key = SigningKey::<SlhDsa192s>::generate(&mut self.rng);
                let verifying_key = signing_key.verifying_key();
                (verifying_key.to_bytes(), signing_key.to_bytes())
            }
            SlhDsaParameterSet::SlhDsa192f => {
                let signing_key = SigningKey::<SlhDsa192f>::generate(&mut self.rng);
                let verifying_key = signing_key.verifying_key();
                (verifying_key.to_bytes(), signing_key.to_bytes())
            }
            SlhDsaParameterSet::SlhDsa256s => {
                let signing_key = SigningKey::<SlhDsa256s>::generate(&mut self.rng);
                let verifying_key = signing_key.verifying_key();
                (verifying_key.to_bytes(), signing_key.to_bytes())
            }
            SlhDsaParameterSet::SlhDsa256f => {
                let signing_key = SigningKey::<SlhDsa256f>::generate(&mut self.rng);
                let verifying_key = signing_key.verifying_key();
                (verifying_key.to_bytes(), signing_key.to_bytes())
            }
        }
    }

    /// Sign a message with the given parameter set and secret key
    fn sign_message(&mut self, param_set: &SlhDsaParameterSet, sk: &[u8], message: &[u8]) -> Vec<u8> {
        match param_set {
            SlhDsaParameterSet::SlhDsa128s => {
                let signing_key = SigningKey::<SlhDsa128s>::from_bytes(sk).unwrap();
                signing_key.sign(message).to_bytes().to_vec()
            }
            SlhDsaParameterSet::SlhDsa128f => {
                let signing_key = SigningKey::<SlhDsa128f>::from_bytes(sk).unwrap();
                signing_key.sign(message).to_bytes().to_vec()
            }
            SlhDsaParameterSet::SlhDsa192s => {
                let signing_key = SigningKey::<SlhDsa192s>::from_bytes(sk).unwrap();
                signing_key.sign(message).to_bytes().to_vec()
            }
            SlhDsaParameterSet::SlhDsa192f => {
                let signing_key = SigningKey::<SlhDsa192f>::from_bytes(sk).unwrap();
                signing_key.sign(message).to_bytes().to_vec()
            }
            SlhDsaParameterSet::SlhDsa256s => {
                let signing_key = SigningKey::<SlhDsa256s>::from_bytes(sk).unwrap();
                signing_key.sign(message).to_bytes().to_vec()
            }
            SlhDsaParameterSet::SlhDsa256f => {
                let signing_key = SigningKey::<SlhDsa256f>::from_bytes(sk).unwrap();
                signing_key.sign(message).to_bytes().to_vec()
            }
        }
    }

    /// Generate random bytes
    fn generate_random_bytes(&mut self, len: usize) -> Vec<u8> {
        use rand_core::RngCore;
        let mut bytes = vec![0u8; len];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }

    /// Get parameter set name for ACVP
    fn param_set_name(&self, param_set: &SlhDsaParameterSet) -> &'static str {
        match param_set {
            SlhDsaParameterSet::SlhDsa128s => "SLH-DSA-SHAKE-128s",
            SlhDsaParameterSet::SlhDsa128f => "SLH-DSA-SHAKE-128f",
            SlhDsaParameterSet::SlhDsa192s => "SLH-DSA-SHAKE-192s",
            SlhDsaParameterSet::SlhDsa192f => "SLH-DSA-SHAKE-192f",
            SlhDsaParameterSet::SlhDsa256s => "SLH-DSA-SHAKE-256s",
            SlhDsaParameterSet::SlhDsa256f => "SLH-DSA-SHAKE-256f",
        }
    }

    /// Export test suite to JSON string
    pub fn export_to_json(&self, suite: &AcvpTestSuite) -> String {
        serde_json::to_string_pretty(suite)
            .expect("Failed to serialize test suite to JSON")
    }

    /// Generate and save test vectors to file
    pub fn generate_and_save(
        &mut self,
        path: &str,
        options: &TestVectorOptions,
    ) -> std::io::Result<()> {
        let suite = self.generate_comprehensive_test_suite(options);
        let json = self.export_to_json(&suite);
        std::fs::write(path, json)?;
        Ok(())
    }
}

impl Default for SlhDsaTestVectorGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_creation() {
        let generator = SlhDsaTestVectorGenerator::new();
        assert_eq!(generator.tc_id_counter, 1);
        assert_eq!(generator.tg_id_counter, 1);
    }

    #[test]
    fn test_generate_small_test_suite() {
        let mut generator = SlhDsaTestVectorGenerator::new();
        let options = TestVectorOptions {
            num_keygen_tests: 2,
            num_siggen_tests: 2,
            num_sigver_valid: 1,
            num_sigver_invalid: 1,
            include_edge_cases: false,
        };

        let suite = generator.generate_comprehensive_test_suite(&options);

        assert_eq!(suite.algorithm, "SLH-DSA");
        assert_eq!(suite.revision, Some("FIPS205".to_string()));
        // 6 parameter sets × 3 test types = 18 groups
        assert_eq!(suite.test_groups.len(), 18);
    }

    #[test]
    fn test_export_to_json() {
        let mut generator = SlhDsaTestVectorGenerator::new();
        let options = TestVectorOptions {
            num_keygen_tests: 1,
            num_siggen_tests: 1,
            num_sigver_valid: 1,
            num_sigver_invalid: 1,
            include_edge_cases: false,
        };

        let suite = generator.generate_comprehensive_test_suite(&options);
        let json_str = generator.export_to_json(&suite);

        assert!(json_str.contains("SLH-DSA"));
        assert!(json_str.contains("FIPS205"));
    }

    #[test]
    fn test_keypair_generation() {
        let mut generator = SlhDsaTestVectorGenerator::new();

        // Test 128s
        let (pk, sk) = generator.generate_keypair(&SlhDsaParameterSet::SlhDsa128s);
        assert_eq!(pk.len(), 32);
        assert_eq!(sk.len(), 64);

        // Test 192s
        let (pk, sk) = generator.generate_keypair(&SlhDsaParameterSet::SlhDsa192s);
        assert_eq!(pk.len(), 48);
        assert_eq!(sk.len(), 96);

        // Test 256s
        let (pk, sk) = generator.generate_keypair(&SlhDsaParameterSet::SlhDsa256s);
        assert_eq!(pk.len(), 64);
        assert_eq!(sk.len(), 128);
    }

    #[test]
    fn test_signature_generation() {
        let mut generator = SlhDsaTestVectorGenerator::new();

        let (_pk, sk) = generator.generate_keypair(&SlhDsaParameterSet::SlhDsa128s);
        let message = b"Test message";
        let signature = generator.sign_message(&SlhDsaParameterSet::SlhDsa128s, &sk, message);

        // SLH-DSA-128s signature size is 7856 bytes
        assert_eq!(signature.len(), 7856);
    }
}
