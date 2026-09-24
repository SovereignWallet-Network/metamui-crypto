//! ACVP (Automated Cryptographic Validation Protocol) Parser for SLH-DSA
//!
//! This module provides NIST FIPS 205 SLH-DSA test vector parsing in ACVP format.
//! It supports all SLH-DSA parameter sets (128s, 128f, 192s, 192f, 256s, 256f) and test types
//! (keyGen, sigGen, sigVer).

use crate::params::{Parameters, SlhDsa128s, SlhDsa128f, SlhDsa192s, SlhDsa192f, SlhDsa256s, SlhDsa256f};
use metamui_acvp_core::{
    traits::{AcvpCompatible, KeyGeneration, ParameterSet, SignatureAlgorithm},
    AcvpError, AcvpParser, AcvpTestCase, AcvpTestGroup, Result,
};

/// SLH-DSA parameter set enumeration
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlhDsaParameterSet {
    /// SLH-DSA-128s (small signatures, NIST Level 1)
    SlhDsa128s,
    /// SLH-DSA-128f (fast signing, NIST Level 1)
    SlhDsa128f,
    /// SLH-DSA-192s (small signatures, NIST Level 3)
    SlhDsa192s,
    /// SLH-DSA-192f (fast signing, NIST Level 3)
    SlhDsa192f,
    /// SLH-DSA-256s (small signatures, NIST Level 5)
    SlhDsa256s,
    /// SLH-DSA-256f (fast signing, NIST Level 5)
    SlhDsa256f,
}

impl SlhDsaParameterSet {
    /// Get public key size in bytes
    pub fn public_key_bytes(&self) -> usize {
        match self {
            SlhDsaParameterSet::SlhDsa128s => SlhDsa128s::PK_BYTES,
            SlhDsaParameterSet::SlhDsa128f => SlhDsa128f::PK_BYTES,
            SlhDsaParameterSet::SlhDsa192s => SlhDsa192s::PK_BYTES,
            SlhDsaParameterSet::SlhDsa192f => SlhDsa192f::PK_BYTES,
            SlhDsaParameterSet::SlhDsa256s => SlhDsa256s::PK_BYTES,
            SlhDsaParameterSet::SlhDsa256f => SlhDsa256f::PK_BYTES,
        }
    }

    /// Get secret key size in bytes
    pub fn secret_key_bytes(&self) -> usize {
        match self {
            SlhDsaParameterSet::SlhDsa128s => SlhDsa128s::SK_BYTES,
            SlhDsaParameterSet::SlhDsa128f => SlhDsa128f::SK_BYTES,
            SlhDsaParameterSet::SlhDsa192s => SlhDsa192s::SK_BYTES,
            SlhDsaParameterSet::SlhDsa192f => SlhDsa192f::SK_BYTES,
            SlhDsaParameterSet::SlhDsa256s => SlhDsa256s::SK_BYTES,
            SlhDsaParameterSet::SlhDsa256f => SlhDsa256f::SK_BYTES,
        }
    }

    /// Get signature size in bytes
    pub fn signature_bytes(&self) -> usize {
        match self {
            SlhDsaParameterSet::SlhDsa128s => SlhDsa128s::SIG_BYTES,
            SlhDsaParameterSet::SlhDsa128f => SlhDsa128f::SIG_BYTES,
            SlhDsaParameterSet::SlhDsa192s => SlhDsa192s::SIG_BYTES,
            SlhDsaParameterSet::SlhDsa192f => SlhDsa192f::SIG_BYTES,
            SlhDsaParameterSet::SlhDsa256s => SlhDsa256s::SIG_BYTES,
            SlhDsaParameterSet::SlhDsa256f => SlhDsa256f::SIG_BYTES,
        }
    }

    /// Get security parameter N in bytes
    pub fn n(&self) -> usize {
        match self {
            SlhDsaParameterSet::SlhDsa128s | SlhDsaParameterSet::SlhDsa128f => SlhDsa128s::N,
            SlhDsaParameterSet::SlhDsa192s | SlhDsaParameterSet::SlhDsa192f => SlhDsa192s::N,
            SlhDsaParameterSet::SlhDsa256s | SlhDsaParameterSet::SlhDsa256f => SlhDsa256s::N,
        }
    }
}

/// SLH-DSA ACVP parameter set wrapper
///
/// Wraps SLH-DSA's internal parameter set to implement ACVP's ParameterSet trait
#[derive(Clone, Debug)]
pub struct SlhDsaAcvpParameterSet {
    /// Parameter set identifier
    pub param_set: SlhDsaParameterSet,
}

impl ParameterSet for SlhDsaAcvpParameterSet {
    fn name(&self) -> &str {
        match self.param_set {
            SlhDsaParameterSet::SlhDsa128s => "SLH-DSA-SHAKE-128s",
            SlhDsaParameterSet::SlhDsa128f => "SLH-DSA-SHAKE-128f",
            SlhDsaParameterSet::SlhDsa192s => "SLH-DSA-SHAKE-192s",
            SlhDsaParameterSet::SlhDsa192f => "SLH-DSA-SHAKE-192f",
            SlhDsaParameterSet::SlhDsa256s => "SLH-DSA-SHAKE-256s",
            SlhDsaParameterSet::SlhDsa256f => "SLH-DSA-SHAKE-256f",
        }
    }

    fn security_level(&self) -> u8 {
        match self.param_set {
            SlhDsaParameterSet::SlhDsa128s | SlhDsaParameterSet::SlhDsa128f => 1, // NIST Level 1
            SlhDsaParameterSet::SlhDsa192s | SlhDsaParameterSet::SlhDsa192f => 3, // NIST Level 3
            SlhDsaParameterSet::SlhDsa256s | SlhDsaParameterSet::SlhDsa256f => 5, // NIST Level 5
        }
    }

    fn public_key_size(&self) -> usize {
        self.param_set.public_key_bytes()
    }

    fn secret_key_size(&self) -> usize {
        self.param_set.secret_key_bytes()
    }

    fn validate(&self) -> Result<()> {
        // Basic validation - ensure sizes are reasonable
        let pk_size = self.public_key_size();
        let sk_size = self.secret_key_size();
        let sig_size = self.signature_size();

        if pk_size == 0 || sk_size == 0 || sig_size == 0 {
            return Err(AcvpError::ValidationError(
                "Parameter set has zero-sized fields".to_string(),
            ));
        }

        Ok(())
    }
}

impl SlhDsaAcvpParameterSet {
    /// Get signature size in bytes
    pub fn signature_size(&self) -> usize {
        self.param_set.signature_bytes()
    }
}

/// SLH-DSA ACVP-compatible algorithm implementation
pub struct SlhDsaAcvp;

impl AcvpCompatible for SlhDsaAcvp {
    type ParameterSet = SlhDsaAcvpParameterSet;

    const ALGORITHM_NAME: &'static str = "SLH-DSA";

    fn parse_parameter_set(name: &str) -> Result<Self::ParameterSet> {
        let param_set = match name {
            // SHAKE variants (standard)
            "SLH-DSA-SHAKE-128s" | "SLH-DSA-128s" | "SlhDsa128s" => SlhDsaParameterSet::SlhDsa128s,
            "SLH-DSA-SHAKE-128f" | "SLH-DSA-128f" | "SlhDsa128f" => SlhDsaParameterSet::SlhDsa128f,
            "SLH-DSA-SHAKE-192s" | "SLH-DSA-192s" | "SlhDsa192s" => SlhDsaParameterSet::SlhDsa192s,
            "SLH-DSA-SHAKE-192f" | "SLH-DSA-192f" | "SlhDsa192f" => SlhDsaParameterSet::SlhDsa192f,
            "SLH-DSA-SHAKE-256s" | "SLH-DSA-256s" | "SlhDsa256s" => SlhDsaParameterSet::SlhDsa256s,
            "SLH-DSA-SHAKE-256f" | "SLH-DSA-256f" | "SlhDsa256f" => SlhDsaParameterSet::SlhDsa256f,
            _ => return Err(AcvpError::UnknownParameterSet(name.to_string())),
        };

        Ok(SlhDsaAcvpParameterSet { param_set })
    }

    fn supported_parameter_sets() -> Vec<Self::ParameterSet> {
        vec![
            SlhDsaAcvpParameterSet { param_set: SlhDsaParameterSet::SlhDsa128s },
            SlhDsaAcvpParameterSet { param_set: SlhDsaParameterSet::SlhDsa128f },
            SlhDsaAcvpParameterSet { param_set: SlhDsaParameterSet::SlhDsa192s },
            SlhDsaAcvpParameterSet { param_set: SlhDsaParameterSet::SlhDsa192f },
            SlhDsaAcvpParameterSet { param_set: SlhDsaParameterSet::SlhDsa256s },
            SlhDsaAcvpParameterSet { param_set: SlhDsaParameterSet::SlhDsa256f },
        ]
    }

    fn supported_test_types() -> Vec<&'static str> {
        vec!["keyGen", "sigGen", "sigVer"]
    }

    fn validate_test_case(
        &self,
        test: &AcvpTestCase,
        group: &AcvpTestGroup,
        param_set: &Self::ParameterSet,
    ) -> Result<()> {
        // Validate based on test type
        match group.test_type.as_str() {
            "keyGen" => self.validate_keygen_test(test, param_set),
            "sigGen" => self.validate_siggen_test(test, param_set),
            "sigVer" => self.validate_sigver_test(test, param_set),
            _ => Ok(()), // Unknown test types handled by base validation
        }
    }

    fn validate_field_sizes(&self, test: &AcvpTestCase, param_set: &Self::ParameterSet) -> Result<()> {
        // Validate pk size if present
        if let Some(pk_hex) = test.get_string("pk") {
            let expected = param_set.public_key_size();
            let actual = pk_hex.len() / 2; // hex is 2 chars per byte
            if actual != expected {
                return Err(AcvpError::size_mismatch("pk", expected, actual));
            }
        }

        // Validate sk size if present
        if let Some(sk_hex) = test.get_string("sk") {
            let expected = param_set.secret_key_size();
            let actual = sk_hex.len() / 2;
            if actual != expected {
                return Err(AcvpError::size_mismatch("sk", expected, actual));
            }
        }

        // Validate signature size if present
        if let Some(sig_hex) = test.get_string("signature") {
            let expected = param_set.signature_size();
            let actual = sig_hex.len() / 2;
            if actual != expected {
                return Err(AcvpError::size_mismatch("signature", expected, actual));
            }
        }

        Ok(())
    }
}

impl KeyGeneration for SlhDsaAcvp {}

impl SignatureAlgorithm for SlhDsaAcvp {
    fn signature_size(param_set: &Self::ParameterSet) -> usize {
        param_set.signature_size()
    }
}

/// Convenience type alias for SLH-DSA ACVP parser
pub type SlhDsaAcvpParser = AcvpParser<SlhDsaAcvp>;

/// Create a new SLH-DSA ACVP parser
pub fn new_parser() -> SlhDsaAcvpParser {
    SlhDsaAcvpParser::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_set_parsing() {
        // Test all standard names
        assert!(SlhDsaAcvp::parse_parameter_set("SLH-DSA-SHAKE-128s").is_ok());
        assert!(SlhDsaAcvp::parse_parameter_set("SLH-DSA-SHAKE-128f").is_ok());
        assert!(SlhDsaAcvp::parse_parameter_set("SLH-DSA-SHAKE-192s").is_ok());
        assert!(SlhDsaAcvp::parse_parameter_set("SLH-DSA-SHAKE-192f").is_ok());
        assert!(SlhDsaAcvp::parse_parameter_set("SLH-DSA-SHAKE-256s").is_ok());
        assert!(SlhDsaAcvp::parse_parameter_set("SLH-DSA-SHAKE-256f").is_ok());

        // Test invalid
        assert!(SlhDsaAcvp::parse_parameter_set("invalid").is_err());
    }

    #[test]
    fn test_parameter_set_properties() {
        let param_set = SlhDsaAcvp::parse_parameter_set("SLH-DSA-SHAKE-128s").unwrap();
        assert_eq!(param_set.name(), "SLH-DSA-SHAKE-128s");
        assert_eq!(param_set.security_level(), 1);
        assert_eq!(param_set.public_key_size(), 32);
        assert_eq!(param_set.secret_key_size(), 64);
        assert_eq!(param_set.signature_size(), 7856);

        let param_set = SlhDsaAcvp::parse_parameter_set("SLH-DSA-SHAKE-192s").unwrap();
        assert_eq!(param_set.name(), "SLH-DSA-SHAKE-192s");
        assert_eq!(param_set.security_level(), 3);
        assert_eq!(param_set.public_key_size(), 48);
        assert_eq!(param_set.secret_key_size(), 96);
        assert_eq!(param_set.signature_size(), 16224);

        let param_set = SlhDsaAcvp::parse_parameter_set("SLH-DSA-SHAKE-256s").unwrap();
        assert_eq!(param_set.name(), "SLH-DSA-SHAKE-256s");
        assert_eq!(param_set.security_level(), 5);
        assert_eq!(param_set.public_key_size(), 64);
        assert_eq!(param_set.secret_key_size(), 128);
        assert_eq!(param_set.signature_size(), 29792);
    }

    #[test]
    fn test_supported_parameter_sets() {
        let sets = SlhDsaAcvp::supported_parameter_sets();
        assert_eq!(sets.len(), 6);
        assert_eq!(sets[0].name(), "SLH-DSA-SHAKE-128s");
        assert_eq!(sets[1].name(), "SLH-DSA-SHAKE-128f");
        assert_eq!(sets[2].name(), "SLH-DSA-SHAKE-192s");
        assert_eq!(sets[3].name(), "SLH-DSA-SHAKE-192f");
        assert_eq!(sets[4].name(), "SLH-DSA-SHAKE-256s");
        assert_eq!(sets[5].name(), "SLH-DSA-SHAKE-256f");
    }

    #[test]
    fn test_supported_test_types() {
        let types = SlhDsaAcvp::supported_test_types();
        assert_eq!(types.len(), 3);
        assert!(types.contains(&"keyGen"));
        assert!(types.contains(&"sigGen"));
        assert!(types.contains(&"sigVer"));
    }

    #[test]
    fn test_parser_creation() {
        let parser = new_parser();
        assert!(parser.get_parameter_set("SLH-DSA-SHAKE-128s").is_some());
        assert!(parser.get_parameter_set("SLH-DSA-SHAKE-256f").is_some());
    }

    #[test]
    fn test_parse_simple_acvp_json() {
        let json = r#"{
            "algorithm": "SLH-DSA",
            "mode": "keyGen",
            "revision": "FIPS205",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "keyGen",
                    "parameterSet": "SLH-DSA-SHAKE-128s",
                    "tests": []
                }
            ]
        }"#;

        let parser = new_parser();
        let result = parser.parse_json(json);
        assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
    }
}
