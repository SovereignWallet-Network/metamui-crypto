//! ACVP (Automated Cryptographic Validation Protocol) Parser for ML-DSA (Dilithium)
//!
//! This module provides NIST FIPS 204 ML-DSA test vector parsing in ACVP format.
//! Refactored to use generic metamui-acvp-core infrastructure.

use crate::params::{DilithiumParams, DILITHIUM2_PARAMS, DILITHIUM3_PARAMS, DILITHIUM5_PARAMS};
use metamui_acvp_core::{
    traits::{AcvpCompatible, KeyGeneration, ParameterSet, SignatureAlgorithm},
    AcvpError, AcvpParser, AcvpTestCase, AcvpTestGroup, Result,
};

/// ML-DSA parameter set enumeration
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlDsaParameterSet {
    /// ML-DSA-44 (Dilithium2, NIST Level 2)
    MlDsa44,
    /// ML-DSA-65 (Dilithium3, NIST Level 3)
    MlDsa65,
    /// ML-DSA-87 (Dilithium5, NIST Level 5)
    MlDsa87,
}

impl MlDsaParameterSet {
    /// Get the Dilithium parameters for this set
    fn params(&self) -> &'static DilithiumParams {
        match self {
            MlDsaParameterSet::MlDsa44 => &DILITHIUM2_PARAMS,
            MlDsaParameterSet::MlDsa65 => &DILITHIUM3_PARAMS,
            MlDsaParameterSet::MlDsa87 => &DILITHIUM5_PARAMS,
        }
    }
}

/// ML-DSA ACVP parameter set wrapper
#[derive(Clone, Debug)]
pub struct MlDsaAcvpParameterSet {
    /// Parameter set identifier
    pub param_set: MlDsaParameterSet,
    /// Dilithium parameters
    params: &'static DilithiumParams,
}

impl ParameterSet for MlDsaAcvpParameterSet {
    fn name(&self) -> &str {
        match self.param_set {
            MlDsaParameterSet::MlDsa44 => "ML-DSA-44",
            MlDsaParameterSet::MlDsa65 => "ML-DSA-65",
            MlDsaParameterSet::MlDsa87 => "ML-DSA-87",
        }
    }

    fn security_level(&self) -> u8 {
        match self.param_set {
            MlDsaParameterSet::MlDsa44 => 2, // NIST Level 2
            MlDsaParameterSet::MlDsa65 => 3, // NIST Level 3
            MlDsaParameterSet::MlDsa87 => 5, // NIST Level 5
        }
    }

    fn public_key_size(&self) -> usize {
        self.params.pk_bytes
    }

    fn secret_key_size(&self) -> usize {
        self.params.sk_bytes
    }

    fn validate(&self) -> Result<()> {
        // Validate parameter consistency
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

impl MlDsaAcvpParameterSet {
    /// Get signature size in bytes
    pub fn signature_size(&self) -> usize {
        self.params.sig_bytes
    }
}

/// ML-DSA ACVP-compatible algorithm implementation
pub struct MlDsaAcvp;

impl AcvpCompatible for MlDsaAcvp {
    type ParameterSet = MlDsaAcvpParameterSet;

    const ALGORITHM_NAME: &'static str = "ML-DSA";

    fn parse_parameter_set(name: &str) -> Result<Self::ParameterSet> {
        let param_set = match name {
            "ML-DSA-44" | "MlDsa44" | "Dilithium2" => MlDsaParameterSet::MlDsa44,
            "ML-DSA-65" | "MlDsa65" | "Dilithium3" => MlDsaParameterSet::MlDsa65,
            "ML-DSA-87" | "MlDsa87" | "Dilithium5" => MlDsaParameterSet::MlDsa87,
            _ => return Err(AcvpError::UnknownParameterSet(name.to_string())),
        };

        let params = param_set.params();

        Ok(MlDsaAcvpParameterSet { param_set, params })
    }

    fn supported_parameter_sets() -> Vec<Self::ParameterSet> {
        vec![
            MlDsaAcvpParameterSet {
                param_set: MlDsaParameterSet::MlDsa44,
                params: &DILITHIUM2_PARAMS,
            },
            MlDsaAcvpParameterSet {
                param_set: MlDsaParameterSet::MlDsa65,
                params: &DILITHIUM3_PARAMS,
            },
            MlDsaAcvpParameterSet {
                param_set: MlDsaParameterSet::MlDsa87,
                params: &DILITHIUM5_PARAMS,
            },
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
            let actual = pk_hex.len() / 2;
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

impl KeyGeneration for MlDsaAcvp {}

impl SignatureAlgorithm for MlDsaAcvp {
    fn signature_size(param_set: &Self::ParameterSet) -> usize {
        param_set.signature_size()
    }
}

/// Convenience type alias for ML-DSA ACVP parser
pub type MlDsaAcvpParser = AcvpParser<MlDsaAcvp>;

/// Create a new ML-DSA ACVP parser
pub fn new_parser() -> MlDsaAcvpParser {
    MlDsaAcvpParser::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_set_parsing() {
        assert!(MlDsaAcvp::parse_parameter_set("ML-DSA-44").is_ok());
        assert!(MlDsaAcvp::parse_parameter_set("ML-DSA-65").is_ok());
        assert!(MlDsaAcvp::parse_parameter_set("ML-DSA-87").is_ok());
        assert!(MlDsaAcvp::parse_parameter_set("Dilithium2").is_ok());
        assert!(MlDsaAcvp::parse_parameter_set("invalid").is_err());
    }

    #[test]
    fn test_parameter_set_properties() {
        let param_set = MlDsaAcvp::parse_parameter_set("ML-DSA-44").unwrap();
        assert_eq!(param_set.name(), "ML-DSA-44");
        assert_eq!(param_set.security_level(), 2);
        assert_eq!(param_set.public_key_size(), 1312);
        assert_eq!(param_set.secret_key_size(), 2560);
        assert_eq!(param_set.signature_size(), 2420);

        let param_set = MlDsaAcvp::parse_parameter_set("ML-DSA-65").unwrap();
        assert_eq!(param_set.name(), "ML-DSA-65");
        assert_eq!(param_set.security_level(), 3);
        assert_eq!(param_set.public_key_size(), 1952);
        assert_eq!(param_set.secret_key_size(), 4032);
        assert_eq!(param_set.signature_size(), 3309);

        let param_set = MlDsaAcvp::parse_parameter_set("ML-DSA-87").unwrap();
        assert_eq!(param_set.name(), "ML-DSA-87");
        assert_eq!(param_set.security_level(), 5);
        assert_eq!(param_set.public_key_size(), 2592);
        assert_eq!(param_set.secret_key_size(), 4896);
        assert_eq!(param_set.signature_size(), 4627);
    }

    #[test]
    fn test_supported_parameter_sets() {
        let sets = MlDsaAcvp::supported_parameter_sets();
        assert_eq!(sets.len(), 3);
        assert_eq!(sets[0].name(), "ML-DSA-44");
        assert_eq!(sets[1].name(), "ML-DSA-65");
        assert_eq!(sets[2].name(), "ML-DSA-87");
    }

    #[test]
    fn test_supported_test_types() {
        let types = MlDsaAcvp::supported_test_types();
        assert_eq!(types.len(), 3);
        assert!(types.contains(&"keyGen"));
        assert!(types.contains(&"sigGen"));
        assert!(types.contains(&"sigVer"));
    }

    #[test]
    fn test_parser_creation() {
        let parser = new_parser();
        assert!(parser.get_parameter_set("ML-DSA-44").is_some());
        assert!(parser.get_parameter_set("ML-DSA-65").is_some());
        assert!(parser.get_parameter_set("ML-DSA-87").is_some());
    }

    #[test]
    fn test_parse_simple_acvp_json() {
        let json = r#"{
            "algorithm": "ML-DSA",
            "mode": "keyGen",
            "revision": "FIPS204",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "keyGen",
                    "parameterSet": "ML-DSA-44",
                    "tests": []
                }
            ]
        }"#;

        let parser = new_parser();
        let result = parser.parse_json(json);
        assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
    }
}
