//! ACVP (Automated Cryptographic Validation Protocol) Parser for ML-KEM
//!
//! This module provides NIST FIPS 203 ML-KEM test vector parsing in ACVP format.
//! It supports all ML-KEM parameter sets (512, 768, 1024) and test types
//! (keyGen, encapGen, decap).

use crate::{
    params::{MLKemParameterSet, MLKemParams, MLKEM512_PARAMS, MLKEM768_PARAMS, MLKEM1024_PARAMS},
};
use metamui_acvp_core::{
    traits::{AcvpCompatible, KemAlgorithm, KeyGeneration, ParameterSet},
    AcvpError, AcvpParser, AcvpTestCase, AcvpTestGroup, Result,
};

/// ML-KEM ACVP parameter set wrapper
///
/// Wraps ML-KEM's internal parameter set to implement ACVP's ParameterSet trait
#[derive(Clone, Debug)]
pub struct MlKemAcvpParameterSet {
    /// Parameter set identifier
    pub param_set: MLKemParameterSet,
    /// Parameter values
    pub params: &'static MLKemParams,
}

impl ParameterSet for MlKemAcvpParameterSet {
    fn name(&self) -> &str {
        match self.param_set {
            MLKemParameterSet::MLKem512 => "ML-KEM-512",
            MLKemParameterSet::MLKem768 => "ML-KEM-768",
            MLKemParameterSet::MLKem1024 => "ML-KEM-1024",
        }
    }

    fn security_level(&self) -> u8 {
        match self.param_set {
            MLKemParameterSet::MLKem512 => 1,  // NIST Level 1
            MLKemParameterSet::MLKem768 => 3,  // NIST Level 3
            MLKemParameterSet::MLKem1024 => 5, // NIST Level 5
        }
    }

    fn public_key_size(&self) -> usize {
        self.params.public_key_bytes
    }

    fn secret_key_size(&self) -> usize {
        self.params.secret_key_bytes
    }

    fn validate(&self) -> Result<()> {
        self.params
            .validate()
            .map_err(|e| AcvpError::ValidationError(format!("Parameter validation failed: {:?}", e)))
    }
}

impl MlKemAcvpParameterSet {
    /// Get ciphertext size in bytes
    pub fn ciphertext_size(&self) -> usize {
        self.params.ciphertext_bytes
    }

    /// Get shared secret size in bytes
    pub fn shared_secret_size(&self) -> usize {
        self.params.shared_secret_bytes
    }
}

/// ML-KEM ACVP-compatible algorithm implementation
pub struct MlKemAcvp;

impl AcvpCompatible for MlKemAcvp {
    type ParameterSet = MlKemAcvpParameterSet;

    const ALGORITHM_NAME: &'static str = "ML-KEM";

    fn parse_parameter_set(name: &str) -> Result<Self::ParameterSet> {
        let param_set = match name {
            "ML-KEM-512" | "MLKem512" | "mlkem512" => MLKemParameterSet::MLKem512,
            "ML-KEM-768" | "MLKem768" | "mlkem768" => MLKemParameterSet::MLKem768,
            "ML-KEM-1024" | "MLKem1024" | "mlkem1024" => MLKemParameterSet::MLKem1024,
            _ => return Err(AcvpError::UnknownParameterSet(name.to_string())),
        };

        let params = param_set.params();

        Ok(MlKemAcvpParameterSet { param_set, params })
    }

    fn supported_parameter_sets() -> Vec<Self::ParameterSet> {
        vec![
            MlKemAcvpParameterSet {
                param_set: MLKemParameterSet::MLKem512,
                params: &MLKEM512_PARAMS,
            },
            MlKemAcvpParameterSet {
                param_set: MLKemParameterSet::MLKem768,
                params: &MLKEM768_PARAMS,
            },
            MlKemAcvpParameterSet {
                param_set: MLKemParameterSet::MLKem1024,
                params: &MLKEM1024_PARAMS,
            },
        ]
    }

    fn supported_test_types() -> Vec<&'static str> {
        vec!["keyGen", "encapGen", "decap"]
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
            "encapGen" => self.validate_encap_test(test, param_set),
            "decap" => self.validate_decap_test(test, param_set),
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

        // Validate ct/ciphertext size if present
        if let Some(ct_hex) = test.get_string("ct").or_else(|| test.get_string("ciphertext")) {
            let expected = param_set.ciphertext_size();
            let actual = ct_hex.len() / 2;
            if actual != expected {
                return Err(AcvpError::size_mismatch("ciphertext", expected, actual));
            }
        }

        // Validate ss/sharedSecret size if present
        if let Some(ss_hex) = test.get_string("ss").or_else(|| test.get_string("sharedSecret")) {
            let expected = param_set.shared_secret_size();
            let actual = ss_hex.len() / 2;
            if actual != expected {
                return Err(AcvpError::size_mismatch("shared_secret", expected, actual));
            }
        }

        Ok(())
    }
}

impl KeyGeneration for MlKemAcvp {}

impl KemAlgorithm for MlKemAcvp {
    fn ciphertext_size(param_set: &Self::ParameterSet) -> usize {
        param_set.ciphertext_size()
    }

    fn shared_secret_size(param_set: &Self::ParameterSet) -> usize {
        param_set.shared_secret_size()
    }
}

/// Convenience type alias for ML-KEM ACVP parser
pub type MlKemAcvpParser = AcvpParser<MlKemAcvp>;

/// Create a new ML-KEM ACVP parser
pub fn new_parser() -> MlKemAcvpParser {
    MlKemAcvpParser::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_set_parsing() {
        assert!(MlKemAcvp::parse_parameter_set("ML-KEM-512").is_ok());
        assert!(MlKemAcvp::parse_parameter_set("ML-KEM-768").is_ok());
        assert!(MlKemAcvp::parse_parameter_set("ML-KEM-1024").is_ok());
        assert!(MlKemAcvp::parse_parameter_set("invalid").is_err());
    }

    #[test]
    fn test_parameter_set_properties() {
        let param_set = MlKemAcvp::parse_parameter_set("ML-KEM-768").unwrap();
        assert_eq!(param_set.name(), "ML-KEM-768");
        assert_eq!(param_set.security_level(), 3);
        assert_eq!(param_set.public_key_size(), 1184);
        assert_eq!(param_set.secret_key_size(), 2400);
        assert_eq!(param_set.ciphertext_size(), 1088);
        assert_eq!(param_set.shared_secret_size(), 32);
    }

    #[test]
    fn test_supported_parameter_sets() {
        let sets = MlKemAcvp::supported_parameter_sets();
        assert_eq!(sets.len(), 3);
        assert_eq!(sets[0].name(), "ML-KEM-512");
        assert_eq!(sets[1].name(), "ML-KEM-768");
        assert_eq!(sets[2].name(), "ML-KEM-1024");
    }

    #[test]
    fn test_supported_test_types() {
        let types = MlKemAcvp::supported_test_types();
        assert_eq!(types.len(), 3);
        assert!(types.contains(&"keyGen"));
        assert!(types.contains(&"encapGen"));
        assert!(types.contains(&"decap"));
    }

    #[test]
    fn test_parser_creation() {
        let parser = new_parser();
        assert!(parser.get_parameter_set("ML-KEM-512").is_some());
        assert!(parser.get_parameter_set("ML-KEM-768").is_some());
        assert!(parser.get_parameter_set("ML-KEM-1024").is_some());
    }

    #[test]
    fn test_parse_simple_acvp_json() {
        let json = r#"{
            "algorithm": "ML-KEM",
            "mode": "keyGen",
            "revision": "FIPS203",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "keyGen",
                    "parameterSet": "ML-KEM-768",
                    "tests": []
                }
            ]
        }"#;

        let parser = new_parser();
        let result = parser.parse_json(json);
        assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
    }
}
