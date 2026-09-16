//! ACVP Parser for Falcon Digital Signature Scheme
//!
//! Supports Falcon-512 and Falcon-1024 parameter sets.

use crate::constants::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES, CRYPTO_BYTES};
use metamui_acvp_core::{
    traits::{AcvpCompatible, KeyGeneration, ParameterSet, SignatureAlgorithm},
    AcvpError, AcvpParser, AcvpTestCase, AcvpTestGroup, Result,
};

/// Falcon parameter set enumeration
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FalconParameterSet {
    /// Falcon-512 (NIST Level 1, 128-bit security)
    Falcon512,
    /// Falcon-1024 (NIST Level 5, 256-bit security)
    Falcon1024,
}

impl FalconParameterSet {
    fn key_sizes(&self) -> (usize, usize, usize) {
        match self {
            FalconParameterSet::Falcon512 => (CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES, CRYPTO_BYTES),
            FalconParameterSet::Falcon1024 => (1793, 2305, 1330),
        }
    }
}

/// Falcon ACVP parameter set wrapper
#[derive(Clone, Debug)]
pub struct FalconAcvpParameterSet {
    pub param_set: FalconParameterSet,
    key_sizes: (usize, usize, usize), // pk, sk, sig
}

impl ParameterSet for FalconAcvpParameterSet {
    fn name(&self) -> &str {
        match self.param_set {
            FalconParameterSet::Falcon512 => "Falcon-512",
            FalconParameterSet::Falcon1024 => "Falcon-1024",
        }
    }

    fn security_level(&self) -> u8 {
        match self.param_set {
            FalconParameterSet::Falcon512 => 1,
            FalconParameterSet::Falcon1024 => 5,
        }
    }

    fn public_key_size(&self) -> usize {
        self.key_sizes.0
    }

    fn secret_key_size(&self) -> usize {
        self.key_sizes.1
    }

    fn validate(&self) -> Result<()> {
        if self.public_key_size() == 0 || self.secret_key_size() == 0 || self.signature_size() == 0 {
            return Err(AcvpError::ValidationError("Parameter set has zero-sized fields".to_string()));
        }
        Ok(())
    }
}

impl FalconAcvpParameterSet {
    pub fn signature_size(&self) -> usize {
        self.key_sizes.2
    }
}

/// Falcon ACVP-compatible algorithm implementation
pub struct FalconAcvp;

impl AcvpCompatible for FalconAcvp {
    type ParameterSet = FalconAcvpParameterSet;

    const ALGORITHM_NAME: &'static str = "Falcon";

    fn parse_parameter_set(name: &str) -> Result<Self::ParameterSet> {
        let param_set = match name {
            "Falcon-512" | "falcon-512" | "FALCON-512" | "Falcon512" => FalconParameterSet::Falcon512,
            "Falcon-1024" | "falcon-1024" | "FALCON-1024" | "Falcon1024" => FalconParameterSet::Falcon1024,
            _ => return Err(AcvpError::UnknownParameterSet(name.to_string())),
        };

        let key_sizes = param_set.key_sizes();
        Ok(FalconAcvpParameterSet { param_set, key_sizes })
    }

    fn supported_parameter_sets() -> Vec<Self::ParameterSet> {
        vec![
            FalconAcvpParameterSet {
                param_set: FalconParameterSet::Falcon512,
                key_sizes: FalconParameterSet::Falcon512.key_sizes(),
            },
            FalconAcvpParameterSet {
                param_set: FalconParameterSet::Falcon1024,
                key_sizes: FalconParameterSet::Falcon1024.key_sizes(),
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
        match group.test_type.as_str() {
            "keyGen" => self.validate_keygen_test(test, param_set),
            "sigGen" => self.validate_siggen_test(test, param_set),
            "sigVer" => self.validate_sigver_test(test, param_set),
            _ => Ok(()),
        }
    }

    fn validate_field_sizes(&self, test: &AcvpTestCase, param_set: &Self::ParameterSet) -> Result<()> {
        if let Some(pk_hex) = test.get_string("pk") {
            let expected = param_set.public_key_size();
            let actual = pk_hex.len() / 2;
            if actual != expected {
                return Err(AcvpError::size_mismatch("pk", expected, actual));
            }
        }

        if let Some(sk_hex) = test.get_string("sk") {
            let expected = param_set.secret_key_size();
            let actual = sk_hex.len() / 2;
            if actual != expected {
                return Err(AcvpError::size_mismatch("sk", expected, actual));
            }
        }

        if let Some(sig_hex) = test.get_string("signature") {
            let expected = param_set.signature_size();
            let actual = sig_hex.len() / 2;
            if actual > expected {
                return Err(AcvpError::size_mismatch("signature", expected, actual));
            }
        }

        Ok(())
    }
}

impl KeyGeneration for FalconAcvp {}

impl SignatureAlgorithm for FalconAcvp {
    fn signature_size(param_set: &Self::ParameterSet) -> usize {
        param_set.signature_size()
    }
}

/// Type alias for Falcon ACVP parser
pub type FalconAcvpParser = AcvpParser<FalconAcvp>;

/// Create a new Falcon ACVP parser
pub fn new_parser() -> FalconAcvpParser {
    FalconAcvpParser::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_set_parsing() {
        assert!(FalconAcvp::parse_parameter_set("Falcon-512").is_ok());
        assert!(FalconAcvp::parse_parameter_set("Falcon-1024").is_ok());
        assert!(FalconAcvp::parse_parameter_set("invalid").is_err());
    }

    #[test]
    fn test_parameter_set_properties() {
        let ps512 = FalconAcvp::parse_parameter_set("Falcon-512").unwrap();
        assert_eq!(ps512.name(), "Falcon-512");
        assert_eq!(ps512.security_level(), 1);
        assert_eq!(ps512.public_key_size(), 897);
        assert_eq!(ps512.secret_key_size(), 2305);
        assert_eq!(ps512.signature_size(), 690);

        let ps1024 = FalconAcvp::parse_parameter_set("Falcon-1024").unwrap();
        assert_eq!(ps1024.name(), "Falcon-1024");
        assert_eq!(ps1024.security_level(), 5);
    }

    #[test]
    fn test_supported_parameter_sets() {
        let sets = FalconAcvp::supported_parameter_sets();
        assert_eq!(sets.len(), 2);
    }

    #[test]
    fn test_supported_test_types() {
        let types = FalconAcvp::supported_test_types();
        assert_eq!(types.len(), 3);
        assert!(types.contains(&"keyGen"));
        assert!(types.contains(&"sigGen"));
        assert!(types.contains(&"sigVer"));
    }
}
