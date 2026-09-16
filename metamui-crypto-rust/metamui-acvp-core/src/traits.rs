//! Traits for algorithm-specific ACVP implementations

use crate::{AcvpTestCase, AcvpTestGroup, Result};
use std::fmt::Debug;

/// Algorithm-specific parameter set information
///
/// Each algorithm should implement this trait to describe its parameter sets
/// (e.g., ML-DSA-44/65/87, ML-KEM-512/768/1024, SLH-DSA-128s/128f/etc.)
pub trait ParameterSet: Clone + Debug {
    /// Parameter set name (e.g., "ML-DSA-44", "ML-KEM-768")
    fn name(&self) -> &str;

    /// NIST security level (1-5)
    fn security_level(&self) -> u8;

    /// Public key size in bytes
    fn public_key_size(&self) -> usize;

    /// Secret key size in bytes
    fn secret_key_size(&self) -> usize;

    /// Algorithm-specific validation
    /// Returns Ok(()) if parameters are valid for this algorithm
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// Main trait for ACVP-compatible algorithms
///
/// Implement this trait to enable ACVP test vector parsing and validation
/// for your cryptographic algorithm.
pub trait AcvpCompatible: Sized {
    /// Parameter set type for this algorithm
    type ParameterSet: ParameterSet;

    /// Algorithm name (e.g., "ML-KEM", "ML-DSA", "SLH-DSA")
    const ALGORITHM_NAME: &'static str;

    /// Parse parameter set from name
    fn parse_parameter_set(name: &str) -> Result<Self::ParameterSet>;

    /// Get all supported parameter sets
    fn supported_parameter_sets() -> Vec<Self::ParameterSet>;

    /// Get supported test types for this algorithm
    /// Examples: ["keyGen", "sigGen", "sigVer"] for signatures
    ///          ["keyGen", "encapGen", "decap"] for KEMs
    fn supported_test_types() -> Vec<&'static str>;

    /// Validate test group parameters
    /// Override for algorithm-specific validation beyond basic checks
    fn validate_test_group(
        &self,
        _group: &AcvpTestGroup,
        _param_set: &Self::ParameterSet,
    ) -> Result<()> {
        Ok(())
    }

    /// Validate individual test case
    /// Override for algorithm-specific field validation
    fn validate_test_case(
        &self,
        _test: &AcvpTestCase,
        _group: &AcvpTestGroup,
        _param_set: &Self::ParameterSet,
    ) -> Result<()> {
        Ok(())
    }

    /// Validate sizes of hex-encoded fields
    /// Override to add custom size validation logic
    fn validate_field_sizes(
        &self,
        _test: &AcvpTestCase,
        _param_set: &Self::ParameterSet,
    ) -> Result<()> {
        Ok(())
    }
}

/// Trait for algorithms that support key generation
pub trait KeyGeneration: AcvpCompatible {
    /// Validate key generation test case
    fn validate_keygen_test(
        &self,
        test: &AcvpTestCase,
        param_set: &Self::ParameterSet,
    ) -> Result<()> {
        // Common validation: check pk and sk presence and sizes
        let pk = test.get_bytes("pk").ok_or_else(|| {
            crate::AcvpError::MissingField("pk (public key)".to_string())
        })?;

        let sk = test.get_bytes("sk").ok_or_else(|| {
            crate::AcvpError::MissingField("sk (secret key)".to_string())
        })?;

        if pk.len() != param_set.public_key_size() {
            return Err(crate::AcvpError::size_mismatch(
                "pk",
                param_set.public_key_size(),
                pk.len(),
            ));
        }

        if sk.len() != param_set.secret_key_size() {
            return Err(crate::AcvpError::size_mismatch(
                "sk",
                param_set.secret_key_size(),
                sk.len(),
            ));
        }

        Ok(())
    }
}

/// Trait for signature algorithms (sigGen, sigVer)
pub trait SignatureAlgorithm: AcvpCompatible {
    /// Signature size for parameter set
    fn signature_size(param_set: &Self::ParameterSet) -> usize;

    /// Validate signature generation test
    fn validate_siggen_test(
        &self,
        test: &AcvpTestCase,
        param_set: &Self::ParameterSet,
    ) -> Result<()> {
        // Check message and signature presence
        let _message = test.get_bytes("message").ok_or_else(|| {
            crate::AcvpError::MissingField("message".to_string())
        })?;

        let signature = test.get_bytes("signature").ok_or_else(|| {
            crate::AcvpError::MissingField("signature".to_string())
        })?;

        let expected_sig_size = Self::signature_size(param_set);
        if signature.len() != expected_sig_size {
            return Err(crate::AcvpError::size_mismatch(
                "signature",
                expected_sig_size,
                signature.len(),
            ));
        }

        Ok(())
    }

    /// Validate signature verification test
    fn validate_sigver_test(
        &self,
        test: &AcvpTestCase,
        _param_set: &Self::ParameterSet,
    ) -> Result<()> {
        // Check all required fields
        let _pk = test.get_bytes("pk").ok_or_else(|| {
            crate::AcvpError::MissingField("pk".to_string())
        })?;

        let _message = test.get_bytes("message").ok_or_else(|| {
            crate::AcvpError::MissingField("message".to_string())
        })?;

        let _signature = test.get_bytes("signature").ok_or_else(|| {
            crate::AcvpError::MissingField("signature".to_string())
        })?;

        // Should have expected result
        test.get_expected_result().ok_or_else(|| {
            crate::AcvpError::MissingField("test result (testPassed/sigVer)".to_string())
        })?;

        Ok(())
    }
}

/// Trait for KEM algorithms (encapGen, decap)
pub trait KemAlgorithm: AcvpCompatible {
    /// Ciphertext size for parameter set
    fn ciphertext_size(param_set: &Self::ParameterSet) -> usize;

    /// Shared secret size for parameter set
    fn shared_secret_size(param_set: &Self::ParameterSet) -> usize;

    /// Validate encapsulation test
    fn validate_encap_test(
        &self,
        test: &AcvpTestCase,
        param_set: &Self::ParameterSet,
    ) -> Result<()> {
        let ct = test.get_bytes("ct").or_else(|| test.get_bytes("ciphertext"))
            .ok_or_else(|| {
                crate::AcvpError::MissingField("ct/ciphertext".to_string())
            })?;

        let ss = test.get_bytes("ss").or_else(|| test.get_bytes("sharedSecret"))
            .ok_or_else(|| {
                crate::AcvpError::MissingField("ss/sharedSecret".to_string())
            })?;

        let expected_ct_size = Self::ciphertext_size(param_set);
        if ct.len() != expected_ct_size {
            return Err(crate::AcvpError::size_mismatch(
                "ciphertext",
                expected_ct_size,
                ct.len(),
            ));
        }

        let expected_ss_size = Self::shared_secret_size(param_set);
        if ss.len() != expected_ss_size {
            return Err(crate::AcvpError::size_mismatch(
                "shared_secret",
                expected_ss_size,
                ss.len(),
            ));
        }

        Ok(())
    }

    /// Validate decapsulation test
    fn validate_decap_test(
        &self,
        test: &AcvpTestCase,
        _param_set: &Self::ParameterSet,
    ) -> Result<()> {
        let _sk = test.get_bytes("sk").ok_or_else(|| {
            crate::AcvpError::MissingField("sk".to_string())
        })?;

        let _ct = test.get_bytes("ct").or_else(|| test.get_bytes("ciphertext"))
            .ok_or_else(|| {
                crate::AcvpError::MissingField("ct/ciphertext".to_string())
            })?;

        let _ss = test.get_bytes("ss").or_else(|| test.get_bytes("sharedSecret"))
            .ok_or_else(|| {
                crate::AcvpError::MissingField("ss/sharedSecret".to_string())
            })?;

        Ok(())
    }
}

/// Trait for hash-based algorithms
pub trait HashAlgorithm: AcvpCompatible {
    /// Hash output size in bytes
    fn hash_size(param_set: &Self::ParameterSet) -> usize;

    /// Validate hash test
    fn validate_hash_test(
        &self,
        test: &AcvpTestCase,
        param_set: &Self::ParameterSet,
    ) -> Result<()> {
        let _message = test.get_bytes("msg").or_else(|| test.get_bytes("message"))
            .ok_or_else(|| {
                crate::AcvpError::MissingField("msg/message".to_string())
            })?;

        let digest = test.get_bytes("md").or_else(|| test.get_bytes("digest"))
            .ok_or_else(|| {
                crate::AcvpError::MissingField("md/digest".to_string())
            })?;

        let expected_size = Self::hash_size(param_set);
        if digest.len() != expected_size {
            return Err(crate::AcvpError::size_mismatch(
                "digest",
                expected_size,
                digest.len(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock parameter set for testing
    #[derive(Clone, Debug)]
    struct MockParamSet {
        name: String,
        level: u8,
        pk_size: usize,
        sk_size: usize,
    }

    impl ParameterSet for MockParamSet {
        fn name(&self) -> &str {
            &self.name
        }
        fn security_level(&self) -> u8 {
            self.level
        }
        fn public_key_size(&self) -> usize {
            self.pk_size
        }
        fn secret_key_size(&self) -> usize {
            self.sk_size
        }
    }

    #[test]
    fn test_parameter_set_trait() {
        let params = MockParamSet {
            name: "Test-Param".to_string(),
            level: 3,
            pk_size: 100,
            sk_size: 200,
        };

        assert_eq!(params.name(), "Test-Param");
        assert_eq!(params.security_level(), 3);
        assert_eq!(params.public_key_size(), 100);
        assert_eq!(params.secret_key_size(), 200);
        assert!(params.validate().is_ok());
    }
}
