/// ACVP (Automated Cryptographic Validation Protocol) Format Parser
/// 
/// This module provides comprehensive parsing for NIST FIPS 204 ML-DSA test vectors
/// in ACVP format. It supports all ML-DSA parameter sets and test types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// ACVP Test Suite containing multiple test groups
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcvpTestSuite {
    #[serde(rename = "vsId")]
    pub vs_id: Option<u32>,
    pub algorithm: String,
    pub mode: Option<String>,
    pub revision: Option<String>,
    #[serde(rename = "isSample")]
    pub is_sample: Option<bool>,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<AcvpTestGroup>,
}

/// ACVP Test Group containing test vectors with common parameters
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcvpTestGroup {
    #[serde(rename = "tgId")]
    pub tg_id: u32,
    #[serde(rename = "testType")]
    pub test_type: String,
    #[serde(rename = "parameterSet")]
    pub parameter_set: String,
    #[serde(rename = "sigType")]
    pub sig_type: Option<String>,
    pub deterministic: Option<bool>,
    pub tests: Vec<AcvpTestCase>,
}

/// Individual ACVP test case
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcvpTestCase {
    #[serde(rename = "tcId")]
    pub tc_id: u32,
    #[serde(rename = "sk")]
    pub secret_key: Option<String>,
    #[serde(rename = "pk")]
    pub public_key: Option<String>,
    pub message: Option<String>,
    pub context: Option<String>,
    pub signature: Option<String>,
    #[serde(rename = "testPassed")]
    pub test_passed: Option<bool>,
    pub reason: Option<String>,
    // Key generation specific fields
    pub seed: Option<String>,
    // Signature verification specific fields
    #[serde(rename = "sigVer")]
    pub sig_ver: Option<bool>,
}

/// ML-DSA parameter set information
#[derive(Debug, Clone)]
pub struct MlDsaParameterSet {
    pub name: String,
    pub security_level: u8,
    pub public_key_size: usize,
    pub secret_key_size: usize,
    pub signature_size: usize,
    pub k: usize,
    pub l: usize,
    pub eta: u32,
    pub tau: u32,
    pub beta: u32,
    pub gamma1: u32,
    pub gamma2: u32,
    pub omega: u32,
}

/// ACVP Parser for ML-DSA test vectors
pub struct AcvpParser {
    parameter_sets: HashMap<String, MlDsaParameterSet>,
}

impl AcvpParser {
    /// Create a new ACVP parser with ML-DSA parameter sets
    pub fn new() -> Self {
        let mut parameter_sets = HashMap::new();
        
        // ML-DSA-44 (Security Level 2)
        parameter_sets.insert("ML-DSA-44".to_string(), MlDsaParameterSet {
            name: "ML-DSA-44".to_string(),
            security_level: 2,
            public_key_size: 1312,
            secret_key_size: 2560,
            signature_size: 2420,
            k: 4,
            l: 4,
            eta: 2,
            tau: 39,
            beta: 78,
            gamma1: 131072,  // 2^17
            gamma2: 95232,   // (q-1)/88
            omega: 80,
        });
        
        // ML-DSA-65 (Security Level 3)
        parameter_sets.insert("ML-DSA-65".to_string(), MlDsaParameterSet {
            name: "ML-DSA-65".to_string(),
            security_level: 3,
            public_key_size: 1952,
            secret_key_size: 4032,
            signature_size: 3309,
            k: 6,
            l: 5,
            eta: 4,
            tau: 49,
            beta: 196,
            gamma1: 524288,  // 2^19
            gamma2: 261888,  // (q-1)/32
            omega: 55,
        });
        
        // ML-DSA-87 (Security Level 5)
        parameter_sets.insert("ML-DSA-87".to_string(), MlDsaParameterSet {
            name: "ML-DSA-87".to_string(),
            security_level: 5,
            public_key_size: 2592,
            secret_key_size: 4896,
            signature_size: 4627,
            k: 8,
            l: 7,
            eta: 2,
            tau: 60,
            beta: 120,
            gamma1: 524288,  // 2^19
            gamma2: 261888,  // (q-1)/32
            omega: 75,
        });
        
        Self { parameter_sets }
    }
    
    /// Parse ACVP test suite from JSON file
    pub fn parse_file<P: AsRef<Path>>(&self, path: P) -> Result<AcvpTestSuite, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        self.parse_json(&content)
    }
    
    /// Parse ACVP test suite from JSON string
    pub fn parse_json(&self, json: &str) -> Result<AcvpTestSuite, Box<dyn std::error::Error>> {
        let test_suite: AcvpTestSuite = serde_json::from_str(json)?;
        self.validate_test_suite(&test_suite)?;
        Ok(test_suite)
    }
    
    /// Validate test suite structure and parameters
    fn validate_test_suite(&self, test_suite: &AcvpTestSuite) -> Result<(), Box<dyn std::error::Error>> {
        // Validate algorithm
        if test_suite.algorithm != "ML-DSA" {
            return Err(format!("Unsupported algorithm: {}", test_suite.algorithm).into());
        }
        
        // Validate test groups
        for group in &test_suite.test_groups {
            self.validate_test_group(group)?;
        }
        
        Ok(())
    }
    
    /// Validate individual test group
    fn validate_test_group(&self, group: &AcvpTestGroup) -> Result<(), Box<dyn std::error::Error>> {
        // Validate parameter set
        let param_set = self.parameter_sets.get(&group.parameter_set)
            .ok_or_else(|| format!("Unknown parameter set: {}", group.parameter_set))?;
        
        // Validate test type
        match group.test_type.as_str() {
            "AFT" | "keyGen" | "sigGen" | "sigVer" => {},
            _ => return Err(format!("Unsupported test type: {}", group.test_type).into()),
        }
        
        // Validate test cases
        for test in &group.tests {
            self.validate_test_case(test, param_set)?;
        }
        
        Ok(())
    }
    
    /// Validate individual test case
    fn validate_test_case(&self, test: &AcvpTestCase, param_set: &MlDsaParameterSet) -> Result<(), Box<dyn std::error::Error>> {
        // Validate key sizes if present
        if let Some(ref pk) = test.public_key {
            let pk_bytes = hex::decode(pk).map_err(|e| format!("Invalid public key hex: {}", e))?;
            if pk_bytes.len() != param_set.public_key_size {
                return Err(format!("Invalid public key size: expected {}, got {}", 
                                   param_set.public_key_size, pk_bytes.len()).into());
            }
        }
        
        if let Some(ref sk) = test.secret_key {
            let sk_bytes = hex::decode(sk).map_err(|e| format!("Invalid secret key hex: {}", e))?;
            if sk_bytes.len() != param_set.secret_key_size {
                return Err(format!("Invalid secret key size: expected {}, got {}", 
                                   param_set.secret_key_size, sk_bytes.len()).into());
            }
        }
        
        if let Some(ref sig) = test.signature {
            let sig_bytes = hex::decode(sig).map_err(|e| format!("Invalid signature hex: {}", e))?;
            if sig_bytes.len() != param_set.signature_size {
                return Err(format!("Invalid signature size: expected {}, got {}", 
                                   param_set.signature_size, sig_bytes.len()).into());
            }
        }
        
        Ok(())
    }
    
    /// Get parameter set by name
    pub fn get_parameter_set(&self, name: &str) -> Option<&MlDsaParameterSet> {
        self.parameter_sets.get(name)
    }
    
    /// Filter test cases by test type
    pub fn filter_by_test_type<'a>(&self, test_suite: &'a AcvpTestSuite, test_type: &str) -> Vec<(&'a AcvpTestGroup, &'a AcvpTestCase)> {
        test_suite.test_groups
            .iter()
            .filter(|group| group.test_type == test_type)
            .flat_map(|group| group.tests.iter().map(move |test| (group, test)))
            .collect()
    }
    
    /// Filter test cases by parameter set
    pub fn filter_by_parameter_set<'a>(&self, test_suite: &'a AcvpTestSuite, param_set: &str) -> Vec<(&'a AcvpTestGroup, &'a AcvpTestCase)> {
        test_suite.test_groups
            .iter()
            .filter(|group| group.parameter_set == param_set)
            .flat_map(|group| group.tests.iter().map(move |test| (group, test)))
            .collect()
    }
    
    /// Convert test case to our internal test vector format
    pub fn to_internal_format(&self, group: &AcvpTestGroup, test: &AcvpTestCase) -> Result<InternalTestVector, Box<dyn std::error::Error>> {
        Ok(InternalTestVector {
            tc_id: test.tc_id,
            parameter_set: group.parameter_set.clone(),
            test_type: group.test_type.clone(),
            public_key: test.public_key.as_ref().map(|s| hex::decode(s)).transpose()?,
            secret_key: test.secret_key.as_ref().map(|s| hex::decode(s)).transpose()?,
            message: test.message.as_ref().map(|s| hex::decode(s)).transpose()?,
            context: test.context.as_ref().map(|s| hex::decode(s)).transpose()?,
            signature: test.signature.as_ref().map(|s| hex::decode(s)).transpose()?,
            expected_result: test.test_passed.or(test.sig_ver),
            reason: test.reason.clone(),
        })
    }
    
    /// Generate statistics about the test suite
    pub fn generate_statistics(&self, test_suite: &AcvpTestSuite) -> TestSuiteStatistics {
        let mut stats = TestSuiteStatistics::default();
        
        stats.total_groups = test_suite.test_groups.len();
        
        for group in &test_suite.test_groups {
            stats.total_tests += group.tests.len();
            
            *stats.by_parameter_set.entry(group.parameter_set.clone()).or_insert(0) += group.tests.len();
            *stats.by_test_type.entry(group.test_type.clone()).or_insert(0) += group.tests.len();
            
            for test in &group.tests {
                if test.test_passed == Some(true) || test.sig_ver == Some(true) {
                    stats.expected_pass += 1;
                } else if test.test_passed == Some(false) || test.sig_ver == Some(false) {
                    stats.expected_fail += 1;
                }
            }
        }
        
        stats
    }
}

/// Internal test vector format
#[derive(Debug, Clone)]
pub struct InternalTestVector {
    pub tc_id: u32,
    pub parameter_set: String,
    pub test_type: String,
    pub public_key: Option<Vec<u8>>,
    pub secret_key: Option<Vec<u8>>,
    pub message: Option<Vec<u8>>,
    pub context: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub expected_result: Option<bool>,
    pub reason: Option<String>,
}

/// Test suite statistics
#[derive(Debug, Default)]
pub struct TestSuiteStatistics {
    pub total_groups: usize,
    pub total_tests: usize,
    pub expected_pass: usize,
    pub expected_fail: usize,
    pub by_parameter_set: HashMap<String, usize>,
    pub by_test_type: HashMap<String, usize>,
}

impl Default for AcvpParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parser_creation() {
        let parser = AcvpParser::new();
        assert!(parser.get_parameter_set("ML-DSA-44").is_some());
        assert!(parser.get_parameter_set("ML-DSA-65").is_some());
        assert!(parser.get_parameter_set("ML-DSA-87").is_some());
        assert!(parser.get_parameter_set("Invalid").is_none());
    }
    
    #[test]
    fn test_parameter_set_validation() {
        let parser = AcvpParser::new();
        
        let ml_dsa_44 = parser.get_parameter_set("ML-DSA-44").unwrap();
        assert_eq!(ml_dsa_44.public_key_size, 1312);
        assert_eq!(ml_dsa_44.signature_size, 2420);
        assert_eq!(ml_dsa_44.security_level, 2);
        
        let ml_dsa_65 = parser.get_parameter_set("ML-DSA-65").unwrap();
        assert_eq!(ml_dsa_65.public_key_size, 1952);
        assert_eq!(ml_dsa_65.signature_size, 3309);
        assert_eq!(ml_dsa_65.security_level, 3);
        
        let ml_dsa_87 = parser.get_parameter_set("ML-DSA-87").unwrap();
        assert_eq!(ml_dsa_87.public_key_size, 2592);
        assert_eq!(ml_dsa_87.signature_size, 4627);
        assert_eq!(ml_dsa_87.security_level, 5);
    }
}