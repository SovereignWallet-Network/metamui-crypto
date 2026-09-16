//! Core ACVP data structures
//!
//! This module defines the hierarchical ACVP test structure:
//! - `AcvpTestSuite`: Top-level container (Vector Set)
//! - `AcvpTestGroup`: Group of tests with common parameters
//! - `AcvpTestCase`: Individual test vector

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Flexible value type for algorithm-specific fields
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FieldValue {
    /// String value (hex-encoded data, parameter names, etc.)
    String(String),
    /// Boolean value (test passed/failed, flags, etc.)
    Bool(bool),
    /// Integer value (IDs, counters, sizes, etc.)
    Integer(i64),
    /// Unsigned integer value
    Unsigned(u64),
    /// Nested object
    Object(HashMap<String, FieldValue>),
    /// Array of values
    Array(Vec<FieldValue>),
    /// Null value
    Null,
}

impl FieldValue {
    /// Try to extract as string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Try to extract as bool
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            FieldValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Try to extract as integer
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            FieldValue::Integer(i) => Some(*i),
            FieldValue::Unsigned(u) => Some(*u as i64),
            _ => None,
        }
    }

    /// Try to extract as unsigned integer
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            FieldValue::Unsigned(u) => Some(*u),
            FieldValue::Integer(i) if *i >= 0 => Some(*i as u64),
            _ => None,
        }
    }
}

/// ACVP Test Suite (Vector Set)
///
/// Top-level container for test vectors following NIST ACVP format.
/// Contains metadata and multiple test groups.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcvpTestSuite {
    /// Vector Set ID (optional)
    #[serde(rename = "vsId", skip_serializing_if = "Option::is_none")]
    pub vs_id: Option<u32>,

    /// Algorithm name (e.g., "ML-KEM", "ML-DSA", "SLH-DSA")
    pub algorithm: String,

    /// Operation mode (e.g., "keyGen", "sigGen", "encapDecap")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// Standard revision (e.g., "FIPS203", "FIPS204", "FIPS205")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,

    /// Whether this is a sample test suite
    #[serde(rename = "isSample", skip_serializing_if = "Option::is_none")]
    pub is_sample: Option<bool>,

    /// Test groups with common parameters
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<AcvpTestGroup>,

    /// Additional algorithm-specific metadata
    #[serde(flatten)]
    pub metadata: HashMap<String, FieldValue>,
}

/// ACVP Test Group
///
/// Group of test cases sharing common parameters (e.g., same parameter set,
/// same test type). Reduces redundancy in test vector files.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcvpTestGroup {
    /// Test Group ID
    #[serde(rename = "tgId")]
    pub tg_id: u32,

    /// Test type (e.g., "AFT", "keyGen", "sigGen", "sigVer", "encapGen", "decap")
    #[serde(rename = "testType")]
    pub test_type: String,

    /// Parameter set name (e.g., "ML-DSA-44", "ML-KEM-768", "SLH-DSA-128s")
    #[serde(rename = "parameterSet")]
    pub parameter_set: String,

    /// Individual test cases in this group
    pub tests: Vec<AcvpTestCase>,

    /// Algorithm-specific group parameters
    #[serde(flatten)]
    pub parameters: HashMap<String, FieldValue>,
}

/// ACVP Test Case
///
/// Individual test vector with inputs and expected outputs.
/// Uses flexible HashMap for algorithm-specific fields.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcvpTestCase {
    /// Test Case ID
    #[serde(rename = "tcId")]
    pub tc_id: u32,

    /// All test fields (algorithm-specific)
    #[serde(flatten)]
    pub fields: HashMap<String, FieldValue>,
}

impl AcvpTestCase {
    /// Get field as hex-decoded bytes
    pub fn get_bytes(&self, field: &str) -> Option<Vec<u8>> {
        self.fields
            .get(field)
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok())
    }

    /// Get field as string
    pub fn get_string(&self, field: &str) -> Option<&str> {
        self.fields.get(field).and_then(|v| v.as_str())
    }

    /// Get field as boolean
    pub fn get_bool(&self, field: &str) -> Option<bool> {
        self.fields.get(field).and_then(|v| v.as_bool())
    }

    /// Get field as integer
    pub fn get_i64(&self, field: &str) -> Option<i64> {
        self.fields.get(field).and_then(|v| v.as_i64())
    }

    /// Get field as unsigned integer
    pub fn get_u64(&self, field: &str) -> Option<u64> {
        self.fields.get(field).and_then(|v| v.as_u64())
    }

    /// Check if field exists
    pub fn has_field(&self, field: &str) -> bool {
        self.fields.contains_key(field)
    }

    /// Get expected test result (pass/fail)
    /// Looks for common result field names
    pub fn get_expected_result(&self) -> Option<bool> {
        self.get_bool("testPassed")
            .or_else(|| self.get_bool("sigVer"))
            .or_else(|| self.get_bool("result"))
    }
}

impl AcvpTestSuite {
    /// Create a new test suite
    pub fn new(algorithm: String) -> Self {
        Self {
            vs_id: None,
            algorithm,
            mode: None,
            revision: None,
            is_sample: None,
            test_groups: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a test group
    pub fn add_group(&mut self, group: AcvpTestGroup) {
        self.test_groups.push(group);
    }

    /// Get all test cases (flat iterator)
    pub fn all_test_cases(&self) -> impl Iterator<Item = (&AcvpTestGroup, &AcvpTestCase)> {
        self.test_groups
            .iter()
            .flat_map(|group| group.tests.iter().map(move |test| (group, test)))
    }

    /// Filter test cases by test type
    pub fn filter_by_test_type(&self, test_type: &str) -> Vec<(&AcvpTestGroup, &AcvpTestCase)> {
        self.test_groups
            .iter()
            .filter(|group| group.test_type == test_type)
            .flat_map(|group| group.tests.iter().map(move |test| (group, test)))
            .collect()
    }

    /// Filter test cases by parameter set
    pub fn filter_by_parameter_set(&self, param_set: &str) -> Vec<(&AcvpTestGroup, &AcvpTestCase)> {
        self.test_groups
            .iter()
            .filter(|group| group.parameter_set == param_set)
            .flat_map(|group| group.tests.iter().map(move |test| (group, test)))
            .collect()
    }

    /// Count total test cases
    pub fn total_tests(&self) -> usize {
        self.test_groups.iter().map(|g| g.tests.len()).sum()
    }
}

impl AcvpTestGroup {
    /// Create a new test group
    pub fn new(tg_id: u32, test_type: String, parameter_set: String) -> Self {
        Self {
            tg_id,
            test_type,
            parameter_set,
            tests: Vec::new(),
            parameters: HashMap::new(),
        }
    }

    /// Add a test case
    pub fn add_test(&mut self, test: AcvpTestCase) {
        self.tests.push(test);
    }

    /// Get group parameter as string
    pub fn get_param_string(&self, param: &str) -> Option<&str> {
        self.parameters.get(param).and_then(|v| v.as_str())
    }

    /// Get group parameter as boolean
    pub fn get_param_bool(&self, param: &str) -> Option<bool> {
        self.parameters.get(param).and_then(|v| v.as_bool())
    }
}

impl AcvpTestCase {
    /// Create a new test case
    pub fn new(tc_id: u32) -> Self {
        Self {
            tc_id,
            fields: HashMap::new(),
        }
    }

    /// Add a field (builder pattern)
    pub fn with_field(mut self, key: String, value: FieldValue) -> Self {
        self.fields.insert(key, value);
        self
    }

    /// Add hex-encoded bytes field
    pub fn with_hex_field(mut self, key: String, bytes: &[u8]) -> Self {
        self.fields.insert(key, FieldValue::String(hex::encode(bytes)));
        self
    }

    /// Add boolean field
    pub fn with_bool_field(mut self, key: String, value: bool) -> Self {
        self.fields.insert(key, FieldValue::Bool(value));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_value_extraction() {
        let string_val = FieldValue::String("test".to_string());
        assert_eq!(string_val.as_str(), Some("test"));

        let bool_val = FieldValue::Bool(true);
        assert_eq!(bool_val.as_bool(), Some(true));

        let int_val = FieldValue::Integer(42);
        assert_eq!(int_val.as_i64(), Some(42));
    }

    #[test]
    fn test_test_case_helpers() {
        let mut test = AcvpTestCase::new(1);
        test.fields.insert("pk".to_string(), FieldValue::String("abcd".to_string()));
        test.fields.insert("testPassed".to_string(), FieldValue::Bool(true));

        assert_eq!(test.get_string("pk"), Some("abcd"));
        assert_eq!(test.get_expected_result(), Some(true));
        assert!(test.has_field("pk"));
        assert!(!test.has_field("missing"));
    }

    #[test]
    fn test_test_suite_operations() {
        let mut suite = AcvpTestSuite::new("ML-KEM".to_string());
        let mut group = AcvpTestGroup::new(1, "keyGen".to_string(), "ML-KEM-768".to_string());
        group.add_test(AcvpTestCase::new(1));
        group.add_test(AcvpTestCase::new(2));
        suite.add_group(group);

        assert_eq!(suite.total_tests(), 2);
        assert_eq!(suite.filter_by_test_type("keyGen").len(), 2);
        assert_eq!(suite.filter_by_parameter_set("ML-KEM-768").len(), 2);
    }
}
