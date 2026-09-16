//! ACVP test suite validation utilities

use crate::{AcvpError, AcvpTestCase, AcvpTestGroup, AcvpTestSuite, Result};

/// Validator for ACVP test suites
///
/// Provides utilities for validating ACVP test structure and content
pub struct AcvpValidator;

impl AcvpValidator {
    /// Validate basic test suite structure
    pub fn validate_structure(suite: &AcvpTestSuite) -> Result<()> {
        // Check algorithm is not empty
        if suite.algorithm.is_empty() {
            return Err(AcvpError::InvalidTestSuite(
                "Algorithm name cannot be empty".to_string(),
            ));
        }

        // Check we have test groups
        if suite.test_groups.is_empty() {
            return Err(AcvpError::InvalidTestSuite(
                "Test suite must contain at least one test group".to_string(),
            ));
        }

        // Validate each group
        for group in &suite.test_groups {
            Self::validate_group_structure(group)?;
        }

        Ok(())
    }

    /// Validate test group structure
    pub fn validate_group_structure(group: &AcvpTestGroup) -> Result<()> {
        // Check test type is not empty
        if group.test_type.is_empty() {
            return Err(AcvpError::InvalidTestGroup(
                "Test type cannot be empty".to_string(),
            ));
        }

        // Check parameter set is not empty
        if group.parameter_set.is_empty() {
            return Err(AcvpError::InvalidTestGroup(
                "Parameter set cannot be empty".to_string(),
            ));
        }

        // Check we have tests
        if group.tests.is_empty() {
            return Err(AcvpError::InvalidTestGroup(
                "Test group must contain at least one test case".to_string(),
            ));
        }

        // Validate each test case
        for test in &group.tests {
            Self::validate_test_structure(test)?;
        }

        Ok(())
    }

    /// Validate test case structure
    pub fn validate_test_structure(test: &AcvpTestCase) -> Result<()> {
        // Check test has some fields
        if test.fields.is_empty() {
            return Err(AcvpError::InvalidTestCase(
                format!("Test case {} has no fields", test.tc_id),
            ));
        }

        Ok(())
    }

    /// Validate hex-encoded field
    pub fn validate_hex_field(test: &AcvpTestCase, field_name: &str) -> Result<Vec<u8>> {
        let hex_str = test.get_string(field_name).ok_or_else(|| {
            AcvpError::MissingField(field_name.to_string())
        })?;

        hex::decode(hex_str).map_err(|e| {
            AcvpError::invalid_field(
                field_name,
                format!("Invalid hex encoding: {}", e),
            )
        })
    }

    /// Validate field size
    pub fn validate_field_size(
        test: &AcvpTestCase,
        field_name: &str,
        expected_size: usize,
    ) -> Result<Vec<u8>> {
        let bytes = Self::validate_hex_field(test, field_name)?;

        if bytes.len() != expected_size {
            return Err(AcvpError::size_mismatch(
                field_name,
                expected_size,
                bytes.len(),
            ));
        }

        Ok(bytes)
    }

    /// Check if test suite has consistent parameter sets
    pub fn check_consistency(suite: &AcvpTestSuite) -> Vec<String> {
        let mut warnings = Vec::new();

        // Collect all parameter sets used
        let mut param_sets: Vec<String> = suite
            .test_groups
            .iter()
            .map(|g| g.parameter_set.clone())
            .collect();
        param_sets.sort();
        param_sets.dedup();

        // Collect all test types used
        let mut test_types: Vec<String> = suite
            .test_groups
            .iter()
            .map(|g| g.test_type.clone())
            .collect();
        test_types.sort();
        test_types.dedup();

        // Check for empty groups
        for group in &suite.test_groups {
            if group.tests.is_empty() {
                warnings.push(format!(
                    "Test group {} has no test cases",
                    group.tg_id
                ));
            }
        }

        // Check for duplicate test case IDs
        let mut test_ids = std::collections::HashSet::new();
        for group in &suite.test_groups {
            for test in &group.tests {
                if !test_ids.insert(test.tc_id) {
                    warnings.push(format!(
                        "Duplicate test case ID: {}",
                        test.tc_id
                    ));
                }
            }
        }

        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AcvpTestCase, AcvpTestGroup, types::FieldValue};
    

    #[test]
    fn test_validate_structure_empty_algorithm() {
        let mut suite = AcvpTestSuite::new("".to_string());
        suite.add_group(AcvpTestGroup::new(1, "test".to_string(), "param".to_string()));

        let result = AcvpValidator::validate_structure(&suite);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_structure_no_groups() {
        let suite = AcvpTestSuite::new("TestAlgo".to_string());
        let result = AcvpValidator::validate_structure(&suite);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hex_field() {
        let mut test = AcvpTestCase::new(1);
        test.fields.insert("data".to_string(), FieldValue::String("abcd".to_string()));

        let result = AcvpValidator::validate_hex_field(&test, "data");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xab, 0xcd]);
    }

    #[test]
    fn test_validate_hex_field_invalid() {
        let mut test = AcvpTestCase::new(1);
        test.fields.insert("data".to_string(), FieldValue::String("xyz".to_string()));

        let result = AcvpValidator::validate_hex_field(&test, "data");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_field_size() {
        let mut test = AcvpTestCase::new(1);
        test.fields.insert("data".to_string(), FieldValue::String("abcd".to_string()));

        let result = AcvpValidator::validate_field_size(&test, "data", 2);
        assert!(result.is_ok());

        let result = AcvpValidator::validate_field_size(&test, "data", 3);
        assert!(result.is_err());
    }
}
