//! Generic ACVP parser implementation

use crate::{
    traits::{AcvpCompatible, ParameterSet},
    AcvpError, AcvpTestCase, AcvpTestGroup, AcvpTestSuite, Result,
};
use std::collections::HashMap;
use std::fs;
use std::marker::PhantomData;
use std::path::Path;

/// Generic ACVP parser for any algorithm implementing AcvpCompatible
pub struct AcvpParser<T: AcvpCompatible> {
    /// Parameter sets for this algorithm
    parameter_sets: HashMap<String, T::ParameterSet>,
    /// Phantom data for type parameter
    _phantom: PhantomData<T>,
}

impl<T: AcvpCompatible> AcvpParser<T> {
    /// Create a new ACVP parser
    ///
    /// Initializes with all supported parameter sets for the algorithm
    pub fn new() -> Self {
        let mut parameter_sets = HashMap::new();
        for param_set in T::supported_parameter_sets() {
            parameter_sets.insert(param_set.name().to_string(), param_set);
        }

        Self {
            parameter_sets,
            _phantom: PhantomData,
        }
    }

    /// Parse ACVP test suite from JSON file
    pub fn parse_file<P: AsRef<Path>>(&self, path: P) -> Result<AcvpTestSuite> {
        let content = fs::read_to_string(path)?;
        self.parse_json(&content)
    }

    /// Parse ACVP test suite from JSON string
    pub fn parse_json(&self, json: &str) -> Result<AcvpTestSuite> {
        let test_suite: AcvpTestSuite = serde_json::from_str(json)?;
        self.validate_test_suite(&test_suite)?;
        Ok(test_suite)
    }

    /// Validate test suite structure and parameters
    fn validate_test_suite(&self, test_suite: &AcvpTestSuite) -> Result<()> {
        // Validate algorithm name
        if test_suite.algorithm != T::ALGORITHM_NAME {
            return Err(AcvpError::UnsupportedAlgorithm(
                test_suite.algorithm.clone(),
            ));
        }

        // Validate test groups
        for group in &test_suite.test_groups {
            self.validate_test_group(group)?;
        }

        Ok(())
    }

    /// Validate individual test group
    fn validate_test_group(&self, group: &AcvpTestGroup) -> Result<()> {
        // Validate parameter set
        let param_set = self
            .parameter_sets
            .get(&group.parameter_set)
            .ok_or_else(|| AcvpError::UnknownParameterSet(group.parameter_set.clone()))?;

        // Validate test type
        let supported_types = T::supported_test_types();
        if !supported_types.contains(&group.test_type.as_str()) {
            return Err(AcvpError::UnsupportedTestType(group.test_type.clone()));
        }

        // Validate test cases
        for test in &group.tests {
            self.validate_test_case(test, group, param_set)?;
        }

        Ok(())
    }

    /// Validate individual test case
    fn validate_test_case(
        &self,
        _test: &AcvpTestCase,
        _group: &AcvpTestGroup,
        _param_set: &T::ParameterSet,
    ) -> Result<()> {
        // Note: Algorithm-specific validation can be implemented by users
        // by calling trait methods directly on their algorithm instance
        // The default trait implementations return Ok(())
        Ok(())
    }

    /// Get parameter set by name
    pub fn get_parameter_set(&self, name: &str) -> Option<&T::ParameterSet> {
        self.parameter_sets.get(name)
    }

    /// Get all parameter sets
    pub fn parameter_sets(&self) -> impl Iterator<Item = &T::ParameterSet> {
        self.parameter_sets.values()
    }

    /// Filter test cases by test type
    pub fn filter_by_test_type<'a>(
        &self,
        test_suite: &'a AcvpTestSuite,
        test_type: &str,
    ) -> Vec<(&'a AcvpTestGroup, &'a AcvpTestCase)> {
        test_suite.filter_by_test_type(test_type)
    }

    /// Filter test cases by parameter set
    pub fn filter_by_parameter_set<'a>(
        &self,
        test_suite: &'a AcvpTestSuite,
        param_set: &str,
    ) -> Vec<(&'a AcvpTestGroup, &'a AcvpTestCase)> {
        test_suite.filter_by_parameter_set(param_set)
    }
}

impl<T: AcvpCompatible> Default for AcvpParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ParameterSet;
    

    // Mock types for testing
    #[derive(Clone, Debug)]
    struct MockParam {
        name: String,
    }

    impl ParameterSet for MockParam {
        fn name(&self) -> &str {
            &self.name
        }
        fn security_level(&self) -> u8 {
            3
        }
        fn public_key_size(&self) -> usize {
            100
        }
        fn secret_key_size(&self) -> usize {
            200
        }
    }

    struct MockAlgorithm;

    impl AcvpCompatible for MockAlgorithm {
        type ParameterSet = MockParam;
        const ALGORITHM_NAME: &'static str = "MockAlgo";

        fn parse_parameter_set(name: &str) -> Result<Self::ParameterSet> {
            Ok(MockParam {
                name: name.to_string(),
            })
        }

        fn supported_parameter_sets() -> Vec<Self::ParameterSet> {
            vec![
                MockParam {
                    name: "Mock-1".to_string(),
                },
                MockParam {
                    name: "Mock-2".to_string(),
                },
            ]
        }

        fn supported_test_types() -> Vec<&'static str> {
            vec!["keyGen", "test"]
        }
    }

    #[test]
    fn test_parser_creation() {
        let parser = AcvpParser::<MockAlgorithm>::new();
        assert!(parser.get_parameter_set("Mock-1").is_some());
        assert!(parser.get_parameter_set("Mock-2").is_some());
        assert!(parser.get_parameter_set("Invalid").is_none());
    }

    #[test]
    fn test_parameter_set_iteration() {
        let parser = AcvpParser::<MockAlgorithm>::new();
        let count = parser.parameter_sets().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_parse_json_basic() {
        let json = r#"{
            "algorithm": "MockAlgo",
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "keyGen",
                    "parameterSet": "Mock-1",
                    "tests": []
                }
            ]
        }"#;

        let parser = AcvpParser::<MockAlgorithm>::new();
        let result = parser.parse_json(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_json_wrong_algorithm() {
        let json = r#"{
            "algorithm": "WrongAlgo",
            "testGroups": []
        }"#;

        let parser = AcvpParser::<MockAlgorithm>::new();
        let result = parser.parse_json(json);
        assert!(result.is_err());
    }
}
