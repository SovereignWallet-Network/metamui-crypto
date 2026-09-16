//! Test suite statistics and analysis

use crate::AcvpTestSuite;
use std::collections::HashMap;

/// Statistics about an ACVP test suite
#[derive(Debug, Clone, Default)]
pub struct TestSuiteStatistics {
    /// Total number of test groups
    pub total_groups: usize,

    /// Total number of test cases across all groups
    pub total_tests: usize,

    /// Number of tests expected to pass
    pub expected_pass: usize,

    /// Number of tests expected to fail
    pub expected_fail: usize,

    /// Number of tests with no expected result
    pub no_expected_result: usize,

    /// Test count by parameter set
    pub by_parameter_set: HashMap<String, usize>,

    /// Test count by test type
    pub by_test_type: HashMap<String, usize>,

    /// Test count by test group
    pub by_group: HashMap<u32, usize>,
}

impl TestSuiteStatistics {
    /// Generate statistics from a test suite
    pub fn from_test_suite(suite: &AcvpTestSuite) -> Self {
        let mut stats = Self::default();

        stats.total_groups = suite.test_groups.len();

        for group in &suite.test_groups {
            let group_test_count = group.tests.len();
            stats.total_tests += group_test_count;

            // Count by parameter set
            *stats
                .by_parameter_set
                .entry(group.parameter_set.clone())
                .or_insert(0) += group_test_count;

            // Count by test type
            *stats.by_test_type.entry(group.test_type.clone()).or_insert(0) += group_test_count;

            // Count by group
            stats.by_group.insert(group.tg_id, group_test_count);

            // Analyze expected results
            for test in &group.tests {
                match test.get_expected_result() {
                    Some(true) => stats.expected_pass += 1,
                    Some(false) => stats.expected_fail += 1,
                    None => stats.no_expected_result += 1,
                }
            }
        }

        stats
    }

    /// Get coverage percentage for expected results
    pub fn expected_result_coverage(&self) -> f64 {
        if self.total_tests == 0 {
            return 0.0;
        }
        let with_results = self.expected_pass + self.expected_fail;
        (with_results as f64 / self.total_tests as f64) * 100.0
    }

    /// Get parameter sets sorted by test count (descending)
    pub fn parameter_sets_by_count(&self) -> Vec<(String, usize)> {
        let mut sets: Vec<_> = self.by_parameter_set.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        sets.sort_by(|a, b| b.1.cmp(&a.1));
        sets
    }

    /// Get test types sorted by count (descending)
    pub fn test_types_by_count(&self) -> Vec<(String, usize)> {
        let mut types: Vec<_> = self.by_test_type.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        types.sort_by(|a, b| b.1.cmp(&a.1));
        types
    }

    /// Generate a human-readable summary
    pub fn summary(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Test Suite Statistics\n"));
        s.push_str(&format!("=====================\n\n"));

        s.push_str(&format!("Overview:\n"));
        s.push_str(&format!("  Total Groups: {}\n", self.total_groups));
        s.push_str(&format!("  Total Tests: {}\n", self.total_tests));
        s.push_str(&format!("  Expected Pass: {}\n", self.expected_pass));
        s.push_str(&format!("  Expected Fail: {}\n", self.expected_fail));
        s.push_str(&format!("  No Expected Result: {}\n", self.no_expected_result));
        s.push_str(&format!(
            "  Result Coverage: {:.1}%\n\n",
            self.expected_result_coverage()
        ));

        s.push_str(&format!("By Parameter Set:\n"));
        for (param_set, count) in self.parameter_sets_by_count() {
            s.push_str(&format!("  {}: {} tests\n", param_set, count));
        }

        s.push_str(&format!("\nBy Test Type:\n"));
        for (test_type, count) in self.test_types_by_count() {
            s.push_str(&format!("  {}: {} tests\n", test_type, count));
        }

        s
    }

    /// Get average tests per group
    pub fn avg_tests_per_group(&self) -> f64 {
        if self.total_groups == 0 {
            return 0.0;
        }
        self.total_tests as f64 / self.total_groups as f64
    }

    /// Check if test suite has good coverage
    /// Returns (is_good, reasons)
    pub fn coverage_quality(&self) -> (bool, Vec<String>) {
        let mut issues = Vec::new();
        let mut is_good = true;

        // Check minimum test count
        if self.total_tests < 10 {
            is_good = false;
            issues.push(format!(
                "Low test count: {} tests (recommend 100+ per parameter set)",
                self.total_tests
            ));
        }

        // Check expected result coverage
        let coverage = self.expected_result_coverage();
        if coverage < 80.0 {
            is_good = false;
            issues.push(format!(
                "Low expected result coverage: {:.1}% (recommend 100%)",
                coverage
            ));
        }

        // Check parameter set coverage
        if self.by_parameter_set.is_empty() {
            is_good = false;
            issues.push("No parameter sets tested".to_string());
        }

        // Check test type diversity
        if self.by_test_type.len() < 2 {
            issues.push("Limited test type diversity (recommend testing multiple operations)".to_string());
        }

        (is_good, issues)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AcvpTestCase, AcvpTestGroup, AcvpTestSuite, types::FieldValue};

    fn create_test_suite() -> AcvpTestSuite {
        let mut suite = AcvpTestSuite::new("TestAlgo".to_string());

        // Group 1: keyGen for Param-1
        let mut group1 = AcvpTestGroup::new(1, "keyGen".to_string(), "Param-1".to_string());
        for i in 1..=5 {
            let mut test = AcvpTestCase::new(i);
            test.fields.insert("testPassed".to_string(), FieldValue::Bool(true));
            group1.add_test(test);
        }
        suite.add_group(group1);

        // Group 2: sigGen for Param-1
        let mut group2 = AcvpTestGroup::new(2, "sigGen".to_string(), "Param-1".to_string());
        for i in 6..=10 {
            let mut test = AcvpTestCase::new(i);
            test.fields.insert("testPassed".to_string(), FieldValue::Bool(true));
            group2.add_test(test);
        }
        suite.add_group(group2);

        // Group 3: keyGen for Param-2
        let mut group3 = AcvpTestGroup::new(3, "keyGen".to_string(), "Param-2".to_string());
        for i in 11..=13 {
            let test = AcvpTestCase::new(i);
            group3.add_test(test);
        }
        suite.add_group(group3);

        suite
    }

    #[test]
    fn test_statistics_generation() {
        let suite = create_test_suite();
        let stats = TestSuiteStatistics::from_test_suite(&suite);

        assert_eq!(stats.total_groups, 3);
        assert_eq!(stats.total_tests, 13);
        assert_eq!(stats.expected_pass, 10);
        assert_eq!(stats.expected_fail, 0);
        assert_eq!(stats.no_expected_result, 3);
    }

    #[test]
    fn test_parameter_set_counts() {
        let suite = create_test_suite();
        let stats = TestSuiteStatistics::from_test_suite(&suite);

        assert_eq!(stats.by_parameter_set.get("Param-1"), Some(&10));
        assert_eq!(stats.by_parameter_set.get("Param-2"), Some(&3));
    }

    #[test]
    fn test_test_type_counts() {
        let suite = create_test_suite();
        let stats = TestSuiteStatistics::from_test_suite(&suite);

        assert_eq!(stats.by_test_type.get("keyGen"), Some(&8));
        assert_eq!(stats.by_test_type.get("sigGen"), Some(&5));
    }

    #[test]
    fn test_expected_result_coverage() {
        let suite = create_test_suite();
        let stats = TestSuiteStatistics::from_test_suite(&suite);

        // 10 out of 13 tests have expected results
        let coverage = stats.expected_result_coverage();
        assert!((coverage - 76.92).abs() < 0.1);
    }

    #[test]
    fn test_avg_tests_per_group() {
        let suite = create_test_suite();
        let stats = TestSuiteStatistics::from_test_suite(&suite);

        let avg = stats.avg_tests_per_group();
        assert!((avg - 4.33).abs() < 0.1); // 13 tests / 3 groups ≈ 4.33
    }

    #[test]
    fn test_coverage_quality() {
        let suite = create_test_suite();
        let stats = TestSuiteStatistics::from_test_suite(&suite);

        let (is_good, issues) = stats.coverage_quality();
        assert!(!is_good); // Low test count
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_summary_generation() {
        let suite = create_test_suite();
        let stats = TestSuiteStatistics::from_test_suite(&suite);

        let summary = stats.summary();
        assert!(summary.contains("Total Groups: 3"));
        assert!(summary.contains("Total Tests: 13"));
        assert!(summary.contains("Param-1"));
        assert!(summary.contains("keyGen"));
    }
}
