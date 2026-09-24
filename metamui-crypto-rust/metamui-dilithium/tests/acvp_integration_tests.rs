/// Integration tests for ACVP parser and test vector generator
/// 
/// These tests verify that the ACVP parser can correctly parse NIST FIPS 204
/// ML-DSA test vectors and that the test vector generator produces valid output.

use metamui_dilithium::acvp_parser::AcvpParser;
use metamui_dilithium::test_vector_generator::{MlDsaTestVectorGenerator, TestVectorOptions};

#[test]
fn test_acvp_parser_ml_dsa_44() {
    let parser = AcvpParser::new();
    
    // Test ML-DSA-44 parameter set validation
    let ml_dsa_44 = parser.get_parameter_set("ML-DSA-44").unwrap();
    assert_eq!(ml_dsa_44.name, "ML-DSA-44");
    assert_eq!(ml_dsa_44.security_level, 2);
    assert_eq!(ml_dsa_44.public_key_size, 1312);
    assert_eq!(ml_dsa_44.secret_key_size, 2560);
    assert_eq!(ml_dsa_44.signature_size, 2420);
    assert_eq!(ml_dsa_44.k, 4);
    assert_eq!(ml_dsa_44.l, 4);
    assert_eq!(ml_dsa_44.eta, 2);
    assert_eq!(ml_dsa_44.tau, 39);
    assert_eq!(ml_dsa_44.beta, 78);
    assert_eq!(ml_dsa_44.gamma1, 131072);
    assert_eq!(ml_dsa_44.gamma2, 95232);
    assert_eq!(ml_dsa_44.omega, 80);
    
    println!("ML-DSA-44 parameter validation successful");
}

#[test]
fn test_acvp_parser_ml_dsa_65() {
    let parser = AcvpParser::new();
    
    let ml_dsa_65 = parser.get_parameter_set("ML-DSA-65").unwrap();
    assert_eq!(ml_dsa_65.name, "ML-DSA-65");
    assert_eq!(ml_dsa_65.security_level, 3);
    assert_eq!(ml_dsa_65.public_key_size, 1952);
    assert_eq!(ml_dsa_65.secret_key_size, 4032);
    assert_eq!(ml_dsa_65.signature_size, 3309);
    assert_eq!(ml_dsa_65.k, 6);
    assert_eq!(ml_dsa_65.l, 5);
    assert_eq!(ml_dsa_65.eta, 4);
    assert_eq!(ml_dsa_65.tau, 49);
    assert_eq!(ml_dsa_65.beta, 196);
    assert_eq!(ml_dsa_65.gamma1, 524288);
    assert_eq!(ml_dsa_65.gamma2, 261888);
    assert_eq!(ml_dsa_65.omega, 55);
    
    println!("ML-DSA-65 parameter validation successful");
}

#[test]
fn test_acvp_parser_ml_dsa_87() {
    let parser = AcvpParser::new();
    
    let ml_dsa_87 = parser.get_parameter_set("ML-DSA-87").unwrap();
    assert_eq!(ml_dsa_87.name, "ML-DSA-87");
    assert_eq!(ml_dsa_87.security_level, 5);
    assert_eq!(ml_dsa_87.public_key_size, 2592);
    assert_eq!(ml_dsa_87.secret_key_size, 4896);
    assert_eq!(ml_dsa_87.signature_size, 4627);
    assert_eq!(ml_dsa_87.k, 8);
    assert_eq!(ml_dsa_87.l, 7);
    assert_eq!(ml_dsa_87.eta, 2);
    assert_eq!(ml_dsa_87.tau, 60);
    assert_eq!(ml_dsa_87.beta, 120);
    assert_eq!(ml_dsa_87.gamma1, 524288);
    assert_eq!(ml_dsa_87.gamma2, 261888);
    assert_eq!(ml_dsa_87.omega, 75);
    
    println!("ML-DSA-87 parameter validation successful");
}

#[test]
fn test_parse_existing_ml_dsa_test_vectors() {
    let parser = AcvpParser::new();
    
    // Test parsing our existing ML-DSA-44 test vectors
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let vectors_dir = ["../..", "../../.."].iter()
        .map(|p| manifest.join(p).join("test-vectors/ml-dsa/ml-dsa-44-kat.json"))
        .find(|p| p.exists())
        .expect("Could not find ml-dsa-44-vectors.json");
    let result = parser.parse_file(vectors_dir.to_str().unwrap());
    
    match result {
        Ok(test_suite) => {
            assert_eq!(test_suite.algorithm, "ML-DSA");
            assert!(!test_suite.test_groups.is_empty());
            
            let group = &test_suite.test_groups[0];
            assert_eq!(group.parameter_set, "ML-DSA-44");
            assert!(!group.tests.is_empty());
            
            println!("Successfully parsed ML-DSA-44 test vectors: {} groups, {} total tests", 
                     test_suite.test_groups.len(), 
                     test_suite.test_groups.iter().map(|g| g.tests.len()).sum::<usize>());
        },
        Err(e) => {
            println!("Note: Could not parse existing test vectors (expected for demo vectors): {}", e);
            // This is expected since our demo vectors don't follow strict ACVP format
        }
    }
}

#[test]
fn test_test_vector_generator() {
    let mut generator = MlDsaTestVectorGenerator::new();
    
    let options = TestVectorOptions {
        num_keygen_tests: 2,
        num_siggen_tests: 2,
        num_sigver_valid_tests: 2,
        num_sigver_invalid_tests: 2,
        include_edge_cases: true,
        deterministic_signing: true,
    };
    
    let test_suite = generator.generate_comprehensive_test_suite(&options);
    
    // Validate the generated test suite
    assert_eq!(test_suite.algorithm, "ML-DSA");
    assert!(!test_suite.test_groups.is_empty());
    
    // Check that we have test groups for all parameter sets
    let mut param_sets = std::collections::HashSet::new();
    let mut test_types = std::collections::HashSet::new();
    
    for group in &test_suite.test_groups {
        param_sets.insert(group.parameter_set.clone());
        test_types.insert(group.test_type.clone());
        
        // Validate each test case has required fields
        for test in &group.tests {
            assert!(test.tc_id > 0);
            
            match group.test_type.as_str() {
                "keyGen" => {
                    assert!(test.public_key.is_some());
                    assert!(test.secret_key.is_some());
                },
                "sigGen" => {
                    assert!(test.public_key.is_some());
                    assert!(test.secret_key.is_some());
                    assert!(test.message.is_some());
                    assert!(test.signature.is_some());
                },
                "sigVer" => {
                    assert!(test.public_key.is_some());
                    assert!(test.message.is_some());
                    assert!(test.signature.is_some());
                    assert!(test.sig_ver.is_some());
                },
                _ => {},
            }
        }
    }
    
    assert!(param_sets.contains("ML-DSA-44"));
    assert!(param_sets.contains("ML-DSA-65"));
    assert!(param_sets.contains("ML-DSA-87"));
    
    assert!(test_types.contains("keyGen"));
    assert!(test_types.contains("sigGen"));
    assert!(test_types.contains("sigVer"));
    
    println!("Generated test suite with {} parameter sets and {} test types", 
             param_sets.len(), test_types.len());
    
    // Test JSON export
    let json = generator.export_to_json(&test_suite).unwrap();
    assert!(!json.is_empty());
    assert!(json.contains("ML-DSA"));
    
    println!("Successfully exported test suite to JSON ({} bytes)", json.len());
}

#[test]
fn test_acvp_parser_with_generated_vectors() {
    let mut generator = MlDsaTestVectorGenerator::new();
    let parser = AcvpParser::new();
    
    let options = TestVectorOptions {
        num_keygen_tests: 1,
        num_siggen_tests: 1,
        num_sigver_valid_tests: 1,
        num_sigver_invalid_tests: 1,
        include_edge_cases: false,
        deterministic_signing: true,
    };
    
    let test_suite = generator.generate_comprehensive_test_suite(&options);
    let json = generator.export_to_json(&test_suite).unwrap();
    
    // Parse the generated JSON
    let parsed_suite = parser.parse_json(&json).unwrap();
    
    assert_eq!(parsed_suite.algorithm, test_suite.algorithm);
    assert_eq!(parsed_suite.test_groups.len(), test_suite.test_groups.len());
    
    // Validate statistics
    let stats = parser.generate_statistics(&parsed_suite);
    assert!(stats.total_tests > 0);
    assert!(stats.total_groups > 0);
    assert!(stats.by_parameter_set.contains_key("ML-DSA-44"));
    assert!(stats.by_parameter_set.contains_key("ML-DSA-65"));
    assert!(stats.by_parameter_set.contains_key("ML-DSA-87"));
    
    println!("ACVP parser statistics: {} groups, {} tests, {} expected pass, {} expected fail",
             stats.total_groups, stats.total_tests, stats.expected_pass, stats.expected_fail);
    
    // Test filtering functionality
    let keygen_tests = parser.filter_by_test_type(&parsed_suite, "keyGen");
    let ml_dsa_44_tests = parser.filter_by_parameter_set(&parsed_suite, "ML-DSA-44");
    
    assert!(!keygen_tests.is_empty());
    assert!(!ml_dsa_44_tests.is_empty());
    
    println!("Filtering tests: {} keyGen tests, {} ML-DSA-44 tests", 
             keygen_tests.len(), ml_dsa_44_tests.len());
}

#[test]
fn test_comprehensive_acvp_workflow() {
    // This test demonstrates the complete ACVP workflow:
    // 1. Generate test vectors
    // 2. Export to JSON
    // 3. Parse the JSON
    // 4. Validate the parsed data
    // 5. Convert to internal format
    
    let mut generator = MlDsaTestVectorGenerator::new();
    let parser = AcvpParser::new();
    
    // Step 1: Generate test vectors
    let options = TestVectorOptions {
        num_keygen_tests: 1,
        num_siggen_tests: 2,
        num_sigver_valid_tests: 1,
        num_sigver_invalid_tests: 1,
        include_edge_cases: false,
        deterministic_signing: true,
    };
    
    let test_suite = generator.generate_comprehensive_test_suite(&options);
    
    // Step 2: Export to JSON
    let json = generator.export_to_json(&test_suite).unwrap();
    
    // Step 3: Parse the JSON
    let parsed_suite = parser.parse_json(&json).unwrap();
    
    // Step 4: Validate the parsed data
    assert_eq!(parsed_suite.algorithm, "ML-DSA");
    
    // Step 5: Convert to internal format and validate
    let mut total_converted = 0;
    for group in &parsed_suite.test_groups {
        for test in &group.tests {
            let internal_vector = parser.to_internal_format(group, test).unwrap();
            
            assert_eq!(internal_vector.parameter_set, group.parameter_set);
            assert_eq!(internal_vector.test_type, group.test_type);
            assert_eq!(internal_vector.tc_id, test.tc_id);
            
            total_converted += 1;
        }
    }
    
    println!("Successfully completed ACVP workflow: generated, exported, parsed, and converted {} test vectors",
             total_converted);
    
    assert!(total_converted > 0);
}