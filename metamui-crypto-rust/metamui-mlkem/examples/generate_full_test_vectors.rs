//! Generate comprehensive ACVP-format test vectors for ML-KEM
//!
//! This example uses the test_vector_generator module to create properly
//! formatted ACVP test vectors for all ML-KEM parameter sets (512, 768, 1024).
//!
//! Usage:
//!   cargo run --example generate_full_test_vectors --features std > mlkem_acvp_vectors.json

use metamui_mlkem::test_vector_generator::{
    MlKemTestVectorGenerator, TestVectorOptions,
};
use std::env;

fn main() {
    // Parse command line arguments for customization
    let args: Vec<String> = env::args().collect();

    let options = if args.len() > 1 {
        // Custom options from command line
        let num_tests = args.get(1)
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(10);

        TestVectorOptions {
            num_keygen_tests: num_tests,
            num_encap_tests: num_tests,
            num_decap_tests: num_tests,
            include_edge_cases: false,
        }
    } else {
        // Default: 10 tests per type
        TestVectorOptions {
            num_keygen_tests: 10,
            num_encap_tests: 10,
            num_decap_tests: 10,
            include_edge_cases: false,
        }
    };

    // Create generator with deterministic seed
    let mut generator = MlKemTestVectorGenerator::new();

    eprintln!("Generating ACVP test vectors for ML-KEM...");
    eprintln!("  - keyGen tests: {} per parameter set", options.num_keygen_tests);
    eprintln!("  - encapGen tests: {} per parameter set", options.num_encap_tests);
    eprintln!("  - decap tests: {} per parameter set", options.num_decap_tests);
    eprintln!("  - Parameter sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024");

    // Generate comprehensive test suite
    let test_suite = generator.generate_comprehensive_test_suite(&options);

    // Export to ACVP JSON format
    let json_output = generator.export_to_json(&test_suite);

    eprintln!("\nGeneration complete!");
    eprintln!("Total test groups: {}", test_suite.test_groups.len());
    eprintln!("Algorithm: {}", test_suite.algorithm);
    eprintln!("Revision: {}", test_suite.revision.as_ref().unwrap_or(&"N/A".to_string()));

    // Output JSON to stdout
    println!("{}", json_output);
}
