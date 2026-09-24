//! Generate comprehensive ACVP-format test vectors for ML-DSA (Dilithium)
//!
//! This example uses the test_vector_generator_v2 module to create properly
//! formatted ACVP test vectors for all ML-DSA parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87).
//!
//! Usage:
//!   cargo run --example generate_ml_dsa_test_vectors > ml_dsa_acvp_vectors.json
//!   cargo run --example generate_ml_dsa_test_vectors 5 > ml_dsa_small_vectors.json

use metamui_dilithium::test_vector_generator_v2::{
    MlDsaTestVectorGenerator, TestVectorOptions,
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
            num_siggen_tests: num_tests,
            num_sigver_valid_tests: num_tests,
            num_sigver_invalid_tests: num_tests,
            include_edge_cases: true,
            deterministic_signing: true,
        }
    } else {
        // Default: comprehensive test suite
        TestVectorOptions {
            num_keygen_tests: 10,
            num_siggen_tests: 15,
            num_sigver_valid_tests: 10,
            num_sigver_invalid_tests: 10,
            include_edge_cases: true,
            deterministic_signing: true,
        }
    };

    // Create generator with deterministic seed
    let mut generator = MlDsaTestVectorGenerator::new();

    eprintln!("Generating ACVP test vectors for ML-DSA (FIPS 204)...");
    eprintln!("  - keyGen tests: {} per parameter set", options.num_keygen_tests);
    eprintln!("  - sigGen tests: {} per parameter set", options.num_siggen_tests);
    eprintln!("  - sigVer valid tests: {} per parameter set", options.num_sigver_valid_tests);
    eprintln!("  - sigVer invalid tests: {} per parameter set", options.num_sigver_invalid_tests);
    eprintln!("  - Parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87");
    eprintln!("  - Deterministic signing: {}", options.deterministic_signing);

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
