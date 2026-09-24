//! Generate comprehensive ACVP-format test vectors for SLH-DSA (Stateless Hash-based Digital Signature Algorithm)
//!
//! This example uses the test_vector_generator module to create properly
//! formatted ACVP test vectors for all SLH-DSA parameter sets (FIPS 205).
//!
//! Usage:
//!   cargo run --example generate_slh_dsa_test_vectors > slh_dsa_acvp_vectors.json
//!   cargo run --example generate_slh_dsa_test_vectors 5 > slh_dsa_small_vectors.json

use metamui_slhdsa::test_vector_generator::{
    SlhDsaTestVectorGenerator, TestVectorOptions,
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
            num_sigver_valid: num_tests,
            num_sigver_invalid: num_tests,
            include_edge_cases: true,
        }
    } else {
        // Default: comprehensive test suite
        TestVectorOptions {
            num_keygen_tests: 10,
            num_siggen_tests: 15,
            num_sigver_valid: 10,
            num_sigver_invalid: 10,
            include_edge_cases: true,
        }
    };

    // Create generator with deterministic seed
    let mut generator = SlhDsaTestVectorGenerator::new();

    eprintln!("Generating ACVP test vectors for SLH-DSA (FIPS 205)...");
    eprintln!("  - keyGen tests: {} per parameter set", options.num_keygen_tests);
    eprintln!("  - sigGen tests: {} per parameter set", options.num_siggen_tests);
    eprintln!("  - sigVer valid tests: {} per parameter set", options.num_sigver_valid);
    eprintln!("  - sigVer invalid tests: {} per parameter set", options.num_sigver_invalid);
    eprintln!("  - Parameter sets: SLH-DSA-128s, SLH-DSA-128f, SLH-DSA-192s, SLH-DSA-192f, SLH-DSA-256s, SLH-DSA-256f");
    eprintln!("  - Hash function: SHAKE256");

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
