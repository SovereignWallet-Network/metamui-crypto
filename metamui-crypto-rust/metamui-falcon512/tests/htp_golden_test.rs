//! Golden-vector integration test for hash_to_point_nist (Falcon-512).
//!
//! Loads cross-language golden test vectors from
//! `test-vectors/falcon/hash_to_point_falcon512_golden.json` (relative to the
//! workspace root) and verifies that the Rust `hash_to_point_nist` function
//! produces exactly the same 512-coefficient polynomial as the Python
//! reference generator for every vector.

use metamui_falcon512::nist_hash::hash_to_point_nist;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// JSON schema types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GoldenFile {
    algorithm: String,
    parameters: Parameters,
    vectors: Vec<TestVector>,
}

#[derive(Deserialize)]
struct Parameters {
    q: u32,
    n: usize,
    threshold: u32,
    byte_order: String,
}

#[derive(Deserialize)]
// `rejection_count` and `total_bytes_consumed` are serde-deserialized
// for schema parity with the generator but not yet asserted against;
// cargo can't see the serde reads.
#[allow(dead_code)]
struct TestVector {
    id: u32,
    #[serde(default)]
    description: String,
    nonce_hex: String,
    message_hex: String,
    c_polynomial: Vec<u32>,
    #[serde(default)]
    rejection_count: u64,
    #[serde(default)]
    total_bytes_consumed: u64,
}

// ---------------------------------------------------------------------------
// Helper: hex string -> Vec<u8>
// ---------------------------------------------------------------------------

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("invalid hex string: {e}"))
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// Embed the golden-vector JSON at compile time so the test binary is
/// self-contained and does not rely on the working directory at runtime.
const GOLDEN_JSON: &str =
    include_str!("../../../test-vectors/falcon/hash_to_point_falcon512_golden.json");

#[test]
fn test_hash_to_point_golden_vectors() {
    let golden: GoldenFile =
        serde_json::from_str(GOLDEN_JSON).expect("failed to parse golden JSON");

    // Sanity-check the file header
    assert_eq!(golden.algorithm, "falcon512_hash_to_point");
    assert_eq!(golden.parameters.q, 12289);
    assert_eq!(golden.parameters.n, 512);
    assert_eq!(golden.parameters.threshold, 61445);
    assert_eq!(golden.parameters.byte_order, "big-endian");

    let num_vectors = golden.vectors.len();
    if num_vectors == 0 {
        println!("No golden vectors found — skipping test");
        return;
    }

    let mut pass_count = 0u32;

    for v in &golden.vectors {
        let nonce = decode_hex(&v.nonce_hex);
        let message = decode_hex(&v.message_hex);

        let rust_poly: Vec<i16> = hash_to_point_nist(&nonce, &message);

        // The golden polynomial must have exactly 512 entries.
        assert_eq!(
            v.c_polynomial.len(),
            512,
            "vector {}: golden c_polynomial length is {} (expected 512)",
            v.id,
            v.c_polynomial.len()
        );
        assert_eq!(
            rust_poly.len(),
            512,
            "vector {}: Rust polynomial length is {} (expected 512)",
            v.id,
            rust_poly.len()
        );

        // Compare every coefficient.
        // Golden values are unsigned in [0, 12289). Since Q = 12289 < 32768,
        // every golden value fits in i16 without wrapping, so a plain cast
        // `golden_coeff as i16` is correct.
        let mut all_match = true;
        for i in 0..512 {
            let golden_coeff = v.c_polynomial[i] as i16;
            let rust_coeff = rust_poly[i];
            if golden_coeff != rust_coeff {
                eprintln!(
                    "  vector {} MISMATCH at index {}: golden={} rust={}",
                    v.id, i, v.c_polynomial[i], rust_coeff
                );
                all_match = false;
            }
        }

        if all_match {
            println!("vector {:>3}: PASS  (desc: {})", v.id, v.description);
            pass_count += 1;
        } else {
            println!("vector {:>3}: FAIL  (desc: {})", v.id, v.description);
        }

        // Hard assert so the test fails on first mismatched vector
        assert!(
            all_match,
            "vector {}: coefficient mismatch detected (see stderr above)",
            v.id
        );
    }

    println!(
        "\n=== hash_to_point golden test: {}/{} vectors passed ===",
        pass_count, num_vectors
    );
}
