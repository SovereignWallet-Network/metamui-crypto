// BLAKE2b block-boundary/keyed conformance gate.
//
// Source: test-vectors/blake2/blake2-boundary-vectors.json (generated from
// CPython hashlib, RFC 7693). Input = bytes(range(256)) cycled to `length`.
// Pins the verified-correct implementation against the eager-compression
// bug class found in sibling bindings by the 2026-06 BLAKE audit.
//
// PANICS (never skips) if the vector file is missing.
use serde::Deserialize;
use std::fs;

use metamui_blake2b::{blake2b_variable, blake2b_variable_keyed, Blake2bHasher};

#[derive(Deserialize)]
struct Case {
    length: usize,
    key: String,
    digest_size: usize,
    expected: String,
}

#[derive(Deserialize)]
struct VectorFile {
    blake2b: Vec<Case>,
}

fn make_input(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

#[test]
fn blake2b_boundary_kat() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/blake2/blake2-boundary-vectors.json"
    );
    let data = fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("blake2 boundary vector file missing ({path}): {e}")
    });
    let file: VectorFile = serde_json::from_str(&data).expect("malformed vector JSON");
    assert!(file.blake2b.len() >= 15, "unexpectedly few blake2b cases");

    for case in &file.blake2b {
        let input = make_input(case.length);
        let expected = hex::decode(&case.expected).unwrap();

        let got = if case.key.is_empty() {
            blake2b_variable(&input, case.digest_size)
        } else {
            let key = hex::decode(&case.key).unwrap();
            blake2b_variable_keyed(&key, &input, case.digest_size)
        };
        assert_eq!(got, expected,
                   "blake2b mismatch at length={} keylen={}",
                   case.length, case.key.len() / 2);

        // Streamed equivalent with BLOCK-ALIGNED 128-byte update pieces —
        // the exact pattern the eager-compression bug corrupted (the
        // keyed-empty case is its purest form: the padded key block IS
        // the final block).
        if case.key.is_empty() && !input.is_empty() {
            let mut hasher = Blake2bHasher::new_with_output_size(case.digest_size);
            for piece in input.chunks(128) {
                hasher.update(piece);
            }
            assert_eq!(hasher.finalize_variable(), expected,
                       "blake2b streamed mismatch at length={}", case.length);
        }
    }
    println!("BLAKE2b boundary gate: {} cases passed", file.blake2b.len());
}
