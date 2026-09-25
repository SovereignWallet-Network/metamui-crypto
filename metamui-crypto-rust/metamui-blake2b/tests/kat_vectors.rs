// KAT vectors for BLAKE2b — RFC 7693 / BLAKE2 reference implementation
// Tests both BLAKE2b-256 (32-byte) and BLAKE2b-512 (64-byte) outputs

use serde::Deserialize;
use std::fs;

// -----------------------------------------------------------------------
// BLAKE2b-256 inline KAT vectors
// -----------------------------------------------------------------------

#[test]
fn blake2b256_kat() {
    let vectors: &[(&[u8], &str)] = &[
        (
            b"",
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
        ),
        (
            b"abc",
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
        ),
        (
            b"The quick brown fox jumps over the lazy dog",
            "01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9",
        ),
    ];
    for (i, (msg, expected_hex)) in vectors.iter().enumerate() {
        let got = metamui_blake2b::blake2b256(msg);
        let got_hex = hex::encode(got.as_ref());
        assert_eq!(
            got_hex, *expected_hex,
            "BLAKE2b-256 KAT failed at vector index {i}"
        );
    }
    println!("BLAKE2b-256: {} KAT vectors passed", vectors.len());
}

// -----------------------------------------------------------------------
// BLAKE2b-512 KAT vectors from JSON file
// -----------------------------------------------------------------------

#[derive(Deserialize)]
struct TestCase {
    tc_id: u32,
    input_hex: String,
    key: Option<String>,
    digest: String,
}

#[derive(Deserialize)]
struct Blake2bSection {
    test_vectors: Vec<TestCase>,
}

#[derive(Deserialize)]
struct VectorFile {
    blake2b: Blake2bSection,
}

#[test]
fn blake2b512_kat_rfc7693() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/blake2/rfc7693-vectors.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28):
    // the vectors are tracked in this repo, so this test FAILS instead of
    // returning green having verified nothing.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();
    let mut count = 0;
    for tv in &file.blake2b.test_vectors {
        if tv.key.is_some() {
            continue; // skip keyed vectors (unkeyed only)
        }
        let msg = hex::decode(&tv.input_hex).unwrap();
        let expected = hex::decode(&tv.digest).unwrap();
        let got = metamui_blake2b::blake2b_512(&msg);
        assert_eq!(
            got.as_ref(),
            expected.as_slice(),
            "BLAKE2b-512 KAT failed at tc_id={}",
            tv.tc_id
        );
        count += 1;
    }
    println!("BLAKE2b-512: {count} RFC 7693 KAT vectors passed");
    assert!(count >= 1, "expected at least 1 vector");
}
