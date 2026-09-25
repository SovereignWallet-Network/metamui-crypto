// KAT vectors for FlatHash -- MetaMUI internal
// Source: test-vectors/flathash/flathash-reference-vectors.json
use metamui_flathash::flat_hash_hex;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct TestCase {
    tc_id: u32,
    input: String,
    hash: String, // 0x-prefixed hex
}

#[derive(Deserialize)]
struct VectorFile {
    test_vectors: Vec<TestCase>,
}

#[test]
fn flathash_kat_reference() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/flathash/flathash-reference-vectors.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28):
    // the vectors are tracked in this repo, so this test FAILS instead of
    // returning green having verified nothing.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();
    let mut count = 0;
    for tv in &file.test_vectors {
        let got = flat_hash_hex(&tv.input)
            .unwrap_or_else(|e| panic!("flat_hash_hex failed at tc_id={}: {e:?}", tv.tc_id));
        // Normalize: remove 0x prefix for comparison
        let got_normalized = got.trim_start_matches("0x");
        let expected_normalized = tv.hash.trim_start_matches("0x");
        assert_eq!(
            got_normalized,
            expected_normalized,
            "FlatHash KAT failed at tc_id={}",
            tv.tc_id
        );
        count += 1;
    }
    println!("FlatHash: {count} reference KAT vectors passed");
    assert!(count >= 5, "expected at least 5 vectors");
}
