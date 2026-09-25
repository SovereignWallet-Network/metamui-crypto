// KAT vectors for Keccak-256 (Ethereum pre-NIST variant)
// Source: test-vectors/keccak256/keccak256-vectors.json
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct TestCase {
    tc_id: u32,
    message_hex: String,
    digest: String,
}

#[derive(Deserialize)]
struct VectorFile {
    test_vectors: Vec<TestCase>,
}

#[test]
fn keccak256_kat_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/keccak256/keccak256-vectors.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28):
    // the vectors are tracked in this repo, so this test FAILS instead of
    // returning green having verified nothing.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();
    let mut count = 0;
    for tv in &file.test_vectors {
        let msg = hex::decode(&tv.message_hex).unwrap();
        let expected = hex::decode(&tv.digest).unwrap();
        let got = metamui_keccak256::keccak256(&msg);
        assert_eq!(
            &got[..],
            expected.as_slice(),
            "Keccak-256 KAT failed at tc_id={}",
            tv.tc_id
        );
        count += 1;
    }
    println!("Keccak-256: {count} KAT vectors passed");
    assert!(count >= 3, "expected at least 3 vectors");
}
