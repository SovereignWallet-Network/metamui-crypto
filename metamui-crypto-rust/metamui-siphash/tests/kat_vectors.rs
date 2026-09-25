// KAT vectors for SipHash-2-4 -- reference implementation
// Source: test-vectors/siphash/siphash-reference-vectors.json
use metamui_siphash::SipHash64;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct VectorFile {
    key: String,
    test_vectors: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestCase {
    tc_id: u32,
    input: String,
    hash: String,
}

#[test]
fn siphash24_kat_reference() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/siphash/siphash-reference-vectors.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28):
    // the vectors are tracked in this repo, so this test FAILS instead of
    // returning green having verified nothing.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();
    let key_bytes = hex::decode(&file.key).unwrap();
    let key: [u8; 16] = key_bytes.try_into().unwrap();

    let mut count = 0;
    for tv in &file.test_vectors {
        let input = hex::decode(&tv.input).unwrap();
        // hash is 8 bytes in little-endian; decode and interpret as u64 LE
        let expected_bytes = hex::decode(&tv.hash).unwrap();
        let expected: u64 = u64::from_le_bytes(expected_bytes.as_slice().try_into().unwrap());

        let mut hasher = SipHash64::new(&key);
        hasher.update(&input);
        let got = hasher.finalize();

        assert_eq!(
            got,
            expected,
            "SipHash-2-4 KAT failed at tc_id={} (input_len={})",
            tv.tc_id,
            input.len()
        );
        count += 1;
    }
    println!("SipHash-2-4: {count} reference KAT vectors passed");
    assert!(count >= 8, "expected at least 8 vectors");
}
