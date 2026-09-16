// KAT vectors for SHA-512 -- NIST FIPS 180-4
// Source: test-vectors/sha-2/sha512-acvp.json
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    id: u32,
    msg: String,
    md: String,
}

#[derive(Deserialize)]
struct VectorFile {
    sample_test_vectors: Vec<TestCase>,
}

#[test]
fn sha512_kat_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/sha-2/sha512-acvp.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28):
    // the vectors are tracked in this repo, so this test FAILS instead of
    // returning green having verified nothing.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();
    let mut count = 0;
    for tv in &file.sample_test_vectors {
        let msg = match hex::decode(&tv.msg) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let expected = hex::decode(&tv.md).unwrap();
        let got = metamui_sha2::sha512::sha512(&msg);
        assert_eq!(
            got.as_ref(),
            expected.as_slice(),
            "SHA-512 KAT failed at tc_id={}",
            tv.id
        );
        count += 1;
    }
    println!("SHA-512: {count} KAT vectors passed");
    assert!(count >= 3, "expected at least 3 vectors");
}
