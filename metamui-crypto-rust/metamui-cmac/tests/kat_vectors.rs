// KAT vectors for AES-256-CMAC -- NIST SP 800-38B / Wycheproof
// Source: test-vectors/cmac/aes-cmac-wycheproof.json
use metamui_cmac::Cmac;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct TestCase {
    tc_id: u32,
    key: String,
    msg: String,
    tag: String,
    result: String,
}

#[derive(Deserialize)]
struct VectorFile {
    test_vectors: Vec<TestCase>,
}

#[test]
fn aes_cmac_256_kat() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/cmac/aes-cmac-wycheproof.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28):
    // the vectors are tracked in this repo, so this test FAILS instead of
    // returning green having verified nothing.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();
    let mut count = 0;
    for tv in &file.test_vectors {
        if tv.result != "valid" {
            continue;
        }
        let key = hex::decode(&tv.key).unwrap();
        let msg = hex::decode(&tv.msg).unwrap();
        let expected = hex::decode(&tv.tag).unwrap();

        let got = Cmac::mac(&key, &msg)
            .unwrap_or_else(|e| panic!("AES-CMAC mac() failed at tc_id={}: {e:?}", tv.tc_id));

        assert_eq!(
            &got,
            expected.as_slice(),
            "AES-256-CMAC KAT failed at tc_id={}",
            tv.tc_id
        );
        count += 1;
    }
    println!("AES-256-CMAC: {count} Wycheproof KAT vectors passed");
    assert!(count >= 3, "expected at least 3 vectors");
}
