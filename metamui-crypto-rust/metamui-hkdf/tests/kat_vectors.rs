// KAT vectors for HKDF-SHA256 -- RFC 5869 Appendix A
// Source: test-vectors/hkdf/rfc5869-vectors.json
use metamui_hkdf::{hkdf_extract_sha256, hkdf_expand_sha256};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct TestCase {
    tc_id: u32,
    hash: String,
    ikm: String,
    salt: String,
    info: String,
    l: usize,
    prk: String,
    okm: String,
}

#[derive(Deserialize)]
struct VectorFile {
    test_vectors: Vec<TestCase>,
}

#[test]
fn hkdf_sha256_kat_rfc5869() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/hkdf/rfc5869-vectors.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28):
    // the vectors are tracked in this repo, so this test FAILS instead of
    // returning green having verified nothing.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();
    let mut count = 0;
    for tv in &file.test_vectors {
        if tv.hash != "SHA-256" {
            continue; // skip SHA-512 vectors
        }
        let ikm = hex::decode(&tv.ikm).unwrap();
        let salt = hex::decode(&tv.salt).unwrap();
        let info = hex::decode(&tv.info).unwrap();
        let expected_prk = hex::decode(&tv.prk).unwrap();
        let expected_okm = hex::decode(&tv.okm).unwrap();

        let salt_opt = if salt.is_empty() { None } else { Some(salt.clone()) };
        let got_prk = hkdf_extract_sha256(ikm.clone(), salt_opt);
        assert_eq!(
            got_prk.as_slice(),
            expected_prk.as_slice(),
            "HKDF-SHA256 PRK mismatch at tc_id={}",
            tv.tc_id
        );

        let got_okm = hkdf_expand_sha256(got_prk.clone(), info.clone(), tv.l).unwrap();
        assert_eq!(
            got_okm.as_slice(),
            expected_okm.as_slice(),
            "HKDF-SHA256 OKM mismatch at tc_id={}",
            tv.tc_id
        );
        count += 1;
    }
    println!("HKDF-SHA256: {count} RFC 5869 KAT vectors passed");
    assert!(count >= 2, "expected at least 2 SHA-256 vectors");
}
