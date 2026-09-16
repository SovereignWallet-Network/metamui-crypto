// KAT vectors for AES-256-GCM -- FIPS 197 / Wycheproof
// Source: test-vectors/aes/aes-gcm-wycheproof.json
use metamui_aes_256::{Aes256Gcm, Aes256Key};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct WpTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
}

#[derive(Deserialize)]
struct WpGroup {
    tests: Vec<WpTest>,
}

#[derive(Deserialize)]
struct VectorFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<WpGroup>,
}

#[test]
fn aes_256_gcm_kat() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/aes/aes-gcm-wycheproof.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28):
    // the vectors are tracked in this repo, so this test FAILS instead of
    // returning green having verified nothing.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();
    let mut count = 0;
    for group in &file.test_groups {
        for tv in &group.tests {
            if tv.result != "valid" {
                continue;
            }
            let key_bytes = hex::decode(&tv.key).unwrap();
            let iv = hex::decode(&tv.iv).unwrap();
            let aad = hex::decode(&tv.aad).unwrap();
            let pt = hex::decode(&tv.msg).unwrap();
            let expected_ct = hex::decode(&tv.ct).unwrap();
            let expected_tag = hex::decode(&tv.tag).unwrap();

            let aes_key = Aes256Key::from_bytes(&key_bytes)
                .unwrap_or_else(|e| panic!("AES key error at tc_id={}: {e:?}", tv.tc_id));
            let cipher = Aes256Gcm::new(&aes_key)
                .unwrap_or_else(|e| panic!("AES-GCM init error at tc_id={}: {e:?}", tv.tc_id));

            let aad_opt = if aad.is_empty() { None } else { Some(aad.as_slice()) };
            let (got_ct, got_tag) = cipher.encrypt(&iv, &pt, aad_opt)
                .unwrap_or_else(|e| panic!("AES-256-GCM encrypt failed at tc_id={}: {e:?}", tv.tc_id));

            assert_eq!(
                got_ct.as_slice(),
                expected_ct.as_slice(),
                "AES-256-GCM ciphertext mismatch at tc_id={}",
                tv.tc_id
            );
            assert_eq!(
                &got_tag,
                expected_tag.as_slice(),
                "AES-256-GCM tag mismatch at tc_id={}",
                tv.tc_id
            );
            count += 1;
        }
    }
    println!("AES-256-GCM: {count} Wycheproof KAT vectors passed");
    assert!(count >= 3, "expected at least 3 vectors");
}
