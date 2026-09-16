// HMAC-SHA-256 / HMAC-SHA-512 Wycheproof gate (FIPS 198-1).
//
// Source: test-vectors/hmac/hmac-sha256-wycheproof.json and
//         test-vectors/hmac/hmac-sha512-wycheproof.json
// (Google Wycheproof `mac_test_schema_v1`, AES-256-class key sizes only).
//
// Each group carries `tagSize` in bits; the full MAC is truncated to that
// length before comparison. `result` is honoured: `valid` must match,
// `invalid` must NOT match, `acceptable` is exercised but not asserted.
//
// PANICS (never skips) if a vector file is missing, and asserts the exact
// number of vectors the repo copy carries.
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct WpTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    key: String,
    msg: String,
    tag: String,
    result: String,
}

#[derive(Deserialize)]
struct WpGroup {
    #[serde(rename = "keySize")]
    key_size: usize,
    #[serde(rename = "tagSize")]
    tag_size: usize,
    tests: Vec<WpTest>,
}

#[derive(Deserialize)]
struct VectorFile {
    algorithm: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<WpGroup>,
}

fn load(file: &str) -> VectorFile {
    let path = format!(
        "{}/../../test-vectors/hmac/{}",
        env!("CARGO_MANIFEST_DIR"),
        file
    );
    let data = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("HMAC Wycheproof vector file missing ({path}): {e}"));
    serde_json::from_str(&data).expect("malformed HMAC Wycheproof JSON")
}

/// Runs one Wycheproof MAC file against `mac(key, msg) -> full tag`.
/// Returns (valid, invalid, acceptable) counts.
fn run(file: &str, algorithm: &str, mac: fn(&[u8], &[u8]) -> Vec<u8>) -> (usize, usize, usize) {
    let vf = load(file);
    assert_eq!(vf.algorithm, algorithm, "{file}: unexpected algorithm header");
    let (mut valid, mut invalid, mut acceptable) = (0, 0, 0);
    for group in &vf.test_groups {
        assert_eq!(group.tag_size % 8, 0, "{file}: tagSize must be whole bytes");
        let tag_len = group.tag_size / 8;
        for tv in &group.tests {
            let key = hex::decode(&tv.key).expect("key hex");
            let msg = hex::decode(&tv.msg).expect("msg hex");
            let expected = hex::decode(&tv.tag).expect("tag hex");
            assert_eq!(
                key.len() * 8,
                group.key_size,
                "{file} tc {}: key length disagrees with group keySize",
                tv.tc_id
            );
            let full = mac(&key, &msg);
            assert!(tag_len <= full.len(), "{file} tc {}: tagSize exceeds MAC", tv.tc_id);
            let got = &full[..tag_len];
            let matches = got == expected.as_slice();
            match tv.result.as_str() {
                "valid" => {
                    assert!(matches, "{file} tc {}: valid tag rejected", tv.tc_id);
                    valid += 1;
                }
                "invalid" => {
                    assert!(!matches, "{file} tc {}: invalid tag accepted", tv.tc_id);
                    invalid += 1;
                }
                "acceptable" => acceptable += 1,
                other => panic!("{file} tc {}: unknown result {other:?}", tv.tc_id),
            }
        }
    }
    (valid, invalid, acceptable)
}

#[test]
fn hmac_sha256_wycheproof_kat() {
    let (valid, invalid, acceptable) = run(
        "hmac-sha256-wycheproof.json",
        "HMACSHA256",
        metamui_sha2::sha256::hmac::hmac_sha256,
    );
    let total = valid + invalid + acceptable;
    // The repo copy carries 12 vectors (2 groups: tagSize 256 and 128).
    assert_eq!(total, 12, "expected 12 HMAC-SHA256 vectors, got {total}");
    println!("HMAC-SHA256 Wycheproof: {total} vectors ({valid} valid, {invalid} invalid, {acceptable} acceptable) passed");
}

#[test]
fn hmac_sha512_wycheproof_kat() {
    let (valid, invalid, acceptable) = run(
        "hmac-sha512-wycheproof.json",
        "HMACSHA512",
        metamui_sha2::sha512::hmac::hmac_sha512,
    );
    let total = valid + invalid + acceptable;
    // The repo copy carries 12 vectors (2 groups: tagSize 512 and 256).
    assert_eq!(total, 12, "expected 12 HMAC-SHA512 vectors, got {total}");
    println!("HMAC-SHA512 Wycheproof: {total} vectors ({valid} valid, {invalid} invalid, {acceptable} acceptable) passed");
}
