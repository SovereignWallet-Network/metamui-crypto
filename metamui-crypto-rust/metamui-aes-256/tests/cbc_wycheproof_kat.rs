// AES-256-CBC with PKCS#7 padding — Wycheproof gate.
//
// Source: test-vectors/aes/aes-cbc-wycheproof.json (Google Wycheproof
// `aes_cbc_pkcs5_test.json`, `ind_cpa_test_schema_v1`, keySize=256 only).
//
// `valid`: encrypt(iv, msg) must equal ct byte-for-byte AND decrypt(iv, ct)
// must return msg. `invalid` (NoPadding / BadPadding): decrypt must be
// rejected — returning garbage instead of an error is the padding-oracle
// failure these cases exist to catch. `acceptable` is exercised, not asserted.
//
// PANICS (never skips) if the file is missing; asserts the exact count.
use metamui_aes_256::modes::cbc::Aes256Cbc;
use metamui_aes_256::{Aes256Key, IV_SIZE};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct WpTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    comment: String,
    key: String,
    iv: String,
    msg: String,
    ct: String,
    result: String,
}

#[derive(Deserialize)]
struct WpGroup {
    #[serde(rename = "keySize")]
    key_size: usize,
    #[serde(rename = "ivSize")]
    iv_size: usize,
    tests: Vec<WpTest>,
}

#[derive(Deserialize)]
struct VectorFile {
    algorithm: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<WpGroup>,
}

#[test]
fn aes_256_cbc_pkcs7_wycheproof_kat() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/aes/aes-cbc-wycheproof.json"
    );
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("AES-CBC Wycheproof vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).expect("malformed AES-CBC JSON");
    assert_eq!(file.algorithm, "AES-CBC-PKCS5");

    let (mut valid, mut invalid, mut acceptable) = (0, 0, 0);
    for group in &file.test_groups {
        assert_eq!(group.key_size, 256, "only AES-256 groups are expected");
        assert_eq!(group.iv_size, IV_SIZE * 8);
        for tv in &group.tests {
            let key = hex::decode(&tv.key).expect("key hex");
            let iv: [u8; IV_SIZE] = hex::decode(&tv.iv)
                .expect("iv hex")
                .try_into()
                .expect("iv must be 16 bytes");
            let msg = hex::decode(&tv.msg).expect("msg hex");
            let ct = hex::decode(&tv.ct).expect("ct hex");

            let aes_key = Aes256Key::from_bytes(&key)
                .unwrap_or_else(|e| panic!("tc {}: key error: {e:?}", tv.tc_id));
            let cipher = Aes256Cbc::new(&aes_key)
                .unwrap_or_else(|e| panic!("tc {}: init error: {e:?}", tv.tc_id));

            match tv.result.as_str() {
                "valid" => {
                    let got_ct = cipher.encrypt(&iv, &msg).unwrap_or_else(|e| {
                        panic!("tc {} ({}): encrypt failed: {e:?}", tv.tc_id, tv.comment)
                    });
                    assert_eq!(got_ct, ct, "tc {} ({}): ciphertext mismatch", tv.tc_id, tv.comment);
                    let got_pt = cipher.decrypt(&iv, &ct).unwrap_or_else(|e| {
                        panic!("tc {} ({}): decrypt failed: {e:?}", tv.tc_id, tv.comment)
                    });
                    assert_eq!(got_pt, msg, "tc {} ({}): plaintext mismatch", tv.tc_id, tv.comment);
                    valid += 1;
                }
                "invalid" => {
                    let r = cipher.decrypt(&iv, &ct);
                    assert!(
                        r.is_err(),
                        "tc {} ({}): invalid ciphertext/padding was accepted: {:?}",
                        tv.tc_id,
                        tv.comment,
                        r.map(hex::encode)
                    );
                    invalid += 1;
                }
                "acceptable" => {
                    let _ = cipher.decrypt(&iv, &ct);
                    acceptable += 1;
                }
                other => panic!("tc {}: unknown result {other:?}", tv.tc_id),
            }
        }
    }
    let total = valid + invalid + acceptable;
    assert_eq!(total, 10, "expected 10 AES-CBC vectors, got {total}");
    assert_eq!(valid, 7, "expected 7 valid AES-CBC vectors, got {valid}");
    assert_eq!(invalid, 3, "expected 3 invalid AES-CBC vectors, got {invalid}");
    println!("AES-256-CBC-PKCS7 Wycheproof: {total} vectors ({valid} valid, {invalid} invalid, {acceptable} acceptable) passed");
}
