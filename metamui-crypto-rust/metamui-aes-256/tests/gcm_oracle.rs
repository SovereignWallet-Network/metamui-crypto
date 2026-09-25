// AES-256-GCM against the long-input oracle vectors.
// Source: test-vectors/aes/aes-256-gcm-oracle.json, produced by
// tools/aes-gcm-oracle-gen (pyca/cryptography generates, Go crypto/cipher
// cross-checks, vendored only when both agree).
//
// The Wycheproof extract this crate was gated on stops at 15-byte messages,
// so the eight-block GHASH path (128 bytes and up) was never exercised; it
// dropped the H^8 factor on the running state, producing non-standard tags
// and accepting two identical bit flips 128 bytes apart. These vectors cross
// every length boundary the implementation branches on, and the invalid cases
// are that forgery.
use metamui_aes_256::{Aes256Gcm, Aes256Key};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct OracleTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    comment: String,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
}

#[derive(Deserialize)]
struct OracleGroup {
    tests: Vec<OracleTest>,
}

#[derive(Deserialize)]
struct OracleFile {
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    #[serde(rename = "testGroups")]
    test_groups: Vec<OracleGroup>,
}

fn load() -> OracleFile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/aes/aes-256-gcm-oracle.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28).
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    serde_json::from_str(&data).unwrap()
}

#[test]
fn aes_256_gcm_long_input_oracle() {
    let file = load();
    let (mut valid, mut invalid) = (0usize, 0usize);
    for group in &file.test_groups {
        for tv in &group.tests {
            let key = Aes256Key::from_bytes(&hex::decode(&tv.key).unwrap()).unwrap();
            let gcm = Aes256Gcm::new(&key).unwrap();
            let iv = hex::decode(&tv.iv).unwrap();
            let aad = hex::decode(&tv.aad).unwrap();
            let ct = hex::decode(&tv.ct).unwrap();
            let tag = hex::decode(&tv.tag).unwrap();
            let aad_opt = if aad.is_empty() { None } else { Some(aad.as_slice()) };
            match tv.result.as_str() {
                "valid" => {
                    let msg = hex::decode(&tv.msg).unwrap();
                    let (got_ct, got_tag) = gcm.encrypt(&iv, &msg, aad_opt).unwrap();
                    assert_eq!(got_ct, ct, "ciphertext mismatch at tcId {} ({})", tv.tc_id, tv.comment);
                    assert_eq!(&got_tag[..], &tag[..], "tag mismatch at tcId {} ({})", tv.tc_id, tv.comment);
                    let opened = gcm
                        .decrypt(&iv, &ct, &tag, aad_opt)
                        .unwrap_or_else(|e| panic!("valid case rejected at tcId {} ({}): {e:?}", tv.tc_id, tv.comment));
                    assert_eq!(opened, msg, "plaintext mismatch at tcId {} ({})", tv.tc_id, tv.comment);
                    valid += 1;
                }
                "invalid" => {
                    assert!(
                        gcm.decrypt(&iv, &ct, &tag, aad_opt).is_err(),
                        "tampered case accepted at tcId {} ({})",
                        tv.tc_id,
                        tv.comment
                    );
                    invalid += 1;
                }
                other => panic!("unknown result {other:?} at tcId {}", tv.tc_id),
            }
        }
    }
    // Every record must have been exercised; a partially read file is a failure.
    assert_eq!(valid + invalid, file.number_of_tests);
    assert!(valid >= 250 && invalid >= 150, "oracle file shrank: {valid} valid, {invalid} invalid");
}

/// The concrete forgery, independent of the vector file: flip the same bit at
/// ciphertext offsets 0 and 128 and keep the tag. Before the fix this
/// decrypted successfully to a modified plaintext.
#[test]
fn aes_256_gcm_rejects_two_block_cancelling_flip() {
    let key = Aes256Key::from_bytes(&[0x42u8; 32]).unwrap();
    let gcm = Aes256Gcm::new(&key).unwrap();
    let nonce = [7u8; 12];
    for (pt_len, aad) in [(256usize, None), (300, Some(&b"header"[..])), (1024, Some(&[0u8; 300][..]))] {
        let pt = vec![0x40u8; pt_len];
        let (mut ct, tag) = gcm.encrypt(&nonce, &pt, aad).unwrap();
        ct[0] ^= 1;
        ct[128] ^= 1;
        assert!(
            gcm.decrypt(&nonce, &ct, &tag, aad).is_err(),
            "forged ciphertext accepted (pt {pt_len} B)"
        );
    }
}
