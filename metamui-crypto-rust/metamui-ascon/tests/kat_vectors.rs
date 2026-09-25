// KAT vectors for Ascon-AEAD128 -- NIST SP 800-232
// Source: test-vectors/ascon/ascon-vectors.json (canonical SP 800-232 KATs,
// derived from the official ascon-c LWC_AEAD_KAT_128_128 vectors).
// Ascon-AEAD128: rate 16, a = 12, b = 8.
use metamui_ascon::{AsconAead128, AsconAead};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct Vector {
    #[serde(default)]
    description: String,
    key: String,
    nonce: String,
    plaintext: String,
    aad: String,
    ciphertext: String,
    tag: String,
}

#[derive(Deserialize)]
struct TestGroup {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct VectorFile {
    test_groups: Vec<TestGroup>,
}

#[test]
fn ascon_aead128_kat() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/ascon/ascon-vectors.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28):
    // the vectors are tracked in this repo, so this test FAILS instead of
    // returning green having verified nothing.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();
    let mut count = 0;
    for group in &file.test_groups {
        for tv in &group.vectors {
            let key_bytes = hex::decode(&tv.key).unwrap();
            let nonce_bytes = hex::decode(&tv.nonce).unwrap();
            let pt = hex::decode(&tv.plaintext).unwrap();
            let aad = hex::decode(&tv.aad).unwrap();
            let expected_ct = hex::decode(&tv.ciphertext).unwrap();
            let expected_tag = hex::decode(&tv.tag).unwrap();

            let key: [u8; 16] = key_bytes.try_into().unwrap();
            let nonce: [u8; 16] = nonce_bytes.try_into().unwrap();

            let ascon = AsconAead128::new(key);

            // Encrypt and check ciphertext + tag against the vector.
            let (got_ct, got_tag) = ascon
                .encrypt(&nonce, &pt, &aad)
                .unwrap_or_else(|e| panic!("encrypt failed [{}]: {e:?}", tv.description));

            assert_eq!(
                got_ct, expected_ct,
                "ciphertext mismatch [{}]",
                tv.description
            );
            assert_eq!(
                got_tag.as_slice(),
                expected_tag.as_slice(),
                "tag mismatch [{}]",
                tv.description
            );

            // Round-trip: decrypt with the expected tag must recover plaintext.
            let mut tag_arr = [0u8; 16];
            tag_arr.copy_from_slice(&expected_tag);
            let recovered = ascon
                .decrypt(&nonce, &expected_ct, &tag_arr, &aad)
                .unwrap_or_else(|e| panic!("decrypt failed [{}]: {e:?}", tv.description));
            assert_eq!(recovered, pt, "decrypt round-trip mismatch [{}]", tv.description);

            count += 1;
        }
    }
    println!("Ascon-AEAD128: {count} KAT vectors passed");
    assert!(count >= 22, "expected at least 22 vectors, got {count}");
}
