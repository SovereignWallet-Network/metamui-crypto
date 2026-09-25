// KAT vectors for Deoxys-II-256-128 (32-byte key, 15-byte nonce, Deoxys-BC-384).
//
// Vectors from the Oasis Protocol reference implementation:
// https://github.com/oasisprotocol/deoxysii-rust
//
// Test file: test-vectors/deoxys/deoxys-oasisprotocol-vectors.json

use metamui_deoxys::DeoxysII;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct TestCase {
    tc_id: u32,
    #[allow(dead_code)]
    description: String,
    key: String,
    nonce: String,
    plaintext: String,
    aad: String,
    ciphertext: String,
    tag: String,
}

#[derive(Deserialize)]
struct VectorFile {
    #[allow(dead_code)]
    algorithm: String,
    test_vectors: Vec<TestCase>,
}

#[test]
fn deoxys_ii_256_128_kat() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/deoxys/deoxys-oasisprotocol-vectors.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28):
    // the vectors are tracked in this repo, so this test FAILS instead of
    // returning green having verified nothing.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();
    assert!(
        !file.test_vectors.is_empty(),
        "Vector file contains no test cases"
    );

    let mut passed = 0;

    for tv in &file.test_vectors {
        let key = hex::decode(&tv.key).unwrap();
        let nonce = hex::decode(&tv.nonce).unwrap();
        let pt = hex::decode(&tv.plaintext).unwrap();
        let aad = hex::decode(&tv.aad).unwrap();
        let expected_ct = hex::decode(&tv.ciphertext).unwrap();
        let expected_tag = hex::decode(&tv.tag).unwrap();

        // --- Encrypt ---
        let ct_tag = DeoxysII::encrypt(&key, &nonce, &pt, &aad)
            .unwrap_or_else(|e| panic!("tc_id={}: encrypt failed: {e:?}", tv.tc_id));

        // Ciphertext length = plaintext length + 16-byte tag
        assert_eq!(
            ct_tag.len(),
            pt.len() + 16,
            "tc_id={}: output length mismatch",
            tv.tc_id
        );

        // Split into ct and tag
        let (got_ct, got_tag) = ct_tag.split_at(pt.len());
        assert_eq!(
            got_ct, &expected_ct[..],
            "tc_id={}: ciphertext mismatch\n  got:      {}\n  expected: {}",
            tv.tc_id,
            hex::encode(got_ct),
            hex::encode(&expected_ct)
        );
        assert_eq!(
            got_tag, &expected_tag[..],
            "tc_id={}: tag mismatch\n  got:      {}\n  expected: {}",
            tv.tc_id,
            hex::encode(got_tag),
            hex::encode(&expected_tag)
        );

        // --- Round-trip: decrypt and verify plaintext recovery ---
        let recovered = DeoxysII::decrypt(&key, &nonce, &ct_tag, &aad)
            .unwrap_or_else(|e| panic!("tc_id={}: decrypt failed: {e:?}", tv.tc_id));
        assert_eq!(
            recovered, pt,
            "tc_id={}: round-trip plaintext mismatch",
            tv.tc_id
        );

        // --- Tamper detection ---
        let mut tampered = ct_tag.clone();
        tampered[0] ^= 0x01;
        let result = DeoxysII::decrypt(&key, &nonce, &tampered, &aad);
        assert!(
            result.is_err(),
            "tc_id={}: tampered ciphertext was accepted",
            tv.tc_id
        );

        eprintln!("tc_id={}: OK", tv.tc_id);
        passed += 1;
    }

    eprintln!(
        "Deoxys-II-256-128: {passed}/{} KAT vectors passed",
        file.test_vectors.len()
    );
}

/// Verify that a 128-bit key is correctly rejected
#[test]
fn deoxys_ii_128_key_rejected() {
    let key = [0x42u8; 16]; // 128-bit key — must be rejected
    let nonce = [0x24u8; 15];
    let result = DeoxysII::encrypt(&key, &nonce, b"test", b"");
    assert!(
        result.is_err(),
        "128-bit key was accepted — key size guard is broken"
    );
}
