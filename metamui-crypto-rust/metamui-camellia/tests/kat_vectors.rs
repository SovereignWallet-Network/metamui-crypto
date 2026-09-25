// KAT vectors for Camellia -- RFC 3713 Appendix A
// Source: test-vectors/camellia/rfc3713-vectors.json
use metamui_camellia::{BlockCipher, Camellia128, Camellia192, Camellia256};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct TestCase {
    tc_id: u32,
    key_size: u32,
    key: String,
    plaintext: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct VectorFile {
    test_vectors: Vec<TestCase>,
}

#[test]
fn camellia_ecb_kat_rfc3713() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/camellia/rfc3713-vectors.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28):
    // the vectors are tracked in this repo, so this test FAILS instead of
    // returning green having verified nothing.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();
    let mut count = 0;
    for tv in &file.test_vectors {
        let key_bytes = hex::decode(&tv.key).unwrap();
        let pt = hex::decode(&tv.plaintext).unwrap();
        let expected = hex::decode(&tv.ciphertext).unwrap();

        let mut block = [0u8; 16];
        block.copy_from_slice(&pt);

        match tv.key_size {
            128 => {
                let key: [u8; 16] = key_bytes.try_into().unwrap();
                let cipher = Camellia128::new(&key);
                cipher.encrypt_block(&mut block);
                assert_eq!(&block, expected.as_slice(), "Camellia-128 KAT failed at tc_id={}", tv.tc_id);
                cipher.decrypt_block(&mut block);
                assert_eq!(&block, pt.as_slice(), "Camellia-128 decrypt roundtrip failed at tc_id={}", tv.tc_id);
            }
            192 => {
                let key: [u8; 24] = key_bytes.try_into().unwrap();
                let cipher = Camellia192::new(&key);
                cipher.encrypt_block(&mut block);
                assert_eq!(&block, expected.as_slice(), "Camellia-192 KAT failed at tc_id={}", tv.tc_id);
                cipher.decrypt_block(&mut block);
                assert_eq!(&block, pt.as_slice(), "Camellia-192 decrypt roundtrip failed at tc_id={}", tv.tc_id);
            }
            256 => {
                let key: [u8; 32] = key_bytes.try_into().unwrap();
                let cipher = Camellia256::new(&key);
                cipher.encrypt_block(&mut block);
                assert_eq!(&block, expected.as_slice(), "Camellia-256 KAT failed at tc_id={}", tv.tc_id);
                cipher.decrypt_block(&mut block);
                assert_eq!(&block, pt.as_slice(), "Camellia-256 decrypt roundtrip failed at tc_id={}", tv.tc_id);
            }
            _ => panic!("unexpected key_size {}", tv.key_size),
        }
        count += 1;
    }
    println!("Camellia: {count} RFC 3713 KAT vectors passed");
    assert!(count >= 3, "expected at least 3 vectors");
}
