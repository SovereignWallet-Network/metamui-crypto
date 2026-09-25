//! BIP-39 Trezor KAT test runner.
//!
//! Loads `test-vectors/bip39/bip39-trezor-vectors.json` (Trezor
//! python-mnemonic English vectors) and round-trips each record:
//! entropy → mnemonic → seed.

use metamui_bip39::Mnemonic;
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    english: Vec<Vec<String>>,
}

#[test]
fn trezor_english_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/bip39/bip39-trezor-vectors.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit A28):
    // the vectors are tracked in this repo, so this test FAILS instead of
    // returning green having verified nothing.
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();
    assert!(!file.english.is_empty(), "no vectors in Trezor file");

    let mut passed = 0usize;
    for (idx, row) in file.english.iter().enumerate() {
        assert!(row.len() >= 3, "vector {idx} malformed");
        let entropy = hex::decode(&row[0]).expect("bad entropy hex");
        let expected_phrase = &row[1];
        let expected_seed = hex::decode(&row[2]).expect("bad seed hex");

        // entropy → mnemonic
        let m = Mnemonic::from_entropy(&entropy).expect("from_entropy");
        assert_eq!(
            m.phrase(),
            expected_phrase,
            "vector {idx}: phrase mismatch"
        );

        // phrase → entropy (round-trip)
        let recovered = Mnemonic::from_phrase(m.phrase())
            .expect("from_phrase")
            .to_entropy();
        assert_eq!(recovered, entropy, "vector {idx}: entropy round-trip");

        // mnemonic → seed with Trezor passphrase
        let seed = m.to_seed("TREZOR");
        assert_eq!(
            &seed[..],
            &expected_seed[..],
            "vector {idx}: seed mismatch"
        );
        passed += 1;
    }
    eprintln!("BIP-39 Trezor English: {passed}/{}", file.english.len());
}
