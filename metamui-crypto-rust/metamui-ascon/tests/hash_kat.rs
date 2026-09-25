// KAT vectors for Ascon-Hash256 -- NIST SP 800-232
// Source: test-vectors/ascon/ascon-hash256-kat.json (derived from the official
// ascon-c LWC_HASH_KAT_128_256 vectors).
use metamui_ascon::AsconHash256;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct Vector {
    #[serde(default)]
    tc_id: u32,
    message: String,
    digest: String,
}

#[derive(Deserialize)]
struct VectorFile {
    test_vectors: Vec<Vector>,
}

#[test]
fn ascon_hash256_kat() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/ascon/ascon-hash256-kat.json"
    );
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let file: VectorFile = serde_json::from_str(&data).unwrap();

    let mut count = 0;
    for tv in &file.test_vectors {
        let msg = hex::decode(&tv.message).unwrap();
        let expected = hex::decode(&tv.digest).unwrap();

        let got = AsconHash256::hash(&msg);
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "digest mismatch [tc_id={}] msg={}",
            tv.tc_id,
            tv.message
        );
        count += 1;
    }

    println!("Ascon-Hash256: {count} KAT vectors passed");
    assert!(count >= 5, "expected at least 5 vectors, got {count}");
}

#[test]
fn ascon_hash256_empty_message() {
    // SP 800-232 Ascon-Hash256 empty-message digest.
    let got = AsconHash256::hash(b"");
    let expected =
        hex::decode("0B3BE5850F2F6B98CAF29F8FDEA89B64A1FA70AA249B8F839BD53BAA304D92B2")
            .unwrap();
    assert_eq!(got.as_slice(), expected.as_slice());
}
