// PBKDF2 known-answer gate.
//
// Source: test-vectors/pbkdf2/rfc6070-vectors.json — one section per PRF.
// This crate implements PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512 only, so
// the HMAC-SHA256 section (RFC 7914 §11 + widely cross-checked vectors) is
// the one consumed. The HMAC-SHA1 section (RFC 6070 proper) has no
// consumer here because the binding has no SHA-1.
//
// Passwords/salts are ASCII; `password_hex`/`salt_hex` take precedence when
// present (embedded-NUL cases). PANICS (never skips) if the file is missing
// or the HMAC-SHA256 section is absent, and asserts the exact vector count.
use metamui_pbkdf2::PBKDF2;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct Case {
    tc_id: u32,
    password: String,
    password_hex: Option<String>,
    salt: String,
    salt_hex: Option<String>,
    c: u32,
    #[serde(rename = "dkLen")]
    dk_len: usize,
    dk: String,
}

#[derive(Deserialize)]
struct Section {
    prf: String,
    test_vectors: Vec<Case>,
}

#[derive(Deserialize)]
struct VectorFile {
    algorithm: String,
    sections: Vec<Section>,
}

fn bytes_of(ascii: &str, hex_override: &Option<String>) -> Vec<u8> {
    match hex_override {
        Some(h) => hex::decode(h).expect("hex override"),
        None => ascii.as_bytes().to_vec(),
    }
}

#[test]
fn pbkdf2_hmac_sha256_rfc6070_file_kat() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/pbkdf2/rfc6070-vectors.json"
    );
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("PBKDF2 vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).expect("malformed PBKDF2 JSON");
    assert_eq!(file.algorithm, "PBKDF2");
    // The file carries two 6-record sections (HMAC-SHA1 = RFC 6070 proper,
    // HMAC-SHA256 = RFC 7914 §11 + cross-checked vectors). Pin the shape so
    // a truncated or restructured copy fails here rather than silently
    // shrinking coverage; only the SHA-256 section can be exercised.
    let total: usize = file.sections.iter().map(|s| s.test_vectors.len()).sum();
    assert_eq!(total, 12, "expected 12 PBKDF2 records (6 SHA-1 + 6 SHA-256), got {total}");
    assert!(
        file.sections.iter().any(|s| s.prf == "HMAC-SHA1" && s.test_vectors.len() == 6),
        "HMAC-SHA1 section missing or not 6 records (unconsumed here: no SHA-1 in this binding)"
    );

    let section = file
        .sections
        .iter()
        .find(|s| s.prf == "HMAC-SHA256")
        .expect("vector file has no HMAC-SHA256 section");

    let mut count = 0;
    for tv in &section.test_vectors {
        let password = bytes_of(&tv.password, &tv.password_hex);
        let salt = bytes_of(&tv.salt, &tv.salt_hex);
        let expected = hex::decode(&tv.dk).expect("dk hex");
        assert_eq!(expected.len(), tv.dk_len, "tc {}: dk/dkLen disagree", tv.tc_id);
        let got = PBKDF2::pbkdf2_hmac_sha256(&password, &salt, tv.c, tv.dk_len)
            .unwrap_or_else(|e| panic!("tc {}: pbkdf2 failed: {e:?}", tv.tc_id));
        assert_eq!(got, expected, "PBKDF2-HMAC-SHA256 mismatch at tc {}", tv.tc_id);
        count += 1;
    }
    assert_eq!(count, 6, "expected 6 HMAC-SHA256 vectors, got {count}");
    println!("PBKDF2-HMAC-SHA256: {count} vectors passed");
}
