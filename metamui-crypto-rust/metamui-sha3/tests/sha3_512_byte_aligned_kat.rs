// SHA3-512 byte-aligned known-answer gate.
//
// Source: test-vectors/sha-3/sha3-512-byte-aligned.json — FIPS 202 standard
// messages + NIST CAVS byte-test ShortMsg inputs + rate-boundary lengths.
// The sibling sha3-512-acvp.json is NIST ACVP and almost entirely
// bit-oriented (len%8!=0), so it exercises essentially nothing on a byte-level
// API; this file is the consumable companion.
//
// PANICS (never skips) if the vector file is missing.
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct Case {
    #[serde(rename = "tcId")]
    tc_id: u32,
    msg: String,
    len: usize,
    md: String,
}

#[derive(Deserialize)]
struct Group {
    tests: Vec<Case>,
}

#[derive(Deserialize)]
struct VectorFile {
    #[serde(rename = "testGroups")]
    test_groups: Vec<Group>,
}

#[test]
fn sha3_512_byte_aligned_kat() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/sha-3/sha3-512-byte-aligned.json"
    );
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("sha3-512 byte-aligned vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).expect("malformed vector JSON");

    let mut tested = 0;
    for group in &file.test_groups {
        for case in &group.tests {
            assert_eq!(case.len % 8, 0, "tc {}: file must be byte-aligned", case.tc_id);
            let msg = hex::decode(&case.msg).expect("invalid msg hex");
            let got = hex::encode(metamui_sha3::sha3_512(&msg));
            assert_eq!(
                got,
                case.md.to_lowercase(),
                "SHA3-512 mismatch at tc {}",
                case.tc_id
            );
            tested += 1;
        }
    }
    assert!(tested >= 10, "unexpectedly few SHA3-512 byte-aligned cases");
    println!("SHA3-512 byte-aligned gate: {tested} cases passed");
}
