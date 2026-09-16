// SHA3-256 byte-aligned known-answer gate.
//
// Source: test-vectors/sha-3/sha3-256-byte-aligned.json — FIPS 202 / NIST
// CSRC example messages on whole bytes. The bit-oriented NIST ACVP sibling
// (sha3-256-acvp.json) is consumed by sha3_acvp_bit_kat.rs.
//
// PANICS (never skips) if the vector file is missing; asserts the exact
// count.
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
fn sha3_256_byte_aligned_kat() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/sha-3/sha3-256-byte-aligned.json"
    );
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("sha3-256 byte-aligned vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).expect("malformed vector JSON");

    let mut tested = 0;
    for group in &file.test_groups {
        for case in &group.tests {
            assert_eq!(case.len % 8, 0, "tc {}: file must be byte-aligned", case.tc_id);
            let msg = hex::decode(&case.msg).expect("invalid msg hex");
            assert_eq!(msg.len() * 8, case.len, "tc {}: msg/len disagree", case.tc_id);
            let got = hex::encode(metamui_sha3::sha3_256(&msg));
            assert_eq!(got, case.md.to_lowercase(), "SHA3-256 mismatch at tc {}", case.tc_id);
            tested += 1;
        }
    }
    assert_eq!(tested, 8, "expected 8 SHA3-256 byte-aligned cases, got {tested}");
    println!("SHA3-256 byte-aligned gate: {tested} cases passed");
}
