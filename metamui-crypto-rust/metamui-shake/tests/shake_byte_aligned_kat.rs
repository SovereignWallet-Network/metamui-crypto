// SHAKE128 / SHAKE256 byte-aligned known-answer gate.
//
// Source: test-vectors/sha-3/shake128-byte-aligned.json and
// shake256-byte-aligned.json — FIPS 202 standard messages + NIST CAVS
// byte-test ShortMsg inputs + rate-boundary lengths, at several output
// lengths. The sibling *-wycheproof.json ACVP files are entirely sub-byte
// (len 1..5 bits), so they exercise nothing on a byte-level XOF API.
//
// PANICS (never skips) if a vector file is missing.
use metamui_shake::shake128::Shake128;
use metamui_shake::shake256::Shake256;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct Case {
    #[serde(rename = "tcId")]
    tc_id: u32,
    msg: String,
    len: usize,
    #[serde(rename = "outLen")]
    out_len: usize,
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

fn run(filename: &str, xof: impl Fn(&[u8], usize) -> Vec<u8>) -> usize {
    let path = format!(
        "{}/../../test-vectors/sha-3/{}",
        env!("CARGO_MANIFEST_DIR"),
        filename
    );
    let data = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("SHAKE byte-aligned vector file missing ({path}): {e}"));
    let file: VectorFile = serde_json::from_str(&data).expect("malformed vector JSON");

    let mut tested = 0;
    for group in &file.test_groups {
        for case in &group.tests {
            assert_eq!(case.len % 8, 0, "tc {}: file must be byte-aligned", case.tc_id);
            let msg = hex::decode(&case.msg).expect("invalid msg hex");
            let got = hex::encode(xof(&msg, case.out_len / 8));
            assert_eq!(
                got,
                case.md.to_lowercase(),
                "{filename} mismatch at tc {} (out {} bits)",
                case.tc_id,
                case.out_len
            );
            tested += 1;
        }
    }
    tested
}

#[test]
fn shake128_byte_aligned_kat() {
    let n = run("shake128-byte-aligned.json", |m, o| Shake128::hash(m, o));
    assert!(n >= 12, "unexpectedly few SHAKE128 cases");
    println!("SHAKE128 byte-aligned gate: {n} cases passed");
}

#[test]
fn shake256_byte_aligned_kat() {
    let n = run("shake256-byte-aligned.json", |m, o| Shake256::hash(m, o));
    assert!(n >= 12, "unexpectedly few SHAKE256 cases");
    println!("SHAKE256 byte-aligned gate: {n} cases passed");
}
