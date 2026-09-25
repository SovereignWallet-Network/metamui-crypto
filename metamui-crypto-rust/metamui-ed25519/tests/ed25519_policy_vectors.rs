//! Ed25519 verification-policy gate: RFC 8032 as written.
//!
//! Source of truth: test-vectors/ed25519/ed25519-policy-vectors.json, built
//! by tools/ed25519-policy-gen from the RFC text and cross-checked against
//! ed25519-zebra + curve25519-dalek. MetaMUI's policy (decided 2026-09-24)
//! for every strict entry point is the `valid_rfc8032` column:
//!
//! * A and R decoded per RFC 8032 §5.1.3 — reject y >= p, x = 0 with the
//!   sign bit set, and no square root;
//! * reject S >= L;
//! * accept iff [8][S]B = [8]R + [8][k]A, k = SHA-512(R || A || M) mod L;
//! * small-order A and R are NOT screened.
//!
//! `verify`, `verify_strict` (method and free function) and `batch_verify`
//! must all agree with `valid_rfc8032` on every row. `Err` counts as a
//! rejection (S >= L and undecodable points are reported as `Err`).
//!
//! This test FAILS — never skips — when the vector file is missing.
use metamui_ed25519::{batch_verify, PublicKey, Signature};
use serde::Deserialize;
use std::fs;

const EXPECTED_ROWS: usize = 37;

#[derive(Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    category: String,
    description: String,
    public_key: String,
    message: String,
    signature: String,
    valid_rfc8032: bool,
    valid_zip215: bool,
}

#[derive(Deserialize)]
struct VectorFile {
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    tests: Vec<TestCase>,
}

fn load() -> VectorFile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/ed25519/ed25519-policy-vectors.json"
    );
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Ed25519 policy vector file unavailable at {path}: {e}"));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("Ed25519 policy vector file unparseable: {e}"))
}

#[test]
fn ed25519_policy_rfc8032_as_written() {
    let file = load();
    assert_eq!(file.number_of_tests, EXPECTED_ROWS, "numberOfTests changed");
    assert_eq!(file.tests.len(), EXPECTED_ROWS, "row count != numberOfTests");

    // The corpus must exercise all three verdict classes this policy has.
    for (rfc, zip) in [(true, true), (false, false), (false, true)] {
        assert!(
            file.tests.iter().any(|t| t.valid_rfc8032 == rfc && t.valid_zip215 == zip),
            "no row with (valid_rfc8032, valid_zip215) = ({rfc}, {zip})"
        );
    }

    let mut ran = 0usize;
    let mut wrong: Vec<String> = Vec::new();
    for tv in &file.tests {
        let pk: [u8; 32] = hex::decode(&tv.public_key)
            .expect("pk hex")
            .try_into()
            .expect("32-byte pk");
        let msg = hex::decode(&tv.message).expect("msg hex");
        let sig_arr: [u8; 64] = hex::decode(&tv.signature)
            .expect("sig hex")
            .try_into()
            .expect("64-byte sig");
        let public = PublicKey::from_bytes(&pk).expect("PublicKey::from_bytes is infallible");
        let sig = Signature::from_bytes(sig_arr);

        let verdicts = [
            ("PublicKey::verify", public.verify(&sig, &msg).unwrap_or(false)),
            ("PublicKey::verify_strict", public.verify_strict(&sig, &msg).unwrap_or(false)),
            ("verify", metamui_ed25519::verify(&sig, &msg, &public).unwrap_or(false)),
            (
                "verify_strict",
                metamui_ed25519::verify_strict(&sig, &msg, &public).unwrap_or(false),
            ),
            ("batch_verify", batch_verify(&[msg.as_slice()], &[&sig_arr], &[&pk])[0]),
        ];
        for (name, got) in verdicts {
            if got != tv.valid_rfc8032 {
                wrong.push(format!(
                    "tcId={} [{}] {}: {name} returned {got}, valid_rfc8032={}",
                    tv.tc_id, tv.category, tv.description, tv.valid_rfc8032
                ));
            }
        }
        ran += 1;
    }

    assert_eq!(ran, EXPECTED_ROWS, "not every row ran");
    assert!(wrong.is_empty(), "RFC 8032 policy disagreements:\n  {}", wrong.join("\n  "));
    println!("Ed25519 policy (RFC 8032 as written): {ran}/{EXPECTED_ROWS} rows agree");
}
