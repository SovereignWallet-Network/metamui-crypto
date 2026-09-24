//! SMAUG-T v1.1.1 KAT byte-equality tests — full v1.1.1 closure target.
//!
//! These tests are the verification gate for Finding #29. The
//! `smaug_v1_2_0` module is a clean-room port of the canonical
//! `cryptoLabInc/SMAUG-T @ v1.1.1` reference implementation (Feb–Apr
//! 2026, MIT). The v1.1.1 KAT (vendored at
//! `test-vectors/smaug-t/v1.2.0-kat/`) is the authoritative
//! KpqC-standardized vector set.
//!
//! Each test runs the in-tree decap on the upstream (pk, sk, ct)
//! triples and asserts byte-equal `ss`. Decap is deterministic, so
//! a correct algorithm must match all 100 vectors per variant.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

use metamui_smaug_t::smaug_v1_2_0::{crypto_kem_dec, Params};
use metamui_smaug_t::smaug_v1_2_0::params::CRYPTO_BYTES;

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // metamui-crypto-rust
    p.pop(); // repo root
    p
}

fn load_kat(filename: &str) -> Value {
    let path = workspace_root()
        .join("test-vectors/smaug-t/v1.2.0-kat")
        .join(filename);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {}", path.display(), e));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("could not parse {}: {}", path.display(), e))
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(cleaned.len() % 2 == 0);
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        out.push(u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap());
    }
    out
}

fn check_decap(filename: &str, params: &Params, label: &str) {
    let data = load_kat(filename);
    let tests = data["test_vectors"].as_array().expect("test_vectors");
    assert_eq!(tests.len(), 100, "{}: expected 100 vectors", label);

    let mut passed = 0usize;
    let mut first_failure: Option<String> = None;

    for tv in tests {
        let count = tv["count"].as_u64().unwrap_or(0);
        let _pk = hex_to_bytes(tv["pk"].as_str().unwrap()); // not directly needed for decap
        let sk = hex_to_bytes(tv["sk"].as_str().unwrap());
        let ct = hex_to_bytes(tv["ct"].as_str().unwrap());
        let expected_ss = hex_to_bytes(tv["ss"].as_str().unwrap());

        let mut ss = vec![0u8; CRYPTO_BYTES];
        crypto_kem_dec(params, &mut ss, &ct, &sk);

        if ss == expected_ss {
            passed += 1;
        } else if first_failure.is_none() {
            first_failure = Some(format!(
                "{} count={}: ss mismatch\n  expected: {}\n  got:      {}",
                label,
                count,
                hex::encode(&expected_ss),
                hex::encode(&ss),
            ));
        }
    }

    if let Some(msg) = first_failure {
        panic!(
            "{}: {} / {} passed byte-equality\n  first failure: {}",
            label, passed, tests.len(), msg
        );
    }
    assert_eq!(passed, 100, "{}: only {} of 100 passed", label, passed);
}

#[test]
fn v1_2_0_mode1_decap_byte_equality() {
    check_decap(
        "smaugt-mode1-v1.2.0-kat.json",
        &metamui_smaug_t::smaug_v1_2_0::MODE1,
        "SMAUG-T1 v1.1.1",
    );
}

#[test]
fn v1_2_0_mode3_decap_byte_equality() {
    check_decap(
        "smaugt-mode3-v1.2.0-kat.json",
        &metamui_smaug_t::smaug_v1_2_0::MODE3,
        "SMAUG-T3 v1.1.1",
    );
}

#[test]
fn v1_2_0_mode5_decap_byte_equality() {
    check_decap(
        "smaugt-mode5-v1.2.0-kat.json",
        &metamui_smaug_t::smaug_v1_2_0::MODE5,
        "SMAUG-T5 v1.1.1",
    );
}

#[test]
fn v1_2_0_modet_decap_byte_equality() {
    check_decap(
        "smaugt-modet-v1.2.0-kat.json",
        &metamui_smaug_t::smaug_v1_2_0::MODET,
        "SMAUG-TiMER v1.1.1",
    );
}
