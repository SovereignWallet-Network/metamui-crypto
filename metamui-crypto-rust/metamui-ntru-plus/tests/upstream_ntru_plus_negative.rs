//! NTRU+ invalid-input gate: test-vectors/ntru-plus-upstream/ntru-plus-negative.json.
//!
//! The KAT gate only ever sees valid keys and ciphertexts. These records are
//! mutations of the KAT records whose verdicts come from the ntruplus.org
//! reference itself (tools/ntru-plus-upstream-gen/negative_harness.c):
//! coefficients `>= q` in pk / ct / sk must be refused (specification
//! 2026-07-10 §6.3), a canonical-but-wrong ciphertext must fail the
//! re-encryption check, and both kinds of decapsulation failure must be an
//! error rather than an all-zero "shared secret". The accepting rows — the
//! unmodified record, and a public key whose coefficient is exactly q-1 —
//! keep a binding that rejects everything from passing.

use metamui_ntru_plus::kem::{decapsulate, encapsulate};
use metamui_ntru_plus::{
    Ciphertext, NtruPlus1152, NtruPlus768, NtruPlus864, NtruPlusError, NtruPlusParams, PublicKey,
    SecretKey,
};
use serde_json::Value;

fn oracle() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/ntru-plus-upstream/ntru-plus-negative.json"
    );
    // A missing vector file is a broken checkout, not a skip.
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    serde_json::from_str(&raw).unwrap()
}

fn check<P: NtruPlusParams>(t: &Value) -> (&'static str, &'static str) {
    let case = t["case"].as_str().unwrap();
    let input = hex::decode(t["input"].as_str().unwrap()).unwrap();
    let expect = t["expect"].as_str().unwrap();
    match t["op"].as_str().unwrap() {
        "dec" => {
            let ct = Ciphertext::from_bytes::<P>(&input).unwrap();
            let sk = SecretKey::from_bytes::<P>(&hex::decode(t["sk"].as_str().unwrap()).unwrap()).unwrap();
            let got = decapsulate::<P>(&ct, &sk);
            if expect == "accept" {
                let ss = got.unwrap_or_else(|e| panic!("{} {case}: reference accepts, got {e:?}", P::NAME));
                assert_eq!(hex::encode(ss.ss), t["ss"].as_str().unwrap(), "{} {case}: shared secret", P::NAME);
                ("dec", "accept")
            } else {
                assert_eq!(got.err(), Some(NtruPlusError::DecapsulationFailed), "{} {case}: must fail", P::NAME);
                ("dec", "reject")
            }
        }
        "enc" => {
            let pk = PublicKey::from_bytes::<P>(&input).unwrap();
            let got = encapsulate::<P>(&pk);
            if expect == "accept" {
                got.unwrap_or_else(|e| panic!("{} {case}: reference accepts, got {e:?}", P::NAME));
                ("enc", "accept")
            } else {
                assert_eq!(got.err(), Some(NtruPlusError::InvalidPublicKey), "{} {case}: must refuse pk", P::NAME);
                ("enc", "reject")
            }
        }
        other => panic!("unknown op {other}"),
    }
}

#[test]
fn upstream_ntru_plus_negative() {
    let doc = oracle();
    let tests = doc["tests"].as_array().expect("tests array");
    let mut counts = std::collections::BTreeMap::new();
    for t in tests {
        let key = match t["param_set"].as_str().unwrap() {
            "ntruplus768" => check::<NtruPlus768>(t),
            "ntruplus864" => check::<NtruPlus864>(t),
            "ntruplus1152" => check::<NtruPlus1152>(t),
            other => panic!("unexpected parameter set {other}"),
        };
        *counts.entry(key).or_insert(0usize) += 1;
    }
    assert_eq!(tests.len(), doc["numberOfTests"].as_u64().unwrap() as usize);
    // Every kind of row must be present; a trimmed file must not pass quietly.
    for kind in [("dec", "accept"), ("dec", "reject"), ("enc", "accept"), ("enc", "reject")] {
        assert!(counts.get(&kind).copied().unwrap_or(0) > 0, "no {kind:?} rows in the oracle");
    }
    println!("PASS NTRU+ negative gate: {counts:?}");
}
