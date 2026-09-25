// KAT vectors for Ed25519 against the ZIP-215 corpus
// Source: test-vectors/ed25519/zip215-vectors.json
//
// This crate verifies under RFC 8032 as written (MetaMUI policy decided
// 2026-09-24): §5.1.3 decoding of A and R, S < L, the cofactored equation,
// and no small-order screen. The ZIP-215 half of the corpus is covered by
// metamui-ed25519-zip215.
//
// No column of this corpus records "RFC 8032 as written": `valid_strict` is
// the retired profile (canonical encodings plus a small-order public-key
// screen) and `valid_rfc8032_cofactorless` is a bare cofactorless verifier.
// The policy's verdict is pinned per tc_id in RFC8032_AS_WRITTEN; it differs
// from `valid_strict` only on tc_2..tc_4 (canonical small-order keys, no
// longer screened), which the test asserts as well. The full policy oracle
// is test-vectors/ed25519/ed25519-policy-vectors.json
// (tests/ed25519_policy_vectors.rs).
use metamui_ed25519::*;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
// `valid_zip215` is serde-populated for schema completeness only.
#[allow(dead_code)]
struct TestCase {
    tc_id: u32,
    description: String,
    public_key: String,
    message: String,
    signature: String,
    valid_zip215: bool,
    valid_strict: bool,
}

#[derive(Deserialize)]
struct VectorFile {
    test_vectors: Vec<TestCase>,
}

/// RFC 8032 as written, per tc_id: tc_1 honest; tc_2..tc_4 canonical
/// small-order A with small-order R and S = 0, so the cofactored equation
/// holds; tc_5 y = p + 1 (non-canonical, §5.1.3 rejects); tc_6 S >= L.
const RFC8032_AS_WRITTEN: [(u32, bool); 6] =
    [(1, true), (2, true), (3, true), (4, true), (5, false), (6, false)];

/// tc_ids on which RFC 8032 as written differs from the retired
/// `valid_strict` profile (its small-order public-key screen).
const SMALL_ORDER_SCREEN_ROWS: [u32; 3] = [2, 3, 4];

#[test]
fn ed25519_zip215_conformance() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/ed25519/zip215-vectors.json"
    );
    // Fail-closed: a missing/unreadable vector file is a hard error, never a skip.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("ZIP-215 vector file unavailable at {path}: {e}"));
    let file: VectorFile = serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("ZIP-215 vector file unparseable: {e}"));
    assert_eq!(
        file.test_vectors.len(),
        RFC8032_AS_WRITTEN.len(),
        "corpus rows and pinned RFC 8032 verdicts diverged"
    );

    let mut pass = 0;
    let mut wrong: Vec<String> = Vec::new();
    for tv in &file.test_vectors {
        let expected = RFC8032_AS_WRITTEN
            .iter()
            .find(|(id, _)| *id == tv.tc_id)
            .unwrap_or_else(|| panic!("tc_id={} has no pinned RFC 8032 verdict", tv.tc_id))
            .1;
        assert_eq!(
            expected != tv.valid_strict,
            SMALL_ORDER_SCREEN_ROWS.contains(&tv.tc_id),
            "tc_id={}: the pinned RFC 8032 verdict may differ from valid_strict only on the \
             small-order-screen rows",
            tv.tc_id
        );

        let pk_bytes = hex::decode(&tv.public_key).unwrap();
        let msg = hex::decode(&tv.message).unwrap();
        let sig_bytes = hex::decode(&tv.signature).unwrap();

        let result = (|| -> Option<(bool, bool)> {
            let pk_arr: [u8; 32] = pk_bytes.try_into().ok()?;
            let sig_arr: [u8; 64] = sig_bytes.try_into().ok()?;
            let pk = PublicKey::from_bytes(&pk_arr).ok()?;
            let sig = Signature::from_bytes(sig_arr);
            Some((
                pk.verify(&sig, &msg).unwrap_or(false),
                pk.verify_strict(&sig, &msg).unwrap_or(false),
            ))
        })();

        let (verify, verify_strict) = result.unwrap_or((false, false));
        if verify == expected && verify_strict == expected {
            pass += 1;
        } else {
            wrong.push(format!(
                "tc_id={} ({}): RFC 8032 as written expects {} but verify={} verify_strict={}",
                tv.tc_id, tv.description, expected, verify, verify_strict
            ));
        }
    }
    println!(
        "Ed25519 ZIP-215 corpus under RFC 8032 as written: {pass}/{} decisions correct",
        file.test_vectors.len()
    );
    assert!(wrong.is_empty(), "RFC 8032 decisions disagree:\n  {}", wrong.join("\n  "));
}
