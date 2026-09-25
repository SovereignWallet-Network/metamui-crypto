//! Genuine-upstream gate: NIST ACVP hmacDRBG-1.0 (SP 800-90A Rev. 1).
//!
//! Source: test-vectors/hmac-drbg/hmac-drbg-vectors.json, vendored complete
//! (22 groups × 15 tests) by tools/classical-vectors-gen/acvp_hmacdrbg_to_json.py.
//! Every group whose hash this crate implements is replayed in full; a
//! missing file or a short group is a failure, never a skip.
use metamui_hmac_drbg::{HashAlgorithm, HmacDrbg};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct OtherInput {
    #[serde(rename = "intendedUse")]
    intended_use: String,
    #[serde(rename = "additionalInput")]
    additional_input: String,
    #[serde(rename = "entropyInput")]
    entropy_input: String,
}

#[derive(Deserialize)]
struct TestCase {
    tc_id: u32,
    #[serde(rename = "entropyInput")]
    entropy_input: String,
    nonce: String,
    #[serde(rename = "personalizationString")]
    personalization_string: String,
    #[serde(rename = "otherInput")]
    other_input: Vec<OtherInput>,
    #[serde(rename = "returnedBits")]
    returned_bits: String,
}

#[derive(Deserialize)]
struct TestGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    #[serde(rename = "hashAlg")]
    hash_alg: String,
    #[serde(rename = "predResist")]
    pred_resist: bool,
    #[serde(rename = "returnedBitsLen")]
    returned_bits_len: usize,
    test_vectors: Vec<TestCase>,
}

#[derive(Deserialize)]
struct VectorFile {
    test_groups: Vec<TestGroup>,
}

fn opt(b: &[u8]) -> Option<&[u8]> {
    if b.is_empty() { None } else { Some(b) }
}

fn supported(hash_alg: &str) -> Option<HashAlgorithm> {
    match hash_alg {
        "SHA2-256" => Some(HashAlgorithm::Sha256),
        "SHA2-384" => Some(HashAlgorithm::Sha384),
        "SHA2-512" => Some(HashAlgorithm::Sha512),
        _ => None,
    }
}

#[test]
fn hmac_drbg_acvp_gate() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/hmac-drbg/hmac-drbg-vectors.json"
    );
    // A missing vector file is a broken checkout, not a skip (audit WS1 P0.2).
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("genuine ACVP HMAC-DRBG vectors missing at {path}: {e}"));
    let file: VectorFile = serde_json::from_str(&data).expect("parse hmac-drbg-vectors.json");

    let mut groups_run = 0;
    let mut count = 0;
    let mut failures = Vec::new();
    for group in &file.test_groups {
        let Some(alg) = supported(&group.hash_alg) else { continue };
        assert_eq!(group.test_vectors.len(), 15, "ACVP group {} is short", group.tg_id);
        groups_run += 1;
        for tv in &group.test_vectors {
            let entropy = hex::decode(&tv.entropy_input).unwrap();
            let nonce = hex::decode(&tv.nonce).unwrap();
            let pers = hex::decode(&tv.personalization_string).unwrap();
            let expected = hex::decode(&tv.returned_bits).unwrap();
            assert_eq!(expected.len() * 8, group.returned_bits_len);

            let mut drbg = HmacDrbg::new(&entropy, Some(&nonce), opt(&pers), alg)
                .unwrap_or_else(|e| panic!("tgId={} tcId={}: instantiate: {e:?}", group.tg_id, tv.tc_id));
            let mut out = vec![0u8; expected.len()];
            for step in &tv.other_input {
                let ent = hex::decode(&step.entropy_input).unwrap();
                let add = hex::decode(&step.additional_input).unwrap();
                match step.intended_use.as_str() {
                    "reSeed" => drbg.reseed(&ent, opt(&add)).expect("reseed"),
                    "generate" if group.pred_resist => {
                        // §9.3.1 step 7: prediction resistance = reseed with the
                        // additional input, then generate with none.
                        drbg.reseed(&ent, opt(&add)).expect("reseed (PR)");
                        drbg.generate(&mut out, None).expect("generate");
                    }
                    "generate" => drbg.generate(&mut out, opt(&add)).expect("generate"),
                    other => panic!("unknown intendedUse {other}"),
                }
            }
            if out != expected {
                failures.push(format!("tgId={} ({}, predResist={}) tcId={}", group.tg_id, group.hash_alg, group.pred_resist, tv.tc_id));
            }
            count += 1;
        }
    }
    assert_eq!(groups_run, 6, "expected the SHA2-256/384/512 groups × predResist true/false");
    assert_eq!(count, 90);
    assert!(failures.is_empty(), "{} of {count} ACVP HMAC-DRBG records mismatch:\n  {}", failures.len(), failures.join("\n  "));
}
