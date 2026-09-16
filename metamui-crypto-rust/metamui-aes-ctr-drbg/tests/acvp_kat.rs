//! Genuine-upstream gate: NIST ACVP ctrDRBG-1.0, AES-256, all four groups
//! (derivation function on/off × prediction resistance on/off).
//!
//! Source: test-vectors/aes-ctr-drbg/ctr-drbg-acvp.json (vendored by
//! tools/classical-vectors-gen/acvp_ctrdrbg_to_json.py from the ACVP-Server
//! internalProjection.json). Before this file the AES-256-CTR-DRBG family had
//! no genuine vectors in any binding (audit finding A5).
//!
//! A missing vector file is a broken checkout, not a skip.

use metamui_aes_ctr_drbg::{AesCtrDrbg, AesCtrDrbgDf};
use serde::Deserialize;

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
    #[serde(rename = "persoString")]
    perso_string: String,
    #[serde(rename = "otherInput")]
    other_input: Vec<OtherInput>,
    #[serde(rename = "returnedBits")]
    returned_bits: String,
}

#[derive(Deserialize)]
struct TestGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    mode: String,
    #[serde(rename = "derFunc")]
    der_func: bool,
    #[serde(rename = "predResistance")]
    pred_resistance: bool,
    #[serde(rename = "returnedBitsLen")]
    returned_bits_len: usize,
    test_vectors: Vec<TestCase>,
}

#[derive(Deserialize)]
struct VectorFile {
    test_groups: Vec<TestGroup>,
}

/// One DRBG instance behind an enum so the step script below is written
/// once for both constructions.
enum Drbg {
    NoDf(AesCtrDrbg),
    Df(AesCtrDrbgDf),
}

impl Drbg {
    fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) {
        match self {
            Drbg::NoDf(d) => d.reseed(entropy, add).expect("reseed"),
            Drbg::Df(d) => d.reseed(entropy, add).expect("reseed (df)"),
        }
    }
    fn generate(&mut self, out: &mut [u8], add: Option<&[u8]>) {
        match self {
            Drbg::NoDf(d) => d.generate(out, add).expect("generate"),
            Drbg::Df(d) => d.generate(out, add).expect("generate (df)"),
        }
    }
}

fn opt(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.is_empty() { None } else { Some(bytes) }
}

#[test]
fn ctr_drbg_aes256_acvp_gate() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/aes-ctr-drbg/ctr-drbg-acvp.json"
    );
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("genuine ACVP ctrDRBG vectors missing at {path}: {e}"));
    let file: VectorFile = serde_json::from_str(&data).expect("parse ctr-drbg-acvp.json");
    assert_eq!(file.test_groups.len(), 4, "expected the four AES-256 ACVP groups");

    let mut total = 0;
    let mut failures: Vec<String> = Vec::new();
    for group in &file.test_groups {
        assert_eq!(group.mode, "AES-256");
        for tc in &group.test_vectors {
            let entropy = hex::decode(&tc.entropy_input).unwrap();
            let nonce = hex::decode(&tc.nonce).unwrap();
            let perso = hex::decode(&tc.perso_string).unwrap();
            let expected = hex::decode(&tc.returned_bits).unwrap();
            assert_eq!(expected.len() * 8, group.returned_bits_len);

            let mut drbg = if group.der_func {
                Drbg::Df(AesCtrDrbgDf::instantiate(&entropy, &nonce, opt(&perso)).expect("instantiate"))
            } else {
                assert!(nonce.is_empty(), "no-DF groups carry no nonce");
                Drbg::NoDf(AesCtrDrbg::new(&entropy, opt(&perso)).expect("instantiate"))
            };

            let mut out = vec![0u8; expected.len()];
            for step in &tc.other_input {
                let add = hex::decode(&step.additional_input).unwrap();
                let ent = hex::decode(&step.entropy_input).unwrap();
                match step.intended_use.as_str() {
                    "reSeed" => drbg.reseed(&ent, opt(&add)),
                    "generate" if group.pred_resistance => {
                        // SP 800-90A §9.3.1 step 7: prediction resistance means
                        // reseed with the additional input, then generate with none.
                        drbg.reseed(&ent, opt(&add));
                        drbg.generate(&mut out, None);
                    }
                    "generate" => drbg.generate(&mut out, opt(&add)),
                    other => panic!("unknown intendedUse {other}"),
                }
            }
            if out != expected {
                failures.push(format!(
                    "tgId={} tcId={} (derFunc={}, predResistance={})",
                    group.tg_id, tc.tc_id, group.der_func, group.pred_resistance
                ));
            }
            total += 1;
        }
    }
    assert_eq!(total, 60, "all 60 AES-256 ACVP records must run");
    assert!(
        failures.is_empty(),
        "{} of 60 ACVP ctrDRBG records mismatch:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}
