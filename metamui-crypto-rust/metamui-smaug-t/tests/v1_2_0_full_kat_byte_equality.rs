//! SMAUG-T v1.1.1 — FULL keygen + encap + decap KAT byte-equality.
//!
//! Extends `tests/v1_2_0_kat_byte_equality.rs` (which only does decap)
//! by driving the AES-256-CTR-DRBG with the upstream 48-byte seed
//! exactly as the NIST PQC KAT framework's `PQCgenKAT_kem.c` does:
//!
//! ```c
//! // For each vector:
//! randombytes_init(seed, NULL, 256);   // (re-)seed DRBG
//! randombytes(d, T_BYTES);             // 32 bytes  (sk rejection seed)
//! randombytes(inner_seed, CRYPTO_BYTES); // 32 bytes  (keygen entropy)
//! crypto_kem_keypair_internal(pk, sk, d, inner_seed);
//! randombytes(mu, MSG_BYTES);          // 32 or 16 bytes (encap message)
//! crypto_kem_enc_internal(ct, ss, pk, mu);
//! ```
//!
//! For each KAT vector this test asserts:
//!   - generated `pk` matches the recorded `pk`
//!   - generated `sk` matches the recorded `sk`
//!   - generated `ct` matches the recorded `ct`
//!   - generated `ss` matches the recorded `ss`
//!   - decap(ct, sk) also returns the recorded `ss` (round-trip check)
//!
//! This is the strictest form of NIST KAT byte-equality and is the
//! final verification gate for the v1.1.1 port.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

use metamui_aes_ctr_drbg::NistKatRng;
use metamui_smaug_t::smaug_v1_2_0::{
    crypto_kem_dec_internal, crypto_kem_enc_internal, crypto_kem_keypair_internal, Params,
};
use metamui_smaug_t::smaug_v1_2_0::params::{CRYPTO_BYTES, T_BYTES};

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn load_kat(filename: &str) -> Value {
    let path = workspace_root()
        .join("test-vectors/smaug-t/v1.2.0-kat")
        .join(filename);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {}", path.display(), e));
    serde_json::from_str(&raw).unwrap()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        out.push(u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap());
    }
    out
}

/// Run the upstream KAT generation flow on every vector, asserting pk,
/// sk, ct, ss all match byte-for-byte.
fn check_full_kat(filename: &str, params: &Params, label: &str) {
    let data = load_kat(filename);
    let tests = data["test_vectors"].as_array().unwrap();
    assert_eq!(tests.len(), 100);

    let pk_bytes = params.publickey_bytes();
    let sk_bytes = params.kem_secretkey_bytes();
    let ct_bytes = params.ciphertext_bytes();
    let msg_bytes = params.msg_bytes;

    let mut pk_pass = 0usize;
    let mut sk_pass = 0usize;
    let mut ct_pass = 0usize;
    let mut ss_pass = 0usize;
    let mut decap_pass = 0usize;
    let mut first_failure: Option<String> = None;

    for tv in tests {
        let count = tv["count"].as_u64().unwrap_or(0);
        let seed = hex_to_bytes(tv["seed"].as_str().unwrap());
        let expected_pk = hex_to_bytes(tv["pk"].as_str().unwrap());
        let expected_sk = hex_to_bytes(tv["sk"].as_str().unwrap());
        let expected_ct = hex_to_bytes(tv["ct"].as_str().unwrap());
        let expected_ss = hex_to_bytes(tv["ss"].as_str().unwrap());

        // Seed the DRBG with the 48-byte vector seed.
        let mut rng = NistKatRng::new(&seed).expect("DRBG init");

        // Step 1+2: derive d and inner_seed from DRBG (32 + 32 bytes).
        let d = rng.randombytes(T_BYTES).unwrap();
        let inner_seed = rng.randombytes(CRYPTO_BYTES).unwrap();

        // Step 3: deterministic keygen.
        let mut pk = vec![0u8; pk_bytes];
        let mut sk = vec![0u8; sk_bytes];
        crypto_kem_keypair_internal(params, &mut pk, &mut sk, &d, &inner_seed).expect("keypair lengths");

        if pk == expected_pk { pk_pass += 1; }
        if sk == expected_sk { sk_pass += 1; }

        // Step 4: derive mu and run deterministic encap.
        let mu = rng.randombytes(msg_bytes).unwrap();
        let mut ct = vec![0u8; ct_bytes];
        let mut ss = vec![0u8; CRYPTO_BYTES];
        crypto_kem_enc_internal(params, &mut ct, &mut ss, &pk, &mu).expect("enc lengths");

        if ct == expected_ct { ct_pass += 1; }
        if ss == expected_ss { ss_pass += 1; }

        // Step 5: also round-trip decap to confirm consistency.
        let mut ss_dec = vec![0u8; CRYPTO_BYTES];
        crypto_kem_dec_internal(params, &mut ss_dec, &ct, &sk).expect("dec lengths");
        if ss_dec == expected_ss { decap_pass += 1; }

        // Capture first failure for diagnostic clarity.
        if first_failure.is_none() {
            if pk != expected_pk {
                first_failure = Some(format!(
                    "count={} PK mismatch (showing first 32 bytes):\n  expected: {}\n  got:      {}",
                    count,
                    hex::encode(&expected_pk[..32.min(expected_pk.len())]),
                    hex::encode(&pk[..32.min(pk.len())]),
                ));
            } else if sk != expected_sk {
                first_failure = Some(format!("count={} SK mismatch", count));
            } else if ct != expected_ct {
                first_failure = Some(format!("count={} CT mismatch", count));
            } else if ss != expected_ss {
                first_failure = Some(format!(
                    "count={} SS mismatch:\n  expected: {}\n  got:      {}",
                    count,
                    hex::encode(&expected_ss),
                    hex::encode(&ss),
                ));
            } else if ss_dec != expected_ss {
                first_failure = Some(format!(
                    "count={} decap SS mismatch:\n  expected: {}\n  got:      {}",
                    count,
                    hex::encode(&expected_ss),
                    hex::encode(&ss_dec),
                ));
            }
        }
    }

    let total = tests.len();
    eprintln!(
        "[{}] pk={}/{} sk={}/{} ct={}/{} ss={}/{} decap={}/{}",
        label, pk_pass, total, sk_pass, total, ct_pass, total, ss_pass, total, decap_pass, total,
    );

    if let Some(msg) = first_failure {
        panic!("{}: full-KAT byte-equality FAILED — {}", label, msg);
    }
    assert_eq!(pk_pass, total, "{}: pk mismatch", label);
    assert_eq!(sk_pass, total, "{}: sk mismatch", label);
    assert_eq!(ct_pass, total, "{}: ct mismatch", label);
    assert_eq!(ss_pass, total, "{}: ss mismatch", label);
    assert_eq!(decap_pass, total, "{}: decap mismatch", label);
}

#[test]
fn v1_2_0_mode1_full_kat() {
    check_full_kat(
        "smaugt-mode1-v1.2.0-kat.json",
        &metamui_smaug_t::smaug_v1_2_0::MODE1,
        "SMAUG-T1",
    );
}

#[test]
fn v1_2_0_mode3_full_kat() {
    check_full_kat(
        "smaugt-mode3-v1.2.0-kat.json",
        &metamui_smaug_t::smaug_v1_2_0::MODE3,
        "SMAUG-T3",
    );
}

#[test]
fn v1_2_0_mode5_full_kat() {
    check_full_kat(
        "smaugt-mode5-v1.2.0-kat.json",
        &metamui_smaug_t::smaug_v1_2_0::MODE5,
        "SMAUG-T5",
    );
}

#[test]
fn v1_2_0_modet_full_kat() {
    check_full_kat(
        "smaugt-modet-v1.2.0-kat.json",
        &metamui_smaug_t::smaug_v1_2_0::MODET,
        "SMAUG-TiMER",
    );
}
