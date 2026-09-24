//! Genuine-upstream conformance gate for NTRU+ (KpqC KEM).
//!
//! The vectors under `test-vectors/ntru-plus-upstream/` are the NTRU+ authors'
//! own `KAT/*/PQCkemKAT_*.rsp` records (ntruplus.org reference, commit
//! 621c667, vendored as the `metamui-crypto-reference/c/ntruplus-ref`
//! submodule), trimmed to five per parameter set by
//! `tools/ntru-plus-upstream-gen/genrun.sh`, which first proves the vendored
//! tree reproduces the shipped files byte-for-byte.
//!
//! The records were produced by the NIST `PQCgenKAT_kem` harness: `randombytes`
//! is the AES-256-CTR-DRBG without derivation function, seeded with the record's
//! 48-byte `seed`; keygen draws `randombytes(32)` per sampling attempt (f, then
//! g) and encaps draws `randombytes(N/8)`. Replaying that DRBG through the
//! crate's deterministic entry points must reproduce pk, sk, ct and ss exactly,
//! and decaps must recover ss.
//!
//! A missing or altered vector file fails this test; it never skips.

use metamui_aes_ctr_drbg::NistKatRng;
use metamui_ntru_plus::kem::{decapsulate, encapsulate_det, generate_keypair_det};
use metamui_ntru_plus::params::{NtruPlus1152, NtruPlus768, NtruPlus864, NtruPlusParams};
use serde_json::Value;
use std::cell::RefCell;
use std::path::PathBuf;

const RECORDS_PER_SET: usize = 5;

fn oracle() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/ntru-plus-upstream/ntru-plus-upstream.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("NTRU+ upstream oracle missing at {}: {e}", path.display()));
    let doc: Value = serde_json::from_str(&text).expect("oracle is not valid JSON");
    let prov = doc["provenance"].as_str().expect("provenance string");
    assert!(
        prov.contains("ntruplus.org") && prov.contains("NOT self-generated"),
        "oracle provenance does not name the ntruplus.org reference KAT files"
    );
    assert_eq!(doc["rng"].as_str(), Some("nist-aes256-ctr-drbg-no-df"));
    doc
}

fn hexv(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap_or_else(|| panic!("missing field {key}"))).unwrap()
}

fn check<P: NtruPlusParams>(v: &Value) {
    let ps = v["param_set"].as_str().unwrap();
    let count = v["count"].as_u64().unwrap();
    let seed = hexv(v, "seed");
    assert_eq!(seed.len(), 48, "{ps} #{count}: NIST KAT seeds are 48 bytes");
    let (want_pk, want_sk, want_ct, want_ss) = (hexv(v, "pk"), hexv(v, "sk"), hexv(v, "ct"), hexv(v, "ss"));
    assert_eq!(want_pk.len(), P::PUBLIC_KEY_SIZE, "{ps} #{count}: pk size");
    assert_eq!(want_sk.len(), P::SECRET_KEY_SIZE, "{ps} #{count}: sk size");
    assert_eq!(want_ct.len(), P::CIPHERTEXT_SIZE, "{ps} #{count}: ct size");

    // One DRBG instance per record, continuous across keygen and encaps,
    // exactly as PQCgenKAT_kem.c calls randombytes_init once per record.
    let rng = RefCell::new(NistKatRng::new(&seed).unwrap());
    let draw = |buf: &mut [u8]| rng.borrow_mut().randombytes_into(buf).unwrap();

    let (pk, sk) = generate_keypair_det::<P, _>(draw).unwrap();
    assert_eq!(pk.h, want_pk, "{ps} #{count}: public key mismatch");
    assert_eq!(sk.to_bytes(), want_sk, "{ps} #{count}: secret key mismatch");

    let (ct, ss) = encapsulate_det::<P, _>(&pk, draw).unwrap();
    assert_eq!(ct.c, want_ct, "{ps} #{count}: ciphertext mismatch");
    assert_eq!(&ss.ss[..], &want_ss[..], "{ps} #{count}: shared secret mismatch");

    let dec = decapsulate::<P>(&ct, &sk).unwrap();
    assert_eq!(&dec.ss[..], &want_ss[..], "{ps} #{count}: decapsulated shared secret mismatch");

    // Tamper control: a flipped ciphertext byte must not recover ss.
    let mut bad = ct.clone();
    bad.c[7] ^= 0x01;
    let dec_bad = decapsulate::<P>(&bad, &sk).unwrap();
    assert_ne!(&dec_bad.ss[..], &want_ss[..], "{ps} #{count}: tampered ciphertext accepted");
}

#[test]
fn upstream_ntru_plus_kat() {
    let doc = oracle();
    let vectors = doc["vectors"].as_array().expect("vectors array");
    let mut seen = [0usize; 3];
    for v in vectors {
        match v["param_set"].as_str().unwrap() {
            "ntruplus768" => { check::<NtruPlus768>(v); seen[0] += 1; }
            "ntruplus864" => { check::<NtruPlus864>(v); seen[1] += 1; }
            "ntruplus1152" => { check::<NtruPlus1152>(v); seen[2] += 1; }
            other => panic!("unexpected parameter set {other}"),
        }
    }
    assert_eq!(seen, [RECORDS_PER_SET; 3], "every parameter set must carry {RECORDS_PER_SET} records");
    assert_eq!(vectors.len(), doc["count"].as_u64().unwrap() as usize);
    println!("PASS NTRU+ upstream gate: {} genuine records across 3 parameter sets", vectors.len());
}
