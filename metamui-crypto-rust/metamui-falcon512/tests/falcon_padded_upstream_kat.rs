//! Genuine-upstream conformance gate for the Falcon **padded** signature profile.
//!
//! Oracle: PQClean `crypto_sign/falcon-padded-{512,1024}/clean` (Round-3
//! `falcon.h` FALCON_SIG_PADDED), whose only published conformance artefact is
//! `META.yml: nistkat-sha256`. `tools/falcon-padded-upstream-gen/genrun.sh`
//! rebuilds PQClean's `nistkat.c` harness against the vendored sources, refuses
//! to vendor anything whose SHA-256 differs from META.yml, and writes the record
//! to `test-vectors/falcon-upstream/falcon-padded-<n>/`.
//!
//! Record layout (PQClean `pqclean.c` `crypto_sign`):
//!   sm = | sig (CRYPTO_BYTES = 666 / 1280) | message |
//!   sig = 0x30+logn | nonce(40) | comp_encode(s2) | zero padding
//!
//! Hard gate: a missing or self-generated oracle FAILS (vectors are vendored;
//! absence is a regression). Every record must verify through `verify_padded`,
//! and a body tamper, a non-zero padding byte, and a length change must all be
//! rejected.

use std::path::PathBuf;

use metamui_falcon512::falcon1024::{verify_padded_1024, PublicKey1024};
use metamui_falcon512::{sizes, verify_padded, PublicKey};

const SELFGEN_MARKER: &str = "metamui-falcon512 Rust reference";

fn upstream_path(rel: &str) -> PathBuf {
    let mut p = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    for seg in ["..", "..", "test-vectors", "falcon-upstream", rel] {
        p.push(seg);
    }
    p
}

struct Record {
    pk: Vec<u8>,
    msg: Vec<u8>,
    sm: Vec<u8>,
}

fn parse_rsp(content: &str) -> Vec<Record> {
    let mut out = Vec::new();
    let (mut pk, mut msg, mut sm) = (None, None, None);
    let flush = |pk: &mut Option<Vec<u8>>, msg: &mut Option<Vec<u8>>, sm: &mut Option<Vec<u8>>, out: &mut Vec<Record>| {
        if let (Some(p), Some(s)) = (pk.take(), sm.take()) {
            out.push(Record { pk: p, msg: msg.take().unwrap_or_default(), sm: s });
        } else {
            let _ = msg.take();
        }
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            flush(&mut pk, &mut msg, &mut sm, &mut out);
            continue;
        }
        if let Some(v) = line.strip_prefix("pk = ") {
            pk = Some(hex::decode(v).expect("pk hex"));
        } else if let Some(v) = line.strip_prefix("msg = ") {
            msg = Some(hex::decode(v).expect("msg hex"));
        } else if let Some(v) = line.strip_prefix("sm = ") {
            sm = Some(hex::decode(v).expect("sm hex"));
        }
    }
    flush(&mut pk, &mut msg, &mut sm, &mut out);
    out
}

enum Variant {
    F512,
    F1024,
}

impl Variant {
    fn logn(&self) -> u8 {
        match self {
            Variant::F512 => 9,
            Variant::F1024 => 10,
        }
    }
    fn padded_len(&self) -> usize {
        match self {
            Variant::F512 => sizes::falcon512::SIG_PADDED,
            Variant::F1024 => sizes::falcon1024::SIG_PADDED,
        }
    }
    fn verify(&self, msg: &[u8], sig: &[u8], pk: &[u8]) -> Result<bool, String> {
        match self {
            Variant::F512 => {
                let pk = PublicKey::from_bytes(pk).map_err(|e| format!("pk: {e:?}"))?;
                verify_padded(msg, sig, &pk).map_err(|e| format!("verify_padded: {e:?}"))
            }
            Variant::F1024 => {
                let pk = PublicKey1024::from_bytes(pk).map_err(|e| format!("pk: {e:?}"))?;
                verify_padded_1024(msg, sig, &pk).map_err(|e| format!("verify_padded_1024: {e:?}"))
            }
        }
    }
}

fn run(variant: Variant, rel: &str, label: &str) {
    let path = upstream_path(rel);
    let content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{label}: genuine-upstream padded KAT missing at {} ({e}); regenerate with \
             tools/falcon-padded-upstream-gen/genrun.sh",
            path.display()
        )
    });
    assert!(
        !content.contains(SELFGEN_MARKER),
        "{label}: {} carries the self-generated marker; not a genuine oracle",
        path.display()
    );
    let records = parse_rsp(&content);
    assert!(!records.is_empty(), "{label}: no records in {}", path.display());

    let n = variant.padded_len();
    for (i, r) in records.iter().enumerate() {
        assert!(r.sm.len() >= n, "{label} record {i}: sm shorter than the padded signature");
        let (sig, msg) = r.sm.split_at(n);
        assert_eq!(msg, &r.msg[..], "{label} record {i}: sm-embedded message != msg field");
        assert_eq!(sig[0], 0x30 | variant.logn(), "{label} record {i}: header byte");

        // (a) genuine padded signature must verify
        assert_eq!(
            variant.verify(msg, sig, &r.pk),
            Ok(true),
            "{label} record {i}: genuine upstream padded signature rejected — algorithm divergence"
        );

        // (b) tamper inside the compressed body → reject
        let mut t = sig.to_vec();
        t[sizes::SIG_PREFIX_LEN] ^= 0x01;
        assert_ne!(variant.verify(msg, &t, &r.pk), Ok(true), "{label} record {i}: body tamper accepted");

        // (c) a non-zero byte in the padding → reject (InvalidPadding)
        let mut t = sig.to_vec();
        let last = t.len() - 1;
        assert_eq!(t[last], 0, "{label} record {i}: expected zero padding at the tail");
        t[last] = 0x01;
        assert_ne!(variant.verify(msg, &t, &r.pk), Ok(true), "{label} record {i}: non-zero padding accepted");

        // (d) wrong length (one byte short / one byte long) → reject
        assert_ne!(variant.verify(msg, &sig[..n - 1], &r.pk), Ok(true), "{label} record {i}: short signature accepted");
        let mut long = sig.to_vec();
        long.push(0);
        assert_ne!(variant.verify(msg, &long, &r.pk), Ok(true), "{label} record {i}: long signature accepted");
    }
    eprintln!("PASS {label}: {} genuine padded record(s) verified; tampers rejected", records.len());
}

#[test]
fn upstream_padded_verify_falcon512() {
    run(Variant::F512, "falcon-padded-512/falcon-padded-512-KAT.rsp", "Falcon-padded-512");
}

#[test]
fn upstream_padded_verify_falcon1024() {
    run(Variant::F1024, "falcon-padded-1024/falcon-padded-1024-KAT.rsp", "Falcon-padded-1024");
}

/// The upstream `sk` (NIST 1281-byte encoding) must load through the validated
/// import path and produce padded signatures of exactly the profile length that
/// verify — the same key material, our signer (not a byte-exact claim).
#[test]
fn upstream_padded_sk_loads_and_signs_falcon512() {
    let content = std::fs::read_to_string(upstream_path("falcon-padded-512/falcon-padded-512-KAT.rsp"))
        .expect("padded-512 oracle present");
    let sk_hex = content
        .lines()
        .find_map(|l| l.trim().strip_prefix("sk = "))
        .expect("sk field");
    let sk = metamui_falcon512::PrivateKey::from_bytes_validated(&hex::decode(sk_hex).unwrap())
        .expect("upstream sk must pass sigma-band validation");
    let pk_hex = content.lines().find_map(|l| l.trim().strip_prefix("pk = ")).unwrap();
    let pk = PublicKey::from_bytes(&hex::decode(pk_hex).unwrap()).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    use rand::SeedableRng;
    let msg = b"padded profile from the upstream key";
    let sig = metamui_falcon512::sign_padded(msg, &sk, &mut rng).expect("sign_padded");
    assert_eq!(sig.len(), sizes::falcon512::SIG_PADDED);
    assert_eq!(verify_padded(msg, &sig, &pk), Ok(true));
}
