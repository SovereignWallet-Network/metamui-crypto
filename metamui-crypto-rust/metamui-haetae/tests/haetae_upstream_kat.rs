//! Genuine upstream KAT conformance gate for HAETAE v1.2.0 (spec v260825).
//!
//! Replays the official `PQCgenKAT_sign.c` seed stream with the NIST
//! AES-256-CTR-DRBG (no DF) and checks that this binding reproduces the
//! reference `pk`/`sk`/`sig` **byte-for-byte**. Unlike `test-vectors/haetae/`
//! (self-generated consensus fixtures), these `.rsp` files are the unmodified
//! reference output — see `test-vectors/haetae-upstream/README.md`.
//!
//! `v1_1_2_signatures_still_verify` replays the previous release's (1.1.2)
//! signatures verify-only: v1.2.0 changed only the hyperball sampler, so keys
//! and the verifier are unchanged and every 1.1.2 signature must still verify
//! — while no longer being what this binding produces.
//!
//! Run one mode at a time (the crate is compile-time mode-selected):
//!   cargo test -p metamui-haetae --no-default-features --features haetae2,std --test haetae_upstream_kat
//!   cargo test -p metamui-haetae --no-default-features --features haetae3,std --test haetae_upstream_kat
//!   cargo test -p metamui-haetae --no-default-features --features haetae5,std --test haetae_upstream_kat

use std::path::PathBuf;

use metamui_aes_ctr_drbg::NistKatRng;
use metamui_haetae::params::{CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};
use metamui_haetae::sign::{
    crypto_sign_keypair_internal, crypto_sign_signature_internal, crypto_sign_verify_internal,
};

#[cfg(feature = "haetae2")]
const MODE: u8 = 2;
#[cfg(feature = "haetae3")]
const MODE: u8 = 3;
#[cfg(feature = "haetae5")]
const MODE: u8 = 5;

fn rsp_path() -> PathBuf {
    rsp_path_in(None)
}

/// `subdir = Some("v1.1.2-verify-only")` selects the previous release's set.
fn rsp_path_in(subdir: Option<&str>) -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let mut p = PathBuf::from(manifest);
    p.push("..");
    p.push("..");
    p.push("test-vectors");
    p.push("haetae-upstream");
    if let Some(d) = subdir {
        p.push(d);
    }
    p.push(format!("haetae{MODE}"));
    p.push(format!("PQCsignKAT_haetae_mode{MODE}.rsp"));
    p
}

struct Vector {
    count: usize,
    seed: Vec<u8>,
    msg: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    sig: Vec<u8>,
}

fn hexval(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Minimal NIST `.rsp` parser: groups the `key = value` lines into records.
fn parse_rsp(text: &str) -> Vec<Vector> {
    let mut out = Vec::new();
    let (mut count, mut seed, mut msg, mut pk, mut sk, mut sig) =
        (None, None, None, None, None, None);
    let flush = |count: &mut Option<usize>,
                 seed: &mut Option<Vec<u8>>,
                 msg: &mut Option<Vec<u8>>,
                 pk: &mut Option<Vec<u8>>,
                 sk: &mut Option<Vec<u8>>,
                 sig: &mut Option<Vec<u8>>,
                 out: &mut Vec<Vector>| {
        if let (Some(c), Some(se), Some(m), Some(p), Some(s), Some(g)) =
            (count.take(), seed.take(), msg.take(), pk.take(), sk.take(), sig.take())
        {
            out.push(Vector { count: c, seed: se, msg: m, pk: p, sk: s, sig: g });
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("count = ") {
            // a new record begins; flush any complete previous one
            flush(&mut count, &mut seed, &mut msg, &mut pk, &mut sk, &mut sig, &mut out);
            count = Some(v.trim().parse().unwrap());
        } else if let Some(v) = line.strip_prefix("seed = ") {
            seed = Some(hexval(v));
        } else if let Some(v) = line.strip_prefix("msg = ") {
            msg = Some(hexval(v));
        } else if let Some(v) = line.strip_prefix("pk = ") {
            pk = Some(hexval(v));
        } else if let Some(v) = line.strip_prefix("sk = ") {
            sk = Some(hexval(v));
        } else if let Some(v) = line.strip_prefix("sig = ") {
            sig = Some(hexval(v));
        }
    }
    flush(&mut count, &mut seed, &mut msg, &mut pk, &mut sk, &mut sig, &mut out);
    out
}

#[test]
fn upstream_kat_byte_exact() {
    let path = rsp_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let vectors = parse_rsp(&text);
    assert_eq!(vectors.len(), 100, "expected 100 KAT records for mode{MODE}");

    for v in &vectors {
        // Replay the PQCgenKAT_sign.c draw order from the 48-byte per-count seed.
        let mut rng = NistKatRng::new(&v.seed).expect("DRBG init");
        let keygen_seed = rng.randombytes(32).unwrap();
        let rnd = rng.randombytes(32).unwrap();
        let ctxlen = rng.randombytes(1).unwrap()[0] as usize;
        let ctx = rng.randombytes(ctxlen).unwrap();
        let mut pre = Vec::with_capacity(1 + ctxlen);
        pre.push(ctxlen as u8);
        pre.extend_from_slice(&ctx);

        // --- KeyGen -------------------------------------------------------
        let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
        let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
        let seed_arr: [u8; 32] = keygen_seed.clone().try_into().unwrap();
        assert_eq!(crypto_sign_keypair_internal(&mut pk, &mut sk, &seed_arr), 0);
        assert_eq!(pk.as_slice(), v.pk.as_slice(), "pk mismatch count={}", v.count);
        assert_eq!(sk.as_slice(), v.sk.as_slice(), "sk mismatch count={}", v.count);

        // --- Sign (detached, context-bound, hedged) ----------------------
        let mut sig = [0u8; CRYPTO_BYTES];
        let mut siglen = 0usize;
        let rnd_arr: [u8; 32] = rnd.clone().try_into().unwrap();
        assert_eq!(
            crypto_sign_signature_internal(
                &mut sig, &mut siglen, &v.msg, v.msg.len(), &pre, &rnd_arr, &sk,
            ),
            0
        );
        assert_eq!(siglen, CRYPTO_BYTES);
        assert_eq!(sig.as_slice(), v.sig.as_slice(), "sig mismatch count={}", v.count);

        // --- Verify -------------------------------------------------------
        assert_eq!(
            crypto_sign_verify_internal(&sig, siglen, &v.msg, v.msg.len(), &pre, &pk),
            0,
            "verify failed count={}",
            v.count
        );
    }
}

/// Verify-only regression over the HAETAE 1.1.2 KAT: same seeds, same keys,
/// signatures produced by the previous sampler. They must verify (the
/// verifier did not change) and must differ from the v1.2.0 record for the
/// same count (the sampler did).
#[test]
fn v1_1_2_signatures_still_verify() {
    let old_path = rsp_path_in(Some("v1.1.2-verify-only"));
    let old_text = std::fs::read_to_string(&old_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", old_path.display()));
    let old = parse_rsp(&old_text);
    let new = parse_rsp(&std::fs::read_to_string(rsp_path()).unwrap());
    assert_eq!(old.len(), 100, "expected 100 v1.1.2 records for mode{MODE}");
    assert_eq!(new.len(), 100);

    let mut differing = 0usize;
    for (o, n) in old.iter().zip(new.iter()) {
        assert_eq!(o.count, n.count);
        assert_eq!(o.seed, n.seed, "seed stream changed between releases? count={}", o.count);
        assert_eq!(o.pk, n.pk, "pk changed between 1.1.2 and 1.2.0; count={}", o.count);
        assert_eq!(o.sk, n.sk, "sk changed between 1.1.2 and 1.2.0; count={}", o.count);
        assert_eq!(o.msg, n.msg);

        let mut rng = NistKatRng::new(&o.seed).expect("DRBG init");
        let _keygen_seed = rng.randombytes(32).unwrap();
        let _rnd = rng.randombytes(32).unwrap();
        let ctxlen = rng.randombytes(1).unwrap()[0] as usize;
        let ctx = rng.randombytes(ctxlen).unwrap();
        let mut pre = Vec::with_capacity(1 + ctxlen);
        pre.push(ctxlen as u8);
        pre.extend_from_slice(&ctx);

        let pk: [u8; CRYPTO_PUBLICKEYBYTES] = o.pk.clone().try_into().unwrap();
        let sig: [u8; CRYPTO_BYTES] = o.sig.clone().try_into().unwrap_or_else(|_| {
            panic!("1.1.2 sig length {} != CRYPTO_BYTES; count={}", o.sig.len(), o.count)
        });
        assert_eq!(
            crypto_sign_verify_internal(&sig, sig.len(), &o.msg, o.msg.len(), &pre, &pk),
            0,
            "1.1.2 signature no longer verifies; count={}",
            o.count
        );
        if o.sig != n.sig {
            differing += 1;
        }
    }
    assert_eq!(
        differing, 100,
        "the 1.1.2 and 1.2.0 signature sets must differ on every record (sampler change)"
    );
}
