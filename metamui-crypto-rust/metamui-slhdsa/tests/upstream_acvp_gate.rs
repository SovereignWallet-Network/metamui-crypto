//! Durable upstream conformance gate for SLH-DSA (FIPS 205).
//!
//! Reads the genuine NIST ACVP-Server vectors vendored under
//! `test-vectors/slh-dsa-upstream/` (a reduced subset of
//! `usnistgov/ACVP-Server/gen-val/json-files/SLH-DSA-*-FIPS205`) and asserts
//! this crate reproduces every expected result byte-for-byte across all 12
//! parameter sets (SHAKE + SHA2), both signature interfaces (external /
//! internal), both pre-hash modes (pure / preHash), and both deterministic and
//! hedged signing.
//!
//! Unlike the repo's historical `slh_dsa_*_vectors.json` (which were generated
//! *by this very crate* and therefore only proved self-consistency), these
//! vectors are an independent oracle: a mismatch is a genuine FIPS 205
//! non-conformance.

use metamui_slhdsa::params::Parameters;
use metamui_slhdsa::signing::{slh_sign_core, PreHashAlgorithm};
use metamui_slhdsa::verification::slh_verify_internal;
use metamui_slhdsa::*;
use serde_json::Value;
use std::path::PathBuf;

macro_rules! with_params {
    ($name:expr, $p:ident => $body:block) => {
        match $name {
            "SLH-DSA-SHAKE-128s" => { type $p = SlhDsa128s; $body }
            "SLH-DSA-SHAKE-128f" => { type $p = SlhDsa128f; $body }
            "SLH-DSA-SHAKE-192s" => { type $p = SlhDsa192s; $body }
            "SLH-DSA-SHAKE-192f" => { type $p = SlhDsa192f; $body }
            "SLH-DSA-SHAKE-256s" => { type $p = SlhDsa256s; $body }
            "SLH-DSA-SHAKE-256f" => { type $p = SlhDsa256f; $body }
            "SLH-DSA-SHA2-128s"  => { type $p = SlhDsa128sSha2; $body }
            "SLH-DSA-SHA2-128f"  => { type $p = SlhDsa128fSha2; $body }
            "SLH-DSA-SHA2-192s"  => { type $p = SlhDsa192sSha2; $body }
            "SLH-DSA-SHA2-192f"  => { type $p = SlhDsa192fSha2; $body }
            "SLH-DSA-SHA2-256s"  => { type $p = SlhDsa256sSha2; $body }
            "SLH-DSA-SHA2-256f"  => { type $p = SlhDsa256fSha2; $body }
            other => panic!("unknown parameter set: {other}"),
        }
    };
}

fn vectors_dir() -> PathBuf {
    // crate dir is metamui-crypto-rust/metamui-slhdsa; vectors live at repo root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/slh-dsa-upstream")
}

fn load(name: &str) -> Value {
    let p = vectors_dir().join(name);
    let s = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    serde_json::from_str(&s).unwrap()
}

fn hx(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap_or("")).expect("hex")
}

fn eq(got: &[u8], want: &str) -> bool {
    hex::encode(got) == want.to_ascii_lowercase()
}

fn m_prime(interface: &str, pre_hash: &str, ctx: &[u8], msg: &[u8], hash_alg: Option<&str>) -> Vec<u8> {
    if interface == "internal" {
        return msg.to_vec();
    }
    if pre_hash == "preHash" {
        let alg = PreHashAlgorithm::from_acvp_str(hash_alg.unwrap()).unwrap();
        let oid = alg.oid();
        let ph = alg.hash(msg);
        let mut m = vec![0x01, ctx.len() as u8];
        m.extend_from_slice(ctx);
        m.extend_from_slice(oid);
        m.extend_from_slice(&ph);
        m
    } else {
        let mut m = vec![0x00, ctx.len() as u8];
        m.extend_from_slice(ctx);
        m.extend_from_slice(msg);
        m
    }
}

fn ctx_of(t: &Value) -> Vec<u8> {
    if t.get("context").is_some() { hx(t, "context") } else { vec![] }
}

#[test]
fn upstream_keygen() {
    let prompt = load("keygen.json");
    for g in prompt["testGroups"].as_array().unwrap() {
        let ps = g["parameterSet"].as_str().unwrap();
        for t in g["tests"].as_array().unwrap() {
            let (ss, sp, pk_seed) = (hx(t, "skSeed"), hx(t, "skPrf"), hx(t, "pkSeed"));
            with_params!(ps, P => {
                let (pk, sk) = slh_keygen_from_seeds::<P>(&ss, &sp, &pk_seed).unwrap();
                assert!(eq(&pk, t["pk"].as_str().unwrap()),
                    "{ps} tc{}: pk mismatch", t["tcId"]);
                assert!(eq(&sk, t["sk"].as_str().unwrap()),
                    "{ps} tc{}: sk mismatch", t["tcId"]);
            });
        }
    }
}

#[test]
fn upstream_siggen() {
    let prompt = load("siggen.json");
    for g in prompt["testGroups"].as_array().unwrap() {
        let ps = g["parameterSet"].as_str().unwrap();
        let det = g["deterministic"].as_bool().unwrap();
        let iface = g["signatureInterface"].as_str().unwrap();
        let ph = g.get("preHash").and_then(|v| v.as_str()).unwrap_or("pure");
        for t in g["tests"].as_array().unwrap() {
            let sk = hx(t, "sk");
            let msg = hx(t, "message");
            let ctx = ctx_of(t);
            let ha = t.get("hashAlg").and_then(|v| v.as_str());
            let mp = m_prime(iface, ph, &ctx, &msg, ha);
            with_params!(ps, P => {
                let n = <P as Parameters>::N;
                let rand = if det { sk[2*n..3*n].to_vec() } else { hx(t, "additionalRandomness") };
                let sig = slh_sign_core::<P>(&sk[..n], &sk[n..2*n], &sk[2*n..3*n], &sk[3*n..4*n], &mp, &rand).unwrap();
                assert!(eq(&sig, t["signature"].as_str().unwrap()),
                    "{ps} tc{} (det={det},if={iface},ph={ph}): signature mismatch", t["tcId"]);
            });
        }
    }
}

#[test]
fn upstream_sigver() {
    let prompt = load("sigver.json");
    for g in prompt["testGroups"].as_array().unwrap() {
        let ps = g["parameterSet"].as_str().unwrap();
        let iface = g["signatureInterface"].as_str().unwrap();
        let ph = g.get("preHash").and_then(|v| v.as_str()).unwrap_or("pure");
        for t in g["tests"].as_array().unwrap() {
            let pk = if t.get("pk").is_some() { hx(t, "pk") } else { hx(g, "pk") };
            let msg = hx(t, "message");
            let ctx = ctx_of(t);
            let sig = hx(t, "signature");
            let ha = t.get("hashAlg").and_then(|v| v.as_str());
            let want = t["testPassed"].as_bool().unwrap();
            let mp = m_prime(iface, ph, &ctx, &msg, ha);
            with_params!(ps, P => {
                let n = <P as Parameters>::N;
                let got = slh_verify_internal::<P>(&pk[..n], &pk[n..2*n], &mp, &sig).is_ok();
                assert_eq!(got, want,
                    "{ps} tc{} (if={iface},ph={ph}): accept={got} want={want}", t["tcId"]);
            });
        }
    }
}
