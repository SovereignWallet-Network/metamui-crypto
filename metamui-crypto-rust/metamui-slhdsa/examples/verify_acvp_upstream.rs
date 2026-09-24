//! Genuine NIST ACVP conformance verifier for SLH-DSA (FIPS 205).
//!
//! Reads the official ACVP-Server vector files (`{keyGen,sigGen,sigVer}-prompt.json`
//! paired with `*-expectedResults.json`) and checks that this crate reproduces
//! every expected result byte-for-byte:
//!
//!   * keyGen  — (skSeed, skPrf, pkSeed) -> (sk, pk)
//!   * sigGen  — deterministic AND hedged, external/internal, pure/preHash
//!   * sigVer  — accept/reject must match `testPassed`
//!
//! Usage:
//!   cargo run -p metamui-slhdsa --example verify_acvp_upstream -- <dir>
//!
//! where <dir> contains keyGen-prompt.json, keyGen-expectedResults.json, etc.
//! Exits non-zero on any mismatch so it can be wired into CI.

use metamui_slhdsa::params::Parameters;
use metamui_slhdsa::signing::{slh_sign_core, PreHashAlgorithm};
use metamui_slhdsa::verification::slh_verify_internal;
use metamui_slhdsa::*;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;

/// Dispatch a runtime ACVP parameterSet string onto the matching concrete
/// `Parameters` type, binding it to `$p` inside `$body`.
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

fn h(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap_or("")).expect("hex")
}

/// ACVP-Server emits UPPERCASE hex; `hex::encode` emits lowercase. Compare
/// the expected (vector) hex against our lowercase output case-insensitively.
fn eq_hex(got: &[u8], want: &str) -> bool {
    hex::encode(got) == want.to_ascii_lowercase()
}

/// Build M' for the (interface, preHash) combination, per FIPS 205 §10.2.
fn build_m_prime(
    interface: &str,
    pre_hash: &str,
    context: &[u8],
    msg: &[u8],
    hash_alg: Option<&str>,
) -> Vec<u8> {
    if interface == "internal" {
        // Internal interface: message is consumed directly as M'.
        return msg.to_vec();
    }
    if pre_hash == "preHash" {
        let alg = PreHashAlgorithm::from_acvp_str(hash_alg.unwrap()).expect("hashAlg");
        let oid = alg.oid();
        let ph = alg.hash(msg);
        let mut m = Vec::with_capacity(2 + context.len() + oid.len() + ph.len());
        m.push(0x01);
        m.push(context.len() as u8);
        m.extend_from_slice(context);
        m.extend_from_slice(oid);
        m.extend_from_slice(&ph);
        m
    } else {
        let mut m = Vec::with_capacity(2 + context.len() + msg.len());
        m.push(0x00);
        m.push(context.len() as u8);
        m.extend_from_slice(context);
        m.extend_from_slice(msg);
        m
    }
}

/// Index expectedResults by tcId for O(1) lookup.
fn expected_by_tcid(exp: &Value) -> HashMap<u64, Value> {
    let mut map = HashMap::new();
    for g in exp["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            map.insert(t["tcId"].as_u64().unwrap(), t.clone());
        }
    }
    map
}

struct Tally {
    pass: usize,
    fail: usize,
}
impl Tally {
    fn new() -> Self {
        Self { pass: 0, fail: 0 }
    }
    fn ok(&mut self) {
        self.pass += 1;
    }
    fn bad(&mut self, msg: String) {
        self.fail += 1;
        if self.fail <= 10 {
            eprintln!("  FAIL: {msg}");
        }
    }
}

fn run_keygen(dir: &str, tally: &mut Tally) {
    let prompt: Value =
        serde_json::from_str(&fs::read_to_string(format!("{dir}/keyGen-prompt.json")).unwrap())
            .unwrap();
    let exp: Value = serde_json::from_str(
        &fs::read_to_string(format!("{dir}/keyGen-expectedResults.json")).unwrap(),
    )
    .unwrap();
    let exp = expected_by_tcid(&exp);

    for g in prompt["testGroups"].as_array().unwrap() {
        let ps = g["parameterSet"].as_str().unwrap();
        for t in g["tests"].as_array().unwrap() {
            let tc = t["tcId"].as_u64().unwrap();
            let sk_seed = h(t, "skSeed");
            let sk_prf = h(t, "skPrf");
            let pk_seed = h(t, "pkSeed");
            let e = &exp[&tc];
            let want_sk = e["sk"].as_str().unwrap();
            let want_pk = e["pk"].as_str().unwrap();

            with_params!(ps, P => {
                match slh_keygen_from_seeds::<P>(&sk_seed, &sk_prf, &pk_seed) {
                    Ok((pk, sk)) => {
                        if eq_hex(&sk, want_sk) && eq_hex(&pk, want_pk) {
                            tally.ok();
                        } else {
                            tally.bad(format!("keyGen {ps} tc{tc}: sk/pk mismatch"));
                        }
                    }
                    Err(e) => tally.bad(format!("keyGen {ps} tc{tc}: {e}")),
                }
            });
        }
    }
}

fn run_siggen(dir: &str, tally: &mut Tally) {
    let prompt: Value =
        serde_json::from_str(&fs::read_to_string(format!("{dir}/sigGen-prompt.json")).unwrap())
            .unwrap();
    let exp: Value = serde_json::from_str(
        &fs::read_to_string(format!("{dir}/sigGen-expectedResults.json")).unwrap(),
    )
    .unwrap();
    let exp = expected_by_tcid(&exp);

    for g in prompt["testGroups"].as_array().unwrap() {
        let ps = g["parameterSet"].as_str().unwrap();
        let deterministic = g["deterministic"].as_bool().unwrap();
        let interface = g["signatureInterface"].as_str().unwrap();
        let pre_hash = g.get("preHash").and_then(|v| v.as_str()).unwrap_or("pure");

        for t in g["tests"].as_array().unwrap() {
            let tc = t["tcId"].as_u64().unwrap();
            let full_sk = h(t, "sk");
            let msg = h(t, "message");
            let context = if t.get("context").is_some() {
                h(t, "context")
            } else {
                vec![]
            };
            let hash_alg = t.get("hashAlg").and_then(|v| v.as_str());

            let m_prime = build_m_prime(interface, pre_hash, &context, &msg, hash_alg);
            let want_sig = exp[&tc]["signature"].as_str().unwrap();

            with_params!(ps, P => {
                let n = <P as Parameters>::N;
                let sk_seed = &full_sk[..n];
                let sk_prf = &full_sk[n..2 * n];
                let pk_seed = &full_sk[2 * n..3 * n];
                let pk_root = &full_sk[3 * n..4 * n];
                // opt_rand: deterministic => PK.seed; hedged => additionalRandomness.
                let add_rand = if deterministic {
                    pk_seed.to_vec()
                } else {
                    h(t, "additionalRandomness")
                };
                match slh_sign_core::<P>(sk_seed, sk_prf, pk_seed, pk_root, &m_prime, &add_rand) {
                    Ok(sig) => {
                        if eq_hex(&sig, want_sig) {
                            tally.ok();
                        } else {
                            tally.bad(format!(
                                "sigGen {ps} tc{tc} (det={deterministic},if={interface},ph={pre_hash}): signature mismatch"
                            ));
                        }
                    }
                    Err(e) => tally.bad(format!("sigGen {ps} tc{tc}: {e}")),
                }
            });
        }
    }
}

fn run_sigver(dir: &str, tally: &mut Tally) {
    let prompt: Value =
        serde_json::from_str(&fs::read_to_string(format!("{dir}/sigVer-prompt.json")).unwrap())
            .unwrap();
    let exp: Value = serde_json::from_str(
        &fs::read_to_string(format!("{dir}/sigVer-expectedResults.json")).unwrap(),
    )
    .unwrap();
    let exp = expected_by_tcid(&exp);

    for g in prompt["testGroups"].as_array().unwrap() {
        let ps = g["parameterSet"].as_str().unwrap();
        let interface = g["signatureInterface"].as_str().unwrap();
        let pre_hash = g.get("preHash").and_then(|v| v.as_str()).unwrap_or("pure");

        for t in g["tests"].as_array().unwrap() {
            let tc = t["tcId"].as_u64().unwrap();
            // Each sigVer test group carries its own pk (some put it on the group).
            let pk = if t.get("pk").is_some() {
                h(t, "pk")
            } else {
                h(g, "pk")
            };
            let msg = h(t, "message");
            let context = if t.get("context").is_some() {
                h(t, "context")
            } else {
                vec![]
            };
            let sig = h(t, "signature");
            let hash_alg = t.get("hashAlg").and_then(|v| v.as_str());
            let want = exp[&tc]["testPassed"].as_bool().unwrap();

            let m_prime = build_m_prime(interface, pre_hash, &context, &msg, hash_alg);

            with_params!(ps, P => {
                let n = <P as Parameters>::N;
                if pk.len() != 2 * n {
                    tally.bad(format!("sigVer {ps} tc{tc}: bad pk len"));
                    continue;
                }
                let pk_seed = &pk[..n];
                let pk_root = &pk[n..2 * n];
                let got = slh_verify_internal::<P>(pk_seed, pk_root, &m_prime, &sig).is_ok();
                if got == want {
                    tally.ok();
                } else {
                    tally.bad(format!(
                        "sigVer {ps} tc{tc} (if={interface},ph={pre_hash}): got accept={got} want={want}"
                    ));
                }
            });
        }
    }
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/acvp-slhdsa".into());
    eprintln!("== SLH-DSA genuine ACVP conformance ({dir}) ==");

    let mut totals = Tally::new();
    for (name, f) in [
        ("keyGen", run_keygen as fn(&str, &mut Tally)),
        ("sigGen", run_siggen),
        ("sigVer", run_sigver),
    ] {
        let mut t = Tally::new();
        f(dir.as_str(), &mut t);
        eprintln!("{name:8}: {} passed, {} failed", t.pass, t.fail);
        totals.pass += t.pass;
        totals.fail += t.fail;
    }
    eprintln!("TOTAL   : {} passed, {} failed", totals.pass, totals.fail);
    if totals.fail > 0 {
        std::process::exit(1);
    }
}
