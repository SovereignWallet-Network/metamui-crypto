//! Genuine NIST ACVP (FIPS 204) conformance gate for ML-DSA.
//!
//! Unlike `ml_dsa_test_vectors.rs` (keyGen only) this exercises the real
//! `usnistgov/ACVP-Server` keyGen + sigGen + sigVer vectors mirrored under
//! `test-vectors/ml-dsa-upstream/`. It answers the question the keyGen-only
//! gate could not: does our signing/verification reproduce NIST's bytes?
//!
//! Coverage: the full FIPS 204 ACVP interface surface — keyGen; sigGen and
//! sigVer for external "pure" (incl. non-empty context), HashML-DSA pre-hash
//! (SHA2/SHA3/SHAKE with the FIPS 204 OID prefix), the internal interface, and
//! externally-supplied μ (externalMu), in both deterministic and hedged
//! (explicit `rnd`) modes — via Dilithium{2,3,5}::{sign_with_context,
//! sign_internal, sign_external_mu, hash_sign} and the verify counterparts.

use metamui_dilithium::{Dilithium2, Dilithium3, Dilithium5};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

fn gate_path(name: &str) -> PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for prefix in &["../..", "../../.."] {
        let p = manifest.join(prefix).join("test-vectors/ml-dsa-upstream").join(name);
        if p.exists() {
            return p;
        }
    }
    panic!("gate file not found: {}", name);
}

#[derive(Deserialize)]
struct File {
    #[serde(rename = "testGroups")]
    test_groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Group {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(default)]
    deterministic: bool,
    #[serde(default, rename = "signatureInterface")]
    signature_interface: String,
    #[serde(default, rename = "preHash")]
    pre_hash: String,
    #[serde(default, rename = "externalMu")]
    external_mu: bool,
    tests: Vec<Test>,
}

#[derive(Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(default)]
    seed: Option<String>,
    #[serde(default)]
    pk: Option<String>,
    #[serde(default)]
    sk: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    mu: Option<String>,
    #[serde(default)]
    rnd: Option<String>,
    #[serde(default, rename = "hashAlg")]
    hash_alg: Option<String>,
    #[serde(default, rename = "testPassed")]
    test_passed: Option<bool>,
}

/// FIPS 204 HashML-DSA pre-hash: return (DER OID, PH(message)) for the named
/// algorithm. SHAKE-128/256 use 256/512-bit outputs per FIPS 204.
fn ph_oid_digest(hash_alg: &str, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use sha2::Digest as _;
    fn oid(last: u8) -> Vec<u8> {
        vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last]
    }
    match hash_alg {
        "SHA2-224" => (oid(0x04), sha2::Sha224::digest(msg).to_vec()),
        "SHA2-256" => (oid(0x01), sha2::Sha256::digest(msg).to_vec()),
        "SHA2-384" => (oid(0x02), sha2::Sha384::digest(msg).to_vec()),
        "SHA2-512" => (oid(0x03), sha2::Sha512::digest(msg).to_vec()),
        "SHA2-512/224" => (oid(0x05), sha2::Sha512_224::digest(msg).to_vec()),
        "SHA2-512/256" => (oid(0x06), sha2::Sha512_256::digest(msg).to_vec()),
        "SHA3-224" => (oid(0x07), { use sha3::Digest as _; sha3::Sha3_224::digest(msg).to_vec() }),
        "SHA3-256" => (oid(0x08), { use sha3::Digest as _; sha3::Sha3_256::digest(msg).to_vec() }),
        "SHA3-384" => (oid(0x09), { use sha3::Digest as _; sha3::Sha3_384::digest(msg).to_vec() }),
        "SHA3-512" => (oid(0x0A), { use sha3::Digest as _; sha3::Sha3_512::digest(msg).to_vec() }),
        "SHAKE-128" => {
            use sha3::digest::{Update, ExtendableOutput, XofReader};
            let mut x = sha3::Shake128::default();
            x.update(msg);
            let mut r = x.finalize_xof();
            let mut out = vec![0u8; 32]; // 256 bits
            r.read(&mut out);
            (oid(0x0B), out)
        }
        "SHAKE-256" => {
            use sha3::digest::{Update, ExtendableOutput, XofReader};
            let mut x = sha3::Shake256::default();
            x.update(msg);
            let mut r = x.finalize_xof();
            let mut out = vec![0u8; 64]; // 512 bits
            r.read(&mut out);
            (oid(0x0C), out)
        }
        other => panic!("unsupported preHash alg {other}"),
    }
}

fn rnd32(t: &Test) -> [u8; 32] {
    match &t.rnd {
        Some(s) => hx(s).try_into().expect("rnd must be 32 bytes"),
        None => [0u8; 32], // deterministic
    }
}

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

/// RNG that hands back a fixed seed on the first `fill_bytes`, then zeros.
/// Lets us drive `generate_keypair_with_rng` deterministically from an ACVP seed.
struct SeedRng {
    seed: [u8; 32],
    used: bool,
}
impl rand_core::RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if !self.used && dest.len() == 32 {
            dest.copy_from_slice(&self.seed);
            self.used = true;
        } else {
            dest.fill(0);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rand_core::CryptoRng for SeedRng {}

fn seed_rng(seed: &[u8]) -> SeedRng {
    SeedRng { seed: seed.try_into().unwrap(), used: false }
}

fn load(name: &str) -> File {
    serde_json::from_str(&fs::read_to_string(gate_path(name)).unwrap()).unwrap()
}

/// keyGen: seed -> (pk, sk) byte-for-byte for all three levels.
#[test]
fn acvp_keygen_byte_exact() {
    let f = load("keygen.json");
    let mut n = 0;
    for g in &f.test_groups {
        for t in &g.tests {
            let seed = hx(t.seed.as_ref().unwrap());
            let (pk, sk): (Vec<u8>, Vec<u8>) = match g.parameter_set.as_str() {
                "ML-DSA-44" => {
                    let (p, s) = Dilithium2::generate_keypair_with_rng(&mut seed_rng(&seed));
                    (p.to_vec(), s.to_vec())
                }
                "ML-DSA-65" => {
                    let (p, s) = Dilithium3::generate_keypair_with_rng(&mut seed_rng(&seed));
                    (p.to_vec(), s.to_vec())
                }
                "ML-DSA-87" => {
                    let (p, s) = Dilithium5::generate_keypair_with_rng(&mut seed_rng(&seed));
                    (p.to_vec(), s.to_vec())
                }
                other => panic!("unknown set {other}"),
            };
            assert_eq!(hex::encode_upper(&pk), t.pk.as_ref().unwrap().to_uppercase(),
                       "{} tcId {} pk mismatch", g.parameter_set, t.tc_id);
            assert_eq!(hex::encode_upper(&sk), t.sk.as_ref().unwrap().to_uppercase(),
                       "{} tcId {} sk mismatch", g.parameter_set, t.tc_id);
            n += 1;
        }
    }
    assert!(n >= 9, "expected >=9 keyGen cases, ran {n}");
    eprintln!("ACVP keyGen byte-exact: {n} cases");
}

/// sigGen: deterministic + external + pure -> signature bytes, INCLUDING
/// non-empty context strings (exercises sign_with_context).
#[test]
fn acvp_siggen_byte_exact_reachable() {
    run_siggen_reachable("siggen.json");
}

#[test]
fn acvp_tr1_siggen_byte_exact_reachable() {
    run_siggen_reachable("siggen-tr1.json");
}

fn run_siggen_reachable(file: &str) {
    let f = load(file);
    let mut n = 0;
    let mut ctx_cases = 0;
    for g in &f.test_groups {
        if !(g.deterministic
            && g.signature_interface == "external"
            && g.pre_hash == "pure"
            && !g.external_mu)
        {
            continue;
        }
        for t in &g.tests {
            let sk = hx(t.sk.as_ref().unwrap());
            let msg = hx(t.message.as_ref().unwrap());
            let ctx = hx(t.context.as_deref().unwrap_or(""));
            if !ctx.is_empty() { ctx_cases += 1; }
            let expected = t.signature.as_ref().unwrap().to_uppercase();
            let got = match g.parameter_set.as_str() {
                "ML-DSA-44" => hex::encode_upper(Dilithium2::sign_with_context(sk.as_slice().try_into().unwrap(), &msg, &ctx)),
                "ML-DSA-65" => hex::encode_upper(Dilithium3::sign_with_context(sk.as_slice().try_into().unwrap(), &msg, &ctx)),
                "ML-DSA-87" => hex::encode_upper(Dilithium5::sign_with_context(sk.as_slice().try_into().unwrap(), &msg, &ctx)),
                other => panic!("unknown set {other}"),
            };
            assert_eq!(got, expected, "{} tcId {} signature mismatch (ctxlen {})", g.parameter_set, t.tc_id, ctx.len());
            n += 1;
        }
    }
    assert!(n >= 6, "expected >=6 reachable sigGen cases, ran {n}");
    assert!(ctx_cases >= 3, "expected >=3 non-empty-context sigGen cases, ran {ctx_cases}");
    eprintln!("ACVP sigGen byte-exact: {n} cases ({ctx_cases} with non-empty context)");
}

/// sigVer: verify_with_context(pk, msg, sig, ctx) == testPassed, external + pure,
/// INCLUDING non-empty context strings.
#[test]
fn acvp_sigver_matches_expected() {
    let f = load("sigver.json");
    let mut n = 0;
    let mut ctx_cases = 0;
    for g in &f.test_groups {
        if !(g.signature_interface == "external" && g.pre_hash == "pure" && !g.external_mu) {
            continue;
        }
        for t in &g.tests {
            let pk = hx(t.pk.as_ref().unwrap());
            let msg = hx(t.message.as_ref().unwrap());
            let sig = hx(t.signature.as_ref().unwrap());
            let ctx = hx(t.context.as_deref().unwrap_or(""));
            if !ctx.is_empty() { ctx_cases += 1; }
            let expect = t.test_passed.unwrap();
            let got = match g.parameter_set.as_str() {
                "ML-DSA-44" => Dilithium2::verify_with_context(pk.as_slice().try_into().unwrap(), &msg, &sig, &ctx),
                "ML-DSA-65" => Dilithium3::verify_with_context(pk.as_slice().try_into().unwrap(), &msg, &sig, &ctx),
                "ML-DSA-87" => Dilithium5::verify_with_context(pk.as_slice().try_into().unwrap(), &msg, &sig, &ctx),
                other => panic!("unknown set {other}"),
            };
            assert_eq!(got, expect, "{} tcId {} verify expected {} got {} (ctxlen {})", g.parameter_set, t.tc_id, expect, got, ctx.len());
            n += 1;
        }
    }
    assert!(n >= 12, "expected >=12 sigVer cases, ran {n}");
    assert!(ctx_cases >= 3, "expected >=3 non-empty-context sigVer cases, ran {ctx_cases}");
    eprintln!("ACVP sigVer matches expected: {n} cases ({ctx_cases} with non-empty context)");
}

/// Regression: unpack_hint must reject non-canonical (non-strictly-increasing)
/// hint encodings per FIPS 204 Alg 21 — the "strong unforgeability" guard that
/// was previously a no-op stub.
#[test]
fn unpack_hint_rejects_malformed() {
    use metamui_dilithium::operations::unpack_hint;
    use metamui_dilithium::params::DILITHIUM2_PARAMS;
    let omega = DILITHIUM2_PARAMS.omega as usize; // 80
    let k = DILITHIUM2_PARAMS.k as usize;         // 4
    let mut data = vec![0u8; omega + k];
    // Poly 0: two positions that are NOT strictly increasing (5 then 5).
    data[0] = 5;
    data[1] = 5;
    data[omega + 0] = 2; // cumulative count for poly 0 = 2
    data[omega + 1] = 2; // poly 1..3 empty
    data[omega + 2] = 2;
    data[omega + 3] = 2;
    assert!(unpack_hint(&data, &DILITHIUM2_PARAMS).is_err(),
            "non-strictly-increasing hint positions must be rejected");

    // Canonical version (5 then 7) must be accepted.
    let mut ok = vec![0u8; omega + k];
    ok[0] = 5; ok[1] = 7;
    ok[omega + 0] = 2; ok[omega + 1] = 2; ok[omega + 2] = 2; ok[omega + 3] = 2;
    assert!(unpack_hint(&ok, &DILITHIUM2_PARAMS).is_ok(),
            "canonical strictly-increasing hint must be accepted");

    // Non-zero trailing padding must be rejected.
    let mut pad = ok.clone();
    pad[2] = 9; // a byte in [index..omega) that should be zero
    assert!(unpack_hint(&pad, &DILITHIUM2_PARAMS).is_err(),
            "non-zero trailing hint padding must be rejected");
}

// --- Per-level dispatch helpers for the full ACVP interface surface ---

fn sk2(sk: &[u8]) -> &[u8; Dilithium2::SECRET_KEY_SIZE] { sk.try_into().unwrap() }
fn sk3(sk: &[u8]) -> &[u8; Dilithium3::SECRET_KEY_SIZE] { sk.try_into().unwrap() }
fn sk5(sk: &[u8]) -> &[u8; Dilithium5::SECRET_KEY_SIZE] { sk.try_into().unwrap() }
fn pk2(pk: &[u8]) -> &[u8; Dilithium2::PUBLIC_KEY_SIZE] { pk.try_into().unwrap() }
fn pk3(pk: &[u8]) -> &[u8; Dilithium3::PUBLIC_KEY_SIZE] { pk.try_into().unwrap() }
fn pk5(pk: &[u8]) -> &[u8; Dilithium5::PUBLIC_KEY_SIZE] { pk.try_into().unwrap() }

fn sign_internal_lvl(ps: &str, sk: &[u8], mp: &[u8], rnd: &[u8; 32]) -> Vec<u8> {
    match ps {
        "ML-DSA-44" => Dilithium2::sign_internal(sk2(sk), mp, rnd).to_vec(),
        "ML-DSA-65" => Dilithium3::sign_internal(sk3(sk), mp, rnd).to_vec(),
        "ML-DSA-87" => Dilithium5::sign_internal(sk5(sk), mp, rnd).to_vec(),
        o => panic!("{o}"),
    }
}
fn sign_extmu_lvl(ps: &str, sk: &[u8], mu: &[u8; 64], rnd: &[u8; 32]) -> Vec<u8> {
    match ps {
        "ML-DSA-44" => Dilithium2::sign_external_mu(sk2(sk), mu, rnd).to_vec(),
        "ML-DSA-65" => Dilithium3::sign_external_mu(sk3(sk), mu, rnd).to_vec(),
        "ML-DSA-87" => Dilithium5::sign_external_mu(sk5(sk), mu, rnd).to_vec(),
        o => panic!("{o}"),
    }
}
fn hash_sign_lvl(ps: &str, sk: &[u8], oid: &[u8], phm: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Vec<u8> {
    match ps {
        "ML-DSA-44" => Dilithium2::hash_sign(sk2(sk), oid, phm, ctx, rnd).to_vec(),
        "ML-DSA-65" => Dilithium3::hash_sign(sk3(sk), oid, phm, ctx, rnd).to_vec(),
        "ML-DSA-87" => Dilithium5::hash_sign(sk5(sk), oid, phm, ctx, rnd).to_vec(),
        o => panic!("{o}"),
    }
}
fn verify_internal_lvl(ps: &str, pk: &[u8], mp: &[u8], sig: &[u8]) -> bool {
    match ps {
        "ML-DSA-44" => Dilithium2::verify_internal(pk2(pk), mp, sig),
        "ML-DSA-65" => Dilithium3::verify_internal(pk3(pk), mp, sig),
        "ML-DSA-87" => Dilithium5::verify_internal(pk5(pk), mp, sig),
        o => panic!("{o}"),
    }
}
fn verify_extmu_lvl(ps: &str, pk: &[u8], mu: &[u8; 64], sig: &[u8]) -> bool {
    match ps {
        "ML-DSA-44" => Dilithium2::verify_external_mu(pk2(pk), mu, sig),
        "ML-DSA-65" => Dilithium3::verify_external_mu(pk3(pk), mu, sig),
        "ML-DSA-87" => Dilithium5::verify_external_mu(pk5(pk), mu, sig),
        o => panic!("{o}"),
    }
}
fn hash_verify_lvl(ps: &str, pk: &[u8], oid: &[u8], phm: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    match ps {
        "ML-DSA-44" => Dilithium2::hash_verify(pk2(pk), oid, phm, ctx, sig),
        "ML-DSA-65" => Dilithium3::hash_verify(pk3(pk), oid, phm, ctx, sig),
        "ML-DSA-87" => Dilithium5::hash_verify(pk5(pk), oid, phm, ctx, sig),
        o => panic!("{o}"),
    }
}

fn mprime_external(t: &Test) -> Vec<u8> {
    let ctx = hx(t.context.as_deref().unwrap_or(""));
    let msg = hx(t.message.as_ref().unwrap());
    let mut mp = Vec::with_capacity(2 + ctx.len() + msg.len());
    mp.extend_from_slice(&[0u8, ctx.len() as u8]);
    mp.extend_from_slice(&ctx);
    mp.extend_from_slice(&msg);
    mp
}

/// Full sigGen surface: external pure + preHash + internal + externalMu, both
/// deterministic and hedged (explicit rnd), all three levels.
#[test]
fn acvp_siggen_all_interfaces() {
    run_siggen_all_interfaces("siggen.json");
}

/// NIST ACVP revision FIPS204-tr1 (`siggen-tr1.json`, 48 groups: the same 8
/// interface kinds × deterministic/hedged × 3 sets, trimmed to 2 tests each).
#[test]
fn acvp_tr1_siggen_all_interfaces() {
    run_siggen_all_interfaces("siggen-tr1.json");
}

fn run_siggen_all_interfaces(file: &str) {
    let f = load(file);
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for g in &f.test_groups {
        let kind = format!("{}/{}/extMu={}/det={}", g.signature_interface, g.pre_hash, g.external_mu, g.deterministic);
        for t in &g.tests {
            let sk = hx(t.sk.as_ref().unwrap());
            let rnd = rnd32(t);
            let expected = t.signature.as_ref().unwrap().to_uppercase();
            let got = match (g.signature_interface.as_str(), g.pre_hash.as_str(), g.external_mu) {
                ("external", "pure", false) => sign_internal_lvl(&g.parameter_set, &sk, &mprime_external(t), &rnd),
                ("external", "preHash", false) => {
                    let ctx = hx(t.context.as_deref().unwrap_or(""));
                    let (oid, phm) = ph_oid_digest(t.hash_alg.as_ref().unwrap(), &hx(t.message.as_ref().unwrap()));
                    hash_sign_lvl(&g.parameter_set, &sk, &oid, &phm, &ctx, &rnd)
                }
                ("internal", _, false) => sign_internal_lvl(&g.parameter_set, &sk, &hx(t.message.as_ref().unwrap()), &rnd),
                ("internal", _, true) => {
                    let mu: [u8; 64] = hx(t.mu.as_ref().unwrap()).try_into().unwrap();
                    sign_extmu_lvl(&g.parameter_set, &sk, &mu, &rnd)
                }
                other => panic!("unhandled sigGen group {other:?}"),
            };
            assert_eq!(hex::encode_upper(&got), expected,
                "{} tcId {} [{}] signature mismatch", g.parameter_set, t.tc_id, kind);
            *counts.entry(kind.clone()).or_insert(0) += 1;
        }
    }
    eprintln!("ACVP sigGen all interfaces: {counts:?}");
    assert!(counts.len() >= 8, "expected all 8 sigGen group kinds, got {}", counts.len());
}

/// Full sigVer surface across all interface variants.
#[test]
fn acvp_sigver_all_interfaces() {
    let f = load("sigver.json");
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for g in &f.test_groups {
        let kind = format!("{}/{}/extMu={}", g.signature_interface, g.pre_hash, g.external_mu);
        for t in &g.tests {
            let pk = hx(t.pk.as_ref().unwrap());
            let sig = hx(t.signature.as_ref().unwrap());
            let expect = t.test_passed.unwrap();
            let got = match (g.signature_interface.as_str(), g.pre_hash.as_str(), g.external_mu) {
                ("external", "pure", false) => verify_internal_lvl(&g.parameter_set, &pk, &mprime_external(t), &sig),
                ("external", "preHash", false) => {
                    let ctx = hx(t.context.as_deref().unwrap_or(""));
                    let (oid, phm) = ph_oid_digest(t.hash_alg.as_ref().unwrap(), &hx(t.message.as_ref().unwrap()));
                    hash_verify_lvl(&g.parameter_set, &pk, &oid, &phm, &ctx, &sig)
                }
                ("internal", _, false) => verify_internal_lvl(&g.parameter_set, &pk, &hx(t.message.as_ref().unwrap()), &sig),
                ("internal", _, true) => {
                    let mu: [u8; 64] = hx(t.mu.as_ref().unwrap()).try_into().unwrap();
                    verify_extmu_lvl(&g.parameter_set, &pk, &mu, &sig)
                }
                other => panic!("unhandled sigVer group {other:?}"),
            };
            assert_eq!(got, expect,
                "{} tcId {} [{}] verify expected {} got {}", g.parameter_set, t.tc_id, kind, expect, got);
            *counts.entry(kind.clone()).or_insert(0) += 1;
        }
    }
    eprintln!("ACVP sigVer all interfaces: {counts:?}");
    assert!(counts.len() >= 4, "expected all 4 sigVer group kinds, got {}", counts.len());
}

/// `hash_sign_with` / `hash_verify_with` (the shared `metamui-prehash-oids`
/// table) reproduce the ACVP preHash groups exactly as the OID/PH pair does.
#[test]
fn prehash_table_matches_acvp_prehash_groups() {
    use metamui_prehash_oids::PreHashAlgorithm;
    let f = load("siggen-tr1.json");
    let mut n = 0;
    for g in f.test_groups.iter().filter(|g| g.pre_hash == "preHash") {
        for t in &g.tests {
            let alg = PreHashAlgorithm::from_acvp_str(t.hash_alg.as_ref().unwrap()).unwrap();
            let sk = hx(t.sk.as_ref().unwrap());
            let pk = hx(t.pk.as_ref().unwrap());
            let msg = hx(t.message.as_ref().unwrap());
            let ctx = hx(t.context.as_deref().unwrap_or(""));
            let rnd = rnd32(t);
            let expected = t.signature.as_ref().unwrap().to_uppercase();
            let (got, ok) = match g.parameter_set.as_str() {
                "ML-DSA-44" => (hex::encode_upper(Dilithium2::hash_sign_with(sk2(&sk), alg, &msg, &ctx, &rnd)), Dilithium2::hash_verify_with(pk2(&pk), alg, &msg, &ctx, &hx(&expected))),
                "ML-DSA-65" => (hex::encode_upper(Dilithium3::hash_sign_with(sk3(&sk), alg, &msg, &ctx, &rnd)), Dilithium3::hash_verify_with(pk3(&pk), alg, &msg, &ctx, &hx(&expected))),
                "ML-DSA-87" => (hex::encode_upper(Dilithium5::hash_sign_with(sk5(&sk), alg, &msg, &ctx, &rnd)), Dilithium5::hash_verify_with(pk5(&pk), alg, &msg, &ctx, &hx(&expected))),
                other => panic!("unknown set {other}"),
            };
            assert_eq!(got, expected, "{} tcId {} hash_sign_with({})", g.parameter_set, t.tc_id, t.hash_alg.as_ref().unwrap());
            assert!(ok, "{} tcId {} hash_verify_with", g.parameter_set, t.tc_id);
            n += 1;
        }
    }
    assert!(n >= 12, "expected >=12 preHash cases, ran {n}");
    eprintln!("prehash table: {n} HashML-DSA cases via PreHashAlgorithm");
}
