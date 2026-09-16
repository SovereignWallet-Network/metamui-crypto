//! Genuine-upstream conformance gate for Falcon (Round 3).
//!
//! Unlike `crosslang_test.rs` / `kat_vectors_test.rs` / `test_nist_kat.rs`
//! (which all verify vectors that *this* implementation generated — a circular
//! check), this gate verifies our verifier against the **unmodified official
//! Falcon Round 3 reference KAT** answer files.
//!
//! It is the only test that can fail when our Falcon diverges from canonical
//! Falcon at the algorithm level (encoding, hash-to-point, or the norm bound).
//! See `test-vectors/falcon-upstream/README.md` for provenance and how the
//! vectors were vendored.
//!
//! Behaviour per parameter set (mirrors the AIMer upstream gate):
//!   * upstream file absent      → SKIP (loud message; suite stays green)
//!   * upstream file self-gen'd  → FAIL (anti-circularity guard)
//!   * upstream file genuine     → verify EVERY record; any rejection fails.
//!
//! There is deliberately **no self-sign fallback**: the whole point is to test
//! foreign signatures, so a verify failure must surface, never be papered over.
//!
//! ## Wire-format adapter (Round 3 `nist.c`)
//!
//! The upstream `sm` is built by the reference `nist.c::crypto_sign`, NOT the
//! standalone `falcon.c` API. Format:
//!
//! ```text
//!   sm = | sig_len (2 bytes BE) | nonce (40) | message (mlen) | esig (sig_len) |
//!        esig[0]   = 0x20 + logn         # 0x29 (n=512) / 0x2A (n=1024)
//!        esig[1..] = comp_encode(s)      # Golomb-Rice compressed signature poly
//!        hash      = SHAKE256(nonce || message)   # Round 3: no domain-sep byte
//! ```
//!
//! Our verifier's signature layout is `[0x30 + logn] | nonce(40) | GR(s)` — the
//! SAME compressed payload, but with the standalone header byte `0x30+logn`
//! (0x39 / 0x3A) instead of `nist.c`'s `0x20+logn`. So the adapter strips the
//! upstream esig header byte and re-prepends ours; the compressed bytes and the
//! nonce are passed through untouched. If verify rejects a genuine upstream
//! signature, that is a real divergence to investigate — do not paper over it.

use std::path::PathBuf;

/// Why a missing vector file fails instead of skipping.
const KAT_ABSENCE_NOTE: &str = "The vectors are tracked in this repo, so their absence is a broken checkout, not an environment quirk — and a green run that verified nothing is exactly what this gate exists to prevent.";

use metamui_falcon512::falcon1024::{verify_1024, PublicKey1024};
use metamui_falcon512::{verify, PublicKey};

/// Marker that brands a vector file as locally generated (and therefore unfit as
/// an upstream conformance source). This is the `generator` string emitted into
/// every self-generated Falcon JSON vector in `test-vectors/falcon/`.
const SELFGEN_MARKER: &str = "metamui-falcon512 Rust reference";

const UPSTREAM_ROOT: &[&str] = &["..", "..", "test-vectors", "falcon-upstream"];

struct KatEntry {
    seed: Vec<u8>,
    pk_bytes: Vec<u8>,
    sk_bytes: Vec<u8>,
    msg: Vec<u8>,
    sm_bytes: Vec<u8>,
}

/// Resolve `test-vectors/falcon-upstream/<rel>` relative to the crate manifest.
fn upstream_path(rel: &str) -> PathBuf {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let mut p = PathBuf::from(manifest_dir);
    for seg in UPSTREAM_ROOT {
        p.push(seg);
    }
    p.push(rel);
    p
}

/// Minimal NIST `.rsp` parser. Only the fields needed to verify a foreign
/// signature are extracted: `pk`, `msg`, `sm` (seed/sk/mlen/smlen ignored — the
/// `sm` carries its own self-describing length prefix).
fn parse_rsp(content: &str) -> Vec<KatEntry> {
    let mut entries = Vec::new();
    let (mut seed, mut pk, mut sk, mut msg, mut sm) = (None, None, None, None, None);

    #[allow(clippy::too_many_arguments)]
    fn flush(
        seed: &mut Option<Vec<u8>>,
        pk: &mut Option<Vec<u8>>,
        sk: &mut Option<Vec<u8>>,
        msg: &mut Option<Vec<u8>>,
        sm: &mut Option<Vec<u8>>,
        out: &mut Vec<KatEntry>,
    ) {
        if let (Some(p), Some(s)) = (pk.take(), sm.take()) {
            // `msg` may legitimately be empty (mlen = 0), so take it separately.
            let m = msg.take().unwrap_or_default();
            out.push(KatEntry {
                seed: seed.take().unwrap_or_default(),
                pk_bytes: p,
                sk_bytes: sk.take().unwrap_or_default(),
                msg: m,
                sm_bytes: s,
            });
        } else {
            // Partial record (e.g. only pk seen) — drop any stragglers.
            let _ = (seed.take(), sk.take(), msg.take());
        }
    }

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            flush(&mut seed, &mut pk, &mut sk, &mut msg, &mut sm, &mut entries);
            continue;
        }
        if let Some(v) = line.strip_prefix("seed = ") {
            seed = Some(hex::decode(v).expect("bad seed hex"));
        } else if let Some(v) = line.strip_prefix("pk = ") {
            pk = Some(hex::decode(v).expect("bad pk hex"));
        } else if let Some(v) = line.strip_prefix("sk = ") {
            sk = Some(hex::decode(v).expect("bad sk hex"));
        } else if let Some(v) = line.strip_prefix("msg = ") {
            msg = Some(hex::decode(v).expect("bad msg hex"));
        } else if let Some(v) = line.strip_prefix("sm = ") {
            sm = Some(hex::decode(v).expect("bad sm hex"));
        }
    }
    flush(&mut seed, &mut pk, &mut sk, &mut msg, &mut sm, &mut entries);
    entries
}

/// Split an upstream `nist.c` signed message into (nonce, message, compressed
/// signature payload) and re-frame the signature into our verifier's layout
/// `[0x30 + logn] | nonce | GR(s)`.
///
/// Returns `(message, our_signature)`.
fn reframe(sm: &[u8], logn: u8) -> Result<(Vec<u8>, Vec<u8>), String> {
    const NONCE: usize = 40;
    if sm.len() < 2 + NONCE + 1 {
        return Err(format!("sm too short: {} bytes", sm.len()));
    }
    let sig_len = ((sm[0] as usize) << 8) | (sm[1] as usize);
    if sm.len() < 2 + NONCE + sig_len || sig_len < 1 {
        return Err(format!(
            "sm length {} inconsistent with sig_len prefix {}",
            sm.len(),
            sig_len
        ));
    }
    let nonce = &sm[2..2 + NONCE];
    let msg = &sm[2 + NONCE..sm.len() - sig_len];
    let esig = &sm[sm.len() - sig_len..];

    let expected_hdr = 0x20 | logn;
    if esig[0] != expected_hdr {
        return Err(format!(
            "upstream esig header 0x{:02x} != expected 0x{:02x} (0x20+logn)",
            esig[0], expected_hdr
        ));
    }
    let comp = &esig[1..]; // Golomb-Rice payload, header stripped

    let mut our_sig = Vec::with_capacity(1 + NONCE + comp.len());
    our_sig.push(0x30 | logn); // our standalone header (0x39 / 0x3A)
    our_sig.extend_from_slice(nonce);
    our_sig.extend_from_slice(comp);
    Ok((msg.to_vec(), our_sig))
}

enum Variant {
    Falcon512,
    Falcon1024,
}

impl Variant {
    fn logn(&self) -> u8 {
        match self {
            Variant::Falcon512 => 9,
            Variant::Falcon1024 => 10,
        }
    }

    /// Verify a re-framed signature with the appropriate per-degree verifier.
    fn verify(&self, msg: &[u8], sig: &[u8], pk_bytes: &[u8]) -> Result<bool, String> {
        match self {
            Variant::Falcon512 => {
                let pk = PublicKey::from_bytes(pk_bytes)
                    .map_err(|e| format!("PublicKey::from_bytes: {e:?}"))?;
                verify(msg, sig, &pk).map_err(|e| format!("verify: {e:?}"))
            }
            Variant::Falcon1024 => {
                let pk = PublicKey1024::from_bytes(pk_bytes)
                    .map_err(|e| format!("PublicKey1024::from_bytes: {e:?}"))?;
                verify_1024(msg, sig, &pk).map_err(|e| format!("verify_1024: {e:?}"))
            }
        }
    }
}

/// The Tier-A gate body, generic over the parameter set.
fn run_upstream_gate(variant: Variant, rel_path: &str, label: &str) {
    let path = upstream_path(rel_path);

    // ---- absent → skip loudly -------------------------------------------
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            panic!(
                "{label}: genuine-upstream KAT not readable at {} ({e}). \
                 See test-vectors/falcon-upstream/README.md. {KAT_ABSENCE_NOTE}",
                path.display()
            );
        }
    };

    // ---- present but self-generated → fail (anti-circularity) -----------
    assert!(
        !content.contains(SELFGEN_MARKER),
        "{label}: {} carries the self-generated marker ('{}'), not genuine \
         upstream. Verifying against it is circular. Replace it with the real \
         Falcon Round 3 .rsp.",
        path.display(),
        SELFGEN_MARKER
    );

    // ---- present and genuine → verify every record ----------------------
    let entries = parse_rsp(&content);
    assert!(!entries.is_empty(), "{label}: no records parsed from {}", path.display());

    let logn = variant.logn();
    let mut accepted = 0usize;
    let mut first_failure: Option<String> = None;

    for (i, e) in entries.iter().enumerate() {
        let (msg, our_sig) = match reframe(&e.sm_bytes, logn) {
            Ok(t) => t,
            Err(why) => {
                first_failure.get_or_insert_with(|| format!("record {i}: reframe failed: {why}"));
                continue;
            }
        };
        // The reframed message must equal the record's standalone `msg` field.
        if msg != e.msg {
            first_failure
                .get_or_insert_with(|| format!("record {i}: sm-embedded message != msg field"));
            continue;
        }

        // (a) genuine signature must VERIFY ...
        match variant.verify(&msg, &our_sig, &e.pk_bytes) {
            Ok(true) => {}
            Ok(false) => {
                first_failure.get_or_insert_with(|| {
                    format!("record {i}: verifier returned false for genuine upstream signature")
                });
                continue;
            }
            Err(err) => {
                first_failure
                    .get_or_insert_with(|| format!("record {i}: verify errored: {err}"));
                continue;
            }
        }

        // (b) ... and a one-byte tamper of the compressed payload must REJECT.
        let mut tampered = our_sig.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        match variant.verify(&msg, &tampered, &e.pk_bytes) {
            Ok(false) | Err(_) => {}
            Ok(true) => {
                first_failure.get_or_insert_with(|| {
                    format!("record {i}: tampered signature was ACCEPTED (verifier too lax)")
                });
                continue;
            }
        }

        accepted += 1;
    }

    if let Some(reason) = first_failure {
        panic!(
            "{label}: {accepted}/{} genuine upstream signatures fully validated — \
             ALGORITHM DIVERGENCE from canonical Falcon.\n  first failure: {reason}",
            entries.len()
        );
    }

    eprintln!(
        "PASS {label}: {accepted}/{} genuine upstream signatures accepted (and tampers rejected)",
        entries.len()
    );
}

// ---------------------------------------------------------------------------
// Tier A — verify-only hard gate. One test per parameter set.
// ---------------------------------------------------------------------------

#[test]
fn upstream_verify_falcon512() {
    run_upstream_gate(Variant::Falcon512, "falcon512/falcon512-KAT.rsp", "Falcon-512");
}

#[test]
fn upstream_verify_falcon1024() {
    run_upstream_gate(Variant::Falcon1024, "falcon1024/falcon1024-KAT.rsp", "Falcon-1024");
}

// ---------------------------------------------------------------------------
// Tier B — byte-exact reproduction diagnostic.
//
// Replays the NIST CTR_DRBG schedule of the official KAT generator through
// `kat_api::derive_kat_inputs` (kg_seed, nonce, sig_seed per record), then
// drives our keygen and signer from those inputs and reports the FIRST stage
// whose bytes diverge from the record: pk → sk → esig. Byte equality needs the
// reference keygen/sampler randomness-consumption order (Tier-B steps 2–3 of
// the 2026-09 audit plan), which this clean-room port does not reproduce yet,
// so the test stays ignored: run it with `-- --ignored` to see the report.
// It never silently passes — a stage that matches is asserted, a stage that
// diverges is printed with the first differing offset.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "Tier B diagnostic: reports the first divergent stage (pk/sk/esig); byte-exact reproduction pending reference keygen/sampler order (audit plan WS1 P1.5 steps 2-3)"]
fn upstream_reproduce_falcon512_byte_exact() {
    use metamui_falcon512::kat_api;

    let path = upstream_path("falcon512/falcon512-KAT.rsp");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("genuine-upstream KAT missing at {} ({e})", path.display()));
    assert!(!content.contains(SELFGEN_MARKER), "self-generated marker present");
    let entries = parse_rsp(&content);
    assert!(!entries.is_empty());

    /// First differing offset over the common prefix; if the prefix is equal
    /// but lengths differ, the shorter length (so "diverges @N" with N == the
    /// shorter length means "same bytes, different length").
    fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
        match a.iter().zip(b).position(|(x, y)| x != y) {
            Some(i) => Some(i),
            None if a.len() != b.len() => Some(a.len().min(b.len())),
            None => None,
        }
    }

    let mut matched_pk = 0usize;
    for (i, e) in entries.iter().enumerate() {
        let seed: [u8; 48] = e.seed.as_slice().try_into().expect("48-byte seed");
        let inputs = kat_api::derive_kat_inputs(&seed).expect("DRBG replay");

        // Stage 1: keygen from SHAKE256(kg_seed)
        let kp = kat_api::keypair_from_kg_seed(&inputs.kg_seed).expect("keygen from kg_seed");
        let our_pk = kp.public_key.to_bytes();
        let our_sk = kp.private_key.to_bytes();
        let pk_diff = first_diff(&our_pk, &e.pk_bytes);
        let sk_diff = first_diff(&our_sk, &e.sk_bytes);

        // Stage 2: sign with the record's nonce and SHAKE256(sig_seed), using
        // the UPSTREAM sk (so the signer is measured independently of keygen).
        let sk_up = metamui_falcon512::PrivateKey::from_bytes(&e.sk_bytes).expect("upstream sk decodes");
        let our_sig = kat_api::sign_with_nonce_seed(&sk_up, &e.msg, &inputs.nonce, &inputs.sig_seed)
            .expect("sign with nonce+seed");
        let (_m, up_sig) = reframe(&e.sm_bytes, 9).expect("reframe");
        let sig_diff = first_diff(&our_sig, &up_sig);
        let nonce_ok = &up_sig[1..41] == &inputs.nonce[..];

        eprintln!(
            "record {i}: pk {}  sk {}  nonce-from-DRBG {}  esig {} (ours {} B / upstream {} B)",
            pk_diff.map_or("MATCH".to_string(), |o| format!("diverges @{o}")),
            sk_diff.map_or("MATCH".to_string(), |o| format!("diverges @{o}")),
            if nonce_ok { "MATCH" } else { "DIVERGES" },
            sig_diff.map_or("MATCH".to_string(), |o| format!("diverges @{o}")),
            our_sig.len(),
            up_sig.len()
        );
        // The DRBG schedule itself must be right: the nonce is a pure DRBG
        // output and appears verbatim in the upstream esig.
        assert!(nonce_ok, "record {i}: DRBG replay does not reproduce the upstream nonce — schedule bug");
        // Whatever we produce must at least be a valid signature under the upstream key.
        let pk_up = PublicKey::from_bytes(&e.pk_bytes).unwrap();
        assert_eq!(verify(&e.msg, &our_sig, &pk_up), Ok(true), "record {i}: our seeded signature does not verify");
        if pk_diff.is_none() {
            matched_pk += 1;
        }
    }
    eprintln!(
        "Tier B summary: {matched_pk}/{} records reproduce pk byte-exactly; see per-record lines for the first divergent stage",
        entries.len()
    );
}

// ---------------------------------------------------------------------------
// Norm-boundary gate (#352, #359).
//
// Algorithm 16 accepts ||(s1, s2)||^2 <= floor(beta^2): 34034726 for
// Falcon-512 and 70265242 for Falcon-1024 (the Round 3 reference l2bound).
// Each file carries signatures whose norm sits exactly on the bound (must
// verify), one above it (must reject), and for Falcon-1024 one at 104313924,
// the bound this tree used before (must reject). The verdicts were checked
// against the vendored PQClean reference verifier. A missing file or an empty
// vector list fails.
// ---------------------------------------------------------------------------

fn norm_boundary_path(file: &str) -> PathBuf {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let mut p = PathBuf::from(manifest_dir);
    for seg in ["..", "..", "test-vectors", "falcon", file] {
        p.push(seg);
    }
    p
}

fn run_norm_boundary(variant: Variant, file: &str, set: &str, beta_sq: u64, count: usize) {
    let path = norm_boundary_path(file);
    let content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("{set}: norm-boundary vectors not readable at {} ({e}). {KAT_ABSENCE_NOTE}", path.display())
    });
    let doc: serde_json::Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("{set}: {} is not valid JSON: {e}", path.display()));
    assert_eq!(doc["parameter_set"].as_str(), Some(set), "{set}: parameter_set");
    assert_eq!(doc["beta_squared"].as_u64(), Some(beta_sq), "{set}: beta_squared");
    let pk = hex::decode(doc["public_key"].as_str().expect("public_key")).expect("public_key hex");
    let msg = hex::decode(doc["message"].as_str().expect("message")).expect("message hex");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "{set}: {} has zero vectors", path.display());
    assert_eq!(vectors.len(), count, "{set}: vector count");

    for v in vectors {
        let label = v["label"].as_str().expect("label");
        let expected = v["expected_valid"].as_bool().expect("expected_valid");
        let sig = hex::decode(v["signature"].as_str().expect("signature")).expect("signature hex");
        assert_eq!(v["signature_bytes"].as_u64(), Some(sig.len() as u64), "{set} {label}: signature_bytes");
        let verdict = match variant.verify(&msg, &sig, &pk) {
            Ok(b) => b,
            Err(e) if !expected => {
                eprintln!("{set} {label}: rejected with error {e}");
                false
            }
            Err(e) => panic!("{set} {label}: verify errored on a signature that must verify: {e}"),
        };
        assert_eq!(
            verdict, expected,
            "{set} {label} (norm_sq {}): verify returned {verdict}, expected {expected}",
            v["norm_sq"]
        );
    }
    eprintln!("PASS {set}: {count} norm-boundary vectors match expected_valid");
}

#[test]
fn norm_boundary_falcon512() {
    run_norm_boundary(Variant::Falcon512, "falcon512-norm-boundary.json", "Falcon-512", 34034726, 2);
}

#[test]
fn norm_boundary_falcon1024() {
    run_norm_boundary(Variant::Falcon1024, "falcon1024-norm-boundary.json", "Falcon-1024", 70265242, 3);
}

/// #360: `sign_compressed::verify_compressed` skipped the norm check, and since
/// s0 is reconstructed from the verification equation, it then accepted any
/// well-formed signature for any message.
#[test]
fn verify_compressed_rejects_other_message() {
    use metamui_falcon512::{generate_keypair, sign, sign_compressed::verify_compressed};
    use rand::{rngs::StdRng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(360);
    let kp = generate_keypair(&mut rng).expect("keygen");
    let msg = b"issue 360: signed message";
    let sig = sign(msg, &kp.private_key, &mut rng).expect("sign");
    assert_eq!(verify(msg, &sig, &kp.public_key), Ok(true), "public verify accepts the signature");

    let other = b"issue 360: a different message";
    let verdict = verify_compressed(other, &sig, &kp.public_key);
    assert!(
        matches!(verdict, Ok(false) | Err(_)),
        "verify_compressed accepted a signature over a different message: {verdict:?}"
    );
}
