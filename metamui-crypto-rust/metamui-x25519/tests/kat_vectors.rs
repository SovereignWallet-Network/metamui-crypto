// KAT vectors for X25519 -- RFC 7748 Sections 5.2 and 6.1
// Source: test-vectors/x25519/rfc7748-vectors.json
//
// Covers all five vectors in the ground-truth file:
//   tc1, tc2  "one-shot"        -- X25519(scalar, u) == output, byte-exact
//   tc3       "iterative"       -- 1,000-iteration RFC 7748 5.2 loop
//   tc4       "iterative"       -- 1,000,000-iteration loop (opt-in, see below)
//   tc5       "diffie-hellman"  -- keygen from base point + DH both directions
//
// The 1,000,000-iteration vector (tc4) is expensive (~minutes). It is gated
// behind the X25519_RUN_1M env var so the default `cargo test` stays fast; set
// X25519_RUN_1M=1 to exercise it.
use metamui_x25519::key_exchange;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct TestCase {
    tc_id: u32,
    #[serde(rename = "type")]
    test_type: String,
    // one-shot
    scalar: Option<String>,
    u_coordinate: Option<String>,
    output: Option<String>,
    // iterative
    iterations: Option<u64>,
    initial_scalar: Option<String>,
    initial_u_coordinate: Option<String>,
    // diffie-hellman
    base_u_coordinate: Option<String>,
    alice_private: Option<String>,
    alice_public: Option<String>,
    bob_private: Option<String>,
    bob_public: Option<String>,
    shared_secret: Option<String>,
}

#[derive(Deserialize)]
struct VectorFile {
    test_vectors: Vec<TestCase>,
}

fn hex32(s: &str) -> Vec<u8> {
    hex::decode(s).expect("invalid hex in vector file")
}

/// X25519(scalar, u) via the public key-exchange API. The API clamps the
/// scalar and masks the u-coordinate high bit internally, exactly as required
/// by RFC 7748, so this is the raw single-function primitive for KAT purposes.
fn x25519(scalar: &[u8], u: &[u8]) -> Vec<u8> {
    key_exchange(scalar.to_vec(), u.to_vec())
        .unwrap_or_else(|e| panic!("X25519 key_exchange failed: {e:?}"))
}

#[test]
fn x25519_kat_rfc7748() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/x25519/rfc7748-vectors.json"
    );
    // Missing vector file is a hard failure -- the KAT must never silently skip.
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read X25519 vector file {path}: {e}"));
    let file: VectorFile = serde_json::from_str(&data).expect("malformed X25519 vector file");

    let run_1m = std::env::var("X25519_RUN_1M").is_ok();
    let mut one_shot = 0u32;
    let mut iterative = 0u32;
    let mut dh = 0u32;

    for tv in &file.test_vectors {
        match tv.test_type.as_str() {
            "one-shot" => {
                let scalar = hex32(tv.scalar.as_deref().unwrap());
                let u = hex32(tv.u_coordinate.as_deref().unwrap());
                let expected = hex32(tv.output.as_deref().unwrap());
                let got = x25519(&scalar, &u);
                assert_eq!(
                    got, expected,
                    "X25519 one-shot KAT failed (byte-exact) at tc_id={}",
                    tv.tc_id
                );
                one_shot += 1;
            }
            "iterative" => {
                let iters = tv.iterations.expect("iterative vector missing iterations");
                let expected = hex32(tv.output.as_deref().unwrap());

                if iters >= 1_000_000 && !run_1m {
                    println!(
                        "SKIP tc_id={} ({} iterations): set X25519_RUN_1M=1 to run",
                        tv.tc_id, iters
                    );
                    continue;
                }

                // RFC 7748 Section 5.2 loop: k = u = initial; repeat
                // r = X25519(k, u); u = k; k = r.
                let mut k = hex32(tv.initial_scalar.as_deref().unwrap());
                let mut u = hex32(tv.initial_u_coordinate.as_deref().unwrap());
                for _ in 0..iters {
                    let r = x25519(&k, &u);
                    u = k;
                    k = r;
                }
                assert_eq!(
                    k, expected,
                    "X25519 iterative KAT failed at tc_id={} after {} iterations",
                    tv.tc_id, iters
                );
                iterative += 1;
            }
            "diffie-hellman" => {
                let base = hex32(tv.base_u_coordinate.as_deref().unwrap());
                let alice_priv = hex32(tv.alice_private.as_deref().unwrap());
                let alice_pub = hex32(tv.alice_public.as_deref().unwrap());
                let bob_priv = hex32(tv.bob_private.as_deref().unwrap());
                let bob_pub = hex32(tv.bob_public.as_deref().unwrap());
                let shared = hex32(tv.shared_secret.as_deref().unwrap());

                // Keygen: public = X25519(private, base point u=9).
                assert_eq!(
                    x25519(&alice_priv, &base),
                    alice_pub,
                    "X25519 DH keygen (alice) failed at tc_id={}",
                    tv.tc_id
                );
                assert_eq!(
                    x25519(&bob_priv, &base),
                    bob_pub,
                    "X25519 DH keygen (bob) failed at tc_id={}",
                    tv.tc_id
                );

                // Shared secret must agree in both directions and match the vector.
                assert_eq!(
                    x25519(&alice_priv, &bob_pub),
                    shared,
                    "X25519 DH shared (alice->bob) failed at tc_id={}",
                    tv.tc_id
                );
                assert_eq!(
                    x25519(&bob_priv, &alice_pub),
                    shared,
                    "X25519 DH shared (bob->alice) failed at tc_id={}",
                    tv.tc_id
                );
                dh += 1;
            }
            other => panic!("unknown X25519 vector type {other:?} at tc_id={}", tv.tc_id),
        }
    }

    println!(
        "X25519 RFC 7748 KAT: {one_shot} one-shot, {iterative} iterative, {dh} diffie-hellman passed"
    );
    assert!(one_shot >= 2, "expected at least 2 one-shot vectors");
    assert!(iterative >= 1, "expected at least 1 iterative vector (tc3)");
    assert!(dh >= 1, "expected at least 1 diffie-hellman vector (tc5)");
}
