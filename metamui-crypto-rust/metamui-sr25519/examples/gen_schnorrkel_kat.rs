//! Sr25519 KAT generator — emits `test-vectors/sr25519/sr25519-schnorrkel-kat.json`
//! from the canonical `schnorrkel` reference implementation.
//!
//! This is the **ground-truth** harness for Phase 1 of the compliance
//! remediation plan (`documents/project/sr25519-compliance-plan.md`).
//! Every subsequent code change to `metamui-sr25519` must keep
//! `tests/kat_schnorrkel.rs` green against the JSON this test writes.
//!
//! Run manually to regenerate:
//!   cargo run --release -p metamui-sr25519 --example gen_schnorrkel_kat
//!
//! This is a generator, not a test: it lives in `examples/` so the test
//! suite carries no `#[ignore]`d pseudo-test (audit A28).
//!
//! Regenerating produces new (randomized) signatures. That is expected
//! — the assertions in `kat_schnorrkel.rs` are verifier-parity and
//! roundtrip-parity, not byte-exact signatures (schnorrkel signing is
//! randomized via `rand_core::OsRng`).
//!
//! **Pinning note**: `schnorrkel` is a dev-dep pinned to `=0.11.4`.
//! Do NOT bump without regenerating this file as a conscious decision.

use schnorrkel::{ExpansionMode, MiniSecretKey};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn vectors_dir() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../test-vectors/sr25519");
    assert!(path.exists(), "test-vectors/sr25519 directory not found at {}", path.display());
    path
}

/// Fixed (mini_secret, context, message) tuples. Do NOT rearrange
/// existing entries — downstream tests reference them by `tc_id`.
fn kat_inputs() -> Vec<(u32, &'static str, [u8; 32], Vec<u8>, Vec<u8>)> {
    vec![
        // tc_id, description, mini_secret, context, message
        (1, "all-zero mini_secret, substrate context, empty message",
            [0u8; 32], b"substrate".to_vec(), b"".to_vec()),
        (2, "all-zero mini_secret, substrate context, short ASCII message",
            [0u8; 32], b"substrate".to_vec(), b"hello".to_vec()),
        (3, "mini_secret=0x01.., substrate context, 'I am Alice'",
            {
                let mut k = [0u8; 32]; k[31] = 1; k
            },
            b"substrate".to_vec(), b"I am Alice".to_vec()),
        (4, "pattern mini_secret (0x42..), substrate context, 32-byte msg",
            [0x42u8; 32], b"substrate".to_vec(), (0u8..32).collect()),
        (5, "ascending mini_secret, empty context, short message",
            {
                let mut k = [0u8; 32];
                for i in 0..32 { k[i] = i as u8; }
                k
            },
            b"".to_vec(), b"x".to_vec()),
        (6, "high-bit mini_secret (0xff..), substrate context, 'The quick brown fox...'",
            [0xffu8; 32], b"substrate".to_vec(),
            b"The quick brown fox jumps over the lazy dog".to_vec()),
        (7, "RFC 8032 test seed (0x9d..), substrate context, empty",
            {
                let mut k = [0u8; 32];
                hex::decode_to_slice(
                    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                    &mut k,
                ).unwrap();
                k
            },
            b"substrate".to_vec(), b"".to_vec()),
        (8, "RFC 8032 test seed, custom context 'MetaMUI-Test', long msg",
            {
                let mut k = [0u8; 32];
                hex::decode_to_slice(
                    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                    &mut k,
                ).unwrap();
                k
            },
            b"MetaMUI-Test".to_vec(),
            b"cross-language interoperability test message \xff\x00\xaa".to_vec()),
        (9, "mini_secret=0xaa.., substrate context, 256-byte binary msg",
            [0xaau8; 32], b"substrate".to_vec(), (0u8..=255).collect()),
        (10, "mini_secret=0x55.., substrate context, 1024-byte repeated pattern",
            [0x55u8; 32], b"substrate".to_vec(), vec![0xcc; 1024]),
        (11, "mini_secret=0x01.., 'Polkadot' context, empty msg",
            {
                let mut k = [0u8; 32]; k[31] = 1; k
            },
            b"Polkadot".to_vec(), b"".to_vec()),
        (12, "mini_secret=0x01.., custom context 'vrf-test', UTF-8 msg",
            {
                let mut k = [0u8; 32]; k[31] = 1; k
            },
            b"vrf-test".to_vec(), "MetaMUI 크립토".as_bytes().to_vec()),
        (13, "alternating mini_secret 0x00/0xff, substrate, single NUL byte",
            {
                let mut k = [0u8; 32];
                for i in 0..32 { k[i] = if i & 1 == 0 { 0 } else { 0xff }; }
                k
            },
            b"substrate".to_vec(), b"\x00".to_vec()),
        (14, "derived-looking mini_secret, substrate, JSON-ish payload",
            {
                let mut k = [0u8; 32];
                hex::decode_to_slice(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    &mut k,
                ).unwrap();
                k
            },
            b"substrate".to_vec(),
            br#"{"nonce":42,"call":"balances.transfer"}"#.to_vec()),
        (15, "edge-case 0x80 mini_secret, substrate, empty",
            [0x80u8; 32], b"substrate".to_vec(), b"".to_vec()),
        (16, "random-looking mini_secret, substrate, 'substrate signing test'",
            {
                let mut k = [0u8; 32];
                hex::decode_to_slice(
                    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                    &mut k,
                ).unwrap();
                k
            },
            b"substrate".to_vec(), b"substrate signing test".to_vec()),
    ]
}

fn main() {
    let inputs = kat_inputs();

    let mut vectors = Vec::with_capacity(inputs.len());
    for (tc_id, description, mini_secret_bytes, context, message) in &inputs {
        // Expand via ExpansionMode::Ed25519 — this is what Polkadot /
        // Substrate use in production. MiniSecretKey::expand_uniform
        // is also valid per the schnorrkel docs but is NOT the
        // deployed choice.
        let mini = MiniSecretKey::from_bytes(mini_secret_bytes)
            .expect("valid mini_secret");
        let keypair = mini.expand_to_keypair(ExpansionMode::Ed25519);
        let public_key = keypair.public.to_bytes();

        // Produce ONE signature with sign_simple — this is exactly the
        // Polkadot signing surface. Note that sign_simple is
        // randomized (witness_scalar rekeys from OsRng), so
        // regeneration yields different bytes.
        let sig = keypair.sign_simple(context, message);
        let sig_bytes = sig.to_bytes();

        // Sanity: schnorrkel must verify its own output.
        keypair.public.verify_simple(context, message, &sig)
            .expect("schnorrkel self-verify failed — pinned version mismatch?");

        vectors.push(json!({
            "tc_id": tc_id,
            "description": description,
            "expansion_mode": "Ed25519",
            "mini_secret": hex_encode(mini_secret_bytes),
            "public_key": hex_encode(&public_key),
            "context": hex_encode(context),
            "context_utf8": std::str::from_utf8(context).unwrap_or(""),
            "message": hex_encode(message),
            "message_utf8_maybe": std::str::from_utf8(message).unwrap_or("<binary>"),
            "signature": hex_encode(&sig_bytes),
            "signature_size": sig_bytes.len(),
        }));
    }

    let output = json!({
        "algorithm": "sr25519",
        "standard": "W3F Schnorrkel — Ristretto255 Schnorr signatures",
        "source": "github.com/w3f/schnorrkel v0.11.4",
        "generator": "metamui-sr25519/examples/gen_schnorrkel_kat.rs",
        "expansion_mode": "Ed25519",
        "note": concat!(
            "Ground-truth KATs generated by the canonical schnorrkel ",
            "crate (v0.11.4) via MiniSecretKey::expand(Ed25519) + ",
            "Keypair::sign_simple. The `signature` field is ONE ",
            "representative value; schnorrkel signing is randomized, ",
            "so byte-exact reproduction is NOT expected. The consuming ",
            "test (kat_schnorrkel.rs) asserts (a) public_key derivation ",
            "parity, (b) that our verifier accepts this signature, and ",
            "(c) that schnorrkel's verifier accepts signatures produced ",
            "by our signer — roundtrip parity, not byte parity.",
        ),
        "vectors": vectors,
    });

    let path = vectors_dir().join("sr25519-schnorrkel-kat.json");
    let rendered = serde_json::to_string_pretty(&output).unwrap();
    fs::write(&path, rendered).expect("write KAT file");
    eprintln!("wrote {} ({} vectors)", path.display(), inputs.len());
}
