//! Generate cross-language Falcon test vectors from the Rust reference implementation.
//!
//! Run with: cargo run --release -p metamui-falcon512 --example generate_crosslang_vectors
//!
//! This is a generator, not a test: it lives in `examples/` so the test
//! suite carries no `#[ignore]`d pseudo-test (audit A28). It rewrites
//! `test-vectors/falcon/falcon{512,1024}_cross_lang.json` in place.

use rand_chacha::ChaChaRng;
use rand::SeedableRng;
use serde_json::json;
use std::fs;
use std::path::PathBuf;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Provenance for regenerated corpora: `VECTORS_COMMIT=$(git rev-parse --short HEAD)`
/// at generation time. Signatures are randomized (the Gaussian sampler draws
/// fresh randomness), so consumers must verify, never byte-compare.
fn generated_by() -> String {
    format!(
        "metamui-falcon512 rust@{}",
        std::env::var("VECTORS_COMMIT").unwrap_or_else(|_| "unknown".to_string())
    )
}

fn vectors_dir() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../test-vectors/falcon");
    assert!(path.exists(), "test-vectors/falcon directory not found");
    path
}

fn generate_falcon512_cross_lang() {
    let mut rng = ChaChaRng::from_seed([0x42u8; 32]);
    let kp = metamui_falcon512::generate_keypair(&mut rng)
        .expect("Falcon-512 keygen failed");

    let pk_hex = hex_encode(&kp.public_key.to_bytes());

    let messages: Vec<(&str, Vec<u8>)> = vec![
        ("empty message", vec![]),
        ("hello", b"hello".to_vec()),
        ("The quick brown fox jumps over the lazy dog", b"The quick brown fox jumps over the lazy dog".to_vec()),
        ("binary data 0x00-0xFF", (0u8..=255).collect()),
        ("short message", b"A".to_vec()),
        ("repeated byte pattern", vec![0xAA; 1024]),
        ("cross-language interop test message", b"cross-language interop test message".to_vec()),
        ("UTF-8 content", "MetaMUI 크립토".as_bytes().to_vec()),
    ];

    let mut vectors = Vec::new();
    for (i, (desc, msg)) in messages.iter().enumerate() {
        let mut sign_rng = ChaChaRng::from_seed([(i as u8).wrapping_add(1); 32]);
        let sig = metamui_falcon512::sign(msg, &kp.private_key, &mut sign_rng)
            .expect("Falcon-512 sign failed");

        // Verify our own signature
        let ok = metamui_falcon512::verify(msg, &sig, &kp.public_key)
            .expect("Falcon-512 verify error");
        assert!(ok, "Self-verify failed for vector {}", i);

        vectors.push(json!({
            "id": i + 1,
            "message": desc,
            "message_hex": hex_encode(msg),
            "signature_hex": hex_encode(&sig),
        }));
    }

    // Tamper vectors: for each positive vector, flip one byte in the
    // signature. All cross-language verifiers must reject these.
    let mut tampered = Vec::new();
    for (i, v) in vectors.iter().enumerate() {
        let sig_hex = v["signature_hex"].as_str().unwrap();
        let mut sig_bytes = hex_decode(sig_hex);
        // Flip a byte in the compressed s1 region (past the 41-byte header+nonce).
        let flip_idx = 100 + i;
        sig_bytes[flip_idx] ^= 0x01;
        let tampered_hex = hex_encode(&sig_bytes);

        // Sanity: our own verifier must reject it.
        let msg_hex = v["message_hex"].as_str().unwrap();
        let msg_bytes = hex_decode(msg_hex);
        let pk_bytes = hex_decode(&pk_hex);
        let pk = metamui_falcon512::PublicKey::from_bytes(&pk_bytes).unwrap();
        let rejected = !metamui_falcon512::verify(&msg_bytes, &sig_bytes, &pk)
            .unwrap_or(false);
        assert!(rejected, "tamper vector {} unexpectedly verified", i);

        tampered.push(json!({
            "id": v["id"],
            "base_id": v["id"],
            "note": format!("signature_hex byte {} XOR 0x01", flip_idx),
            "message_hex": msg_hex,
            "signature_hex": tampered_hex,
            "expect_valid": false,
        }));
    }

    let output = json!({
        "algorithm": "Falcon-512",
        "generator": "metamui-falcon512 Rust reference",
        "generated_by": generated_by(),
        "mode": "verify_only",
        "note": "Signatures are randomized; consumers must verify, never byte-compare.",
        "public_key": pk_hex,
        "vectors": vectors,
        "tampered_vectors": tampered,
    });

    let path = vectors_dir().join("falcon512_cross_lang.json");
    fs::write(&path, serde_json::to_string_pretty(&output).unwrap())
        .expect("Failed to write falcon512_cross_lang.json");
    println!("Wrote {} ({} vectors)", path.display(), messages.len());
}

fn generate_falcon1024_cross_lang() {
    let mut rng = ChaChaRng::from_seed([0x43u8; 32]);
    let kp = metamui_falcon512::falcon1024::generate_keypair_1024(&mut rng)
        .expect("Falcon-1024 keygen failed");

    let pk_hex = hex_encode(&kp.public_key.to_bytes());

    let messages: Vec<(&str, Vec<u8>)> = vec![
        ("empty message", vec![]),
        ("hello", b"hello".to_vec()),
        ("The quick brown fox jumps over the lazy dog", b"The quick brown fox jumps over the lazy dog".to_vec()),
        ("binary data 0x00-0xFF", (0u8..=255).collect()),
        ("short message", b"A".to_vec()),
        ("repeated byte pattern", vec![0xAA; 1024]),
        ("cross-language interop test message", b"cross-language interop test message".to_vec()),
        ("UTF-8 content", "MetaMUI 크립토".as_bytes().to_vec()),
    ];

    let mut vectors = Vec::new();
    for (i, (desc, msg)) in messages.iter().enumerate() {
        let mut sign_rng = ChaChaRng::from_seed([(i as u8).wrapping_add(1); 32]);
        let sig = metamui_falcon512::falcon1024::sign_1024(msg, &kp.private_key, &mut sign_rng)
            .expect("Falcon-1024 sign failed");

        let ok = metamui_falcon512::falcon1024::verify_1024(msg, &sig, &kp.public_key)
            .expect("Falcon-1024 verify error");
        assert!(ok, "Self-verify failed for vector {}", i);

        vectors.push(json!({
            "id": i + 1,
            "message": desc,
            "message_hex": hex_encode(msg),
            "signature_hex": hex_encode(&sig),
        }));
    }

    // Tamper vectors: for each positive vector, flip one byte in the
    // signature. All cross-language verifiers must reject these.
    let mut tampered = Vec::new();
    for (i, v) in vectors.iter().enumerate() {
        let sig_hex = v["signature_hex"].as_str().unwrap();
        let mut sig_bytes = hex_decode(sig_hex);
        let flip_idx = 100 + i;
        sig_bytes[flip_idx] ^= 0x01;
        let tampered_hex = hex_encode(&sig_bytes);

        let msg_hex = v["message_hex"].as_str().unwrap();
        let msg_bytes = hex_decode(msg_hex);
        let pk_bytes = hex_decode(&pk_hex);
        let pk = metamui_falcon512::falcon1024::PublicKey1024::from_bytes(&pk_bytes).unwrap();
        let rejected = !metamui_falcon512::falcon1024::verify_1024(&msg_bytes, &sig_bytes, &pk)
            .unwrap_or(false);
        assert!(rejected, "tamper vector {} unexpectedly verified", i);

        tampered.push(json!({
            "id": v["id"],
            "base_id": v["id"],
            "note": format!("signature_hex byte {} XOR 0x01", flip_idx),
            "message_hex": msg_hex,
            "signature_hex": tampered_hex,
            "expect_valid": false,
        }));
    }

    let output = json!({
        "algorithm": "Falcon-1024",
        "generator": "metamui-falcon512 Rust reference",
        "generated_by": generated_by(),
        "mode": "verify_only",
        "note": "Signatures are randomized; consumers must verify, never byte-compare.",
        "public_key": pk_hex,
        "vectors": vectors,
        "tampered_vectors": tampered,
    });

    let path = vectors_dir().join("falcon1024_cross_lang.json");
    fs::write(&path, serde_json::to_string_pretty(&output).unwrap())
        .expect("Failed to write falcon1024_cross_lang.json");
    println!("Wrote {} ({} vectors)", path.display(), messages.len());
}

fn main() {
    generate_falcon512_cross_lang();
    generate_falcon1024_cross_lang();
}
