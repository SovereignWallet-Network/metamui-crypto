//! Cross-language Falcon-512/1024 verification tests.
//!
//! Loads C-generated test vectors and verifies them using the Rust implementation.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    algorithm: String,
    public_key: String,
    vectors: Vec<Vector>,
    #[serde(default)]
    tampered_vectors: Vec<TamperedVector>,
}

#[derive(Deserialize)]
struct Vector {
    id: u32,
    message: String,
    message_hex: String,
    signature_hex: String,
}

#[derive(Deserialize)]
struct TamperedVector {
    id: u32,
    message_hex: String,
    signature_hex: String,
    #[allow(dead_code)]
    expect_valid: bool,
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn find_vectors_dir() -> PathBuf {
    // Try relative to crate root
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../test-vectors/falcon");
    if path.exists() {
        return path;
    }
    // Fallback
    PathBuf::from("test-vectors/falcon")
}

#[test]
fn test_crosslang_falcon512() {
    let vectors_dir = find_vectors_dir();
    let json_path = vectors_dir.join("falcon512_cross_lang.json");
    // The cross-language oracle is tracked in this repo: a missing file is
    // a broken checkout, not a skip (audit A28) — FAIL instead of going green.
    let data = fs::read_to_string(&json_path)
        .unwrap_or_else(|e| panic!("cross-language vectors missing at {} ({e})", json_path.display()));
    let vf: VectorFile = serde_json::from_str(&data).unwrap();

    let pk_bytes = hex_decode(&vf.public_key);
    match metamui_falcon512::PublicKey::from_bytes(&pk_bytes) {
        Ok(pk) => {
            // Cross-language vectors decoded successfully — verify them
            let mut passed = 0;
            for v in &vf.vectors {
                let msg_bytes = if v.message_hex.is_empty() {
                    vec![]
                } else {
                    hex_decode(&v.message_hex)
                };
                let sig_bytes = hex_decode(&v.signature_hex);

                let result = metamui_falcon512::verify(&msg_bytes, &sig_bytes, &pk)
                    .expect("verify returned Err");
                assert!(
                    result,
                    "Falcon-512 cross-lang verify failed for vector {}: {:?}",
                    v.id, v.message
                );
                passed += 1;
                println!("  [{}] {}... PASSED", v.id, &v.message[..v.message.len().min(40)]);
            }
            println!(
                "\nRust {}: {}/{} verified",
                vf.algorithm, passed, vf.vectors.len()
            );

            // Tampered vectors
            let mut rejected = 0;
            for tv in &vf.tampered_vectors {
                let msg = if tv.message_hex.is_empty() { vec![] } else { hex_decode(&tv.message_hex) };
                let sig = hex_decode(&tv.signature_hex);
                let ok = metamui_falcon512::verify(&msg, &sig, &pk).unwrap_or(false);
                assert!(!ok, "Falcon-512 tamper vector {} unexpectedly verified", tv.id);
                rejected += 1;
            }
            if !vf.tampered_vectors.is_empty() {
                println!("Rust {}: {}/{} tamper vectors correctly rejected",
                    vf.algorithm, rejected, vf.tampered_vectors.len());
            }
        }
        Err(e) => {
            // HARD FAIL — do NOT silently fall back to a self-test. A decode
            // failure here means the canonical cross-language public key cannot
            // be parsed by this (spec-conformant, big-endian) decoder, i.e. the
            // vectors are non-conformant or the decoder regressed. The old
            // self-test fallback masked exactly the little-endian divergence
            // that the falcon-upstream gate later exposed. See
            // test-vectors/falcon-upstream/README.md.
            panic!(
                "Falcon-512 cross-lang PK decode failed ({:?}). The canonical \
                 falcon512_cross_lang.json must be big-endian conformant — \
                 regenerate it with `cargo run --example generate_crosslang_vectors`.",
                e
            );
        }
    }
}

#[test]
fn test_crosslang_falcon1024() {
    let vectors_dir = find_vectors_dir();
    let json_path = vectors_dir.join("falcon1024_cross_lang.json");
    // The cross-language oracle is tracked in this repo: a missing file is
    // a broken checkout, not a skip (audit A28) — FAIL instead of going green.
    let data = fs::read_to_string(&json_path)
        .unwrap_or_else(|e| panic!("cross-language vectors missing at {} ({e})", json_path.display()));
    let vf: VectorFile = serde_json::from_str(&data).unwrap();

    let pk_bytes = hex_decode(&vf.public_key);
    match metamui_falcon512::falcon1024::PublicKey1024::from_bytes(&pk_bytes) {
        Ok(pk) => {
            let mut passed = 0;
            for v in &vf.vectors {
                let msg_bytes = if v.message_hex.is_empty() {
                    vec![]
                } else {
                    hex_decode(&v.message_hex)
                };
                let sig_bytes = hex_decode(&v.signature_hex);

                let result = metamui_falcon512::falcon1024::verify_1024(&msg_bytes, &sig_bytes, &pk)
                    .expect("verify_1024 returned Err");
                assert!(
                    result,
                    "Falcon-1024 cross-lang verify failed for vector {}: {:?}",
                    v.id, v.message
                );
                passed += 1;
                println!("  [{}] {}... PASSED", v.id, &v.message[..v.message.len().min(40)]);
            }
            println!(
                "\nRust {}: {}/{} verified",
                vf.algorithm, passed, vf.vectors.len()
            );

            let mut rejected = 0;
            for tv in &vf.tampered_vectors {
                let msg = if tv.message_hex.is_empty() { vec![] } else { hex_decode(&tv.message_hex) };
                let sig = hex_decode(&tv.signature_hex);
                let ok = metamui_falcon512::falcon1024::verify_1024(&msg, &sig, &pk).unwrap_or(false);
                assert!(!ok, "Falcon-1024 tamper vector {} unexpectedly verified", tv.id);
                rejected += 1;
            }
            if !vf.tampered_vectors.is_empty() {
                println!("Rust {}: {}/{} tamper vectors correctly rejected",
                    vf.algorithm, rejected, vf.tampered_vectors.len());
            }
        }
        Err(e) => {
            // HARD FAIL — see the Falcon-512 case above. No silent self-test.
            panic!(
                "Falcon-1024 cross-lang PK decode failed ({:?}). The canonical \
                 falcon1024_cross_lang.json must be big-endian conformant — \
                 regenerate it with `cargo run --example generate_crosslang_vectors`.",
                e
            );
        }
    }
}
