//! The facade's public surface must not offer deterministic or seeded
//! entropy. This test reads the crate's own sources and fails on any public
//! function whose name suggests one, so the rule survives refactors that a
//! reviewer might not read line by line.
//!
//! What *is* allowed: every randomized operation takes `&mut R where R:
//! RngCore + CryptoRng`. A caller may pass a seeded `CryptoRng`; that is the
//! caller's protocol decision and leaves no such entry point in this crate.

use std::fs;
use std::path::Path;

const FORBIDDEN: &[&str] = &[
    "deterministic",
    "from_seed",
    "from_dz",
    "with_seed",
    "seeded",
    "_kat",
    "kat_",
    "test_rng",
    "fixed_rng",
    "insecure",
];

#[test]
fn no_public_function_offers_deterministic_entropy() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0;
    let mut offenders = Vec::new();
    for entry in fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        for (n, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if !(t.starts_with("pub fn ") || t.starts_with("pub const fn ") || t.starts_with("pub(crate) fn ")) {
                continue;
            }
            checked += 1;
            let lower = t.to_ascii_lowercase();
            for word in FORBIDDEN {
                if lower.contains(word) {
                    offenders.push(format!("{}:{}: {}", path.display(), n + 1, t));
                }
            }
        }
    }
    assert!(checked > 10, "expected to scan the facade's public functions, saw {checked}");
    assert!(offenders.is_empty(), "deterministic-entropy surface found:\n{}", offenders.join("\n"));
}

#[test]
fn every_randomized_operation_requires_a_cryptographic_rng() {
    // Every generic `rng` parameter must carry the CryptoRng bound.
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut seen = 0;
    for entry in fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        for (n, line) in text.lines().enumerate() {
            if line.contains("pub fn ") && line.contains("<R:") {
                seen += 1;
                assert!(line.contains("CryptoRng"), "{}:{}: generic RNG without CryptoRng bound: {}", path.display(), n + 1, line.trim());
            }
        }
    }
    assert!(seen >= 5, "expected the randomized entry points to be generic over R, saw {seen}");
}
