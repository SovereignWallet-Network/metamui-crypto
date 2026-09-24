//! Every seeded entry point of this crate must be compiled only with the
//! `kat-internal` feature. This test reads `src/sign.rs` and fails if one of
//! them is declared without the gate, so the rule survives refactors.

use std::fs;
use std::path::Path;

const GATED: &[&str] = &[
    "pub fn crypto_sign_keypair_internal(",
    "pub fn crypto_sign_signature_internal(",
];

#[test]
fn seeded_entry_points_are_behind_kat_internal() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sign.rs");
    let text = fs::read_to_string(&src).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let mut missing = Vec::new();
    for decl in GATED {
        let idx = lines
            .iter()
            .position(|l| l.trim() == *decl)
            .unwrap_or_else(|| panic!("`{decl}` not declared in src/sign.rs"));
        let gated = idx > 0 && lines[idx - 1].trim() == "#[cfg(feature = \"kat-internal\")]";
        if !gated {
            missing.push(*decl);
        }
    }
    assert!(
        missing.is_empty(),
        "seeded entry points compiled without `kat-internal`:\n{}",
        missing.join("\n")
    );
}

#[test]
fn seed_taking_bodies_are_crate_private() {
    // The bodies the randomized API feeds an OS seed into must not be `pub`.
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sign.rs");
    let text = fs::read_to_string(&src).unwrap();
    for body in ["keypair_internal(", "signature_internal("] {
        let decl = format!("pub(crate) fn {body}");
        assert!(text.lines().any(|l| l.trim() == decl), "`{decl}` missing");
        let leaked = format!("pub fn {body}");
        assert!(!text.lines().any(|l| l.trim() == leaked), "`{leaked}` is public");
    }
}
