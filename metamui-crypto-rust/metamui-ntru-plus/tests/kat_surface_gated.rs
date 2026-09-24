//! Every seeded entry point of this crate must be compiled only with the
//! `kat-internal` feature. This test reads `src/kem.rs` and fails if one of
//! them is declared without the gate, so the rule survives refactors.

use std::fs;
use std::path::Path;

const GATED: &[&str] = &[
    "pub fn generate_keypair_det<P: NtruPlusParams, F: FnMut(&mut [u8])>(",
    "pub fn encapsulate_det<P: NtruPlusParams, F: FnMut(&mut [u8])>(",
];

#[test]
fn seeded_entry_points_are_behind_kat_internal() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/kem.rs");
    let text = fs::read_to_string(&src).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let mut missing = Vec::new();
    for decl in GATED {
        let idx = lines
            .iter()
            .position(|l| l.trim() == *decl)
            .unwrap_or_else(|| panic!("`{decl}` not declared in src/kem.rs"));
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
fn randombytes_taking_bodies_are_crate_private() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/kem.rs");
    let text = fs::read_to_string(&src).unwrap();
    for body in ["keypair_from_randombytes", "encapsulate_from_randombytes"] {
        assert!(
            text.lines().any(|l| l.trim().starts_with(&format!("pub(crate) fn {body}<"))),
            "`pub(crate) fn {body}` missing"
        );
        assert!(
            !text.lines().any(|l| l.trim().starts_with(&format!("pub fn {body}<"))),
            "`pub fn {body}` is public"
        );
    }
}
