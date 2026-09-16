//! Every seeded or known-answer module of this crate must be compiled only
//! with the `kat-internal` feature. This test reads `src/lib.rs` and fails if
//! one of them is declared without the gate, so the rule survives refactors.

use std::fs;
use std::path::Path;

const GATED: &[&str] = &[
    "kat_api",
    "kat_nist",
    "deterministic_rng",
    "deterministic_mode",
    "differential_testing",
    "security_audit",
    "nist_validation",
    "test_helpers",
    "nist_kat_framework",
    "nist_vector_parser",
    "nist_vectors",
    "nist_vectors_generated",
    "nist_api",
    "nist_kat_test",
];

#[test]
fn seeded_modules_are_behind_kat_internal() {
    let lib = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let text = fs::read_to_string(&lib).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let mut missing = Vec::new();
    for name in GATED {
        let decl = format!("pub mod {name};");
        let idx = lines
            .iter()
            .position(|l| l.trim() == decl)
            .unwrap_or_else(|| panic!("{decl} not declared in src/lib.rs"));
        let gated = idx > 0 && lines[idx - 1].trim() == "#[cfg(feature = \"kat-internal\")]";
        if !gated {
            missing.push(decl);
        }
    }
    assert!(missing.is_empty(), "seeded modules compiled without `kat-internal`:\n{}", missing.join("\n"));
}

#[test]
fn drbg_kat_constructor_is_behind_kat_internal() {
    let drbg = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/drbg.rs");
    let text = fs::read_to_string(&drbg).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let idx = lines
        .iter()
        .position(|l| l.trim().starts_with("pub fn new_for_kat"))
        .expect("NistCtrDrbg::new_for_kat declared");
    assert_eq!(lines[idx - 1].trim(), "#[cfg(feature = \"kat-internal\")]", "new_for_kat is not gated");
}
