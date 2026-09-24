//! Every seeded entry point of this crate must be compiled only with the
//! `kat-internal` feature. This test reads the source files and fails if one
//! of them is declared without the gate, so the rule survives refactors.

use std::fs;
use std::path::Path;

/// (source file, declaration prefix) for each gated function.
const GATED: &[(&str, &str)] = &[
    ("src/lib.rs", "pub fn keygen_from_seed"),
    ("src/smaug_v1_2_0/api.rs", "pub fn keygen_from_seed"),
    ("src/smaug_v1_2_0/api.rs", "pub fn keygen_internal"),
    ("src/smaug_v1_2_0/api.rs", "pub fn encapsulate_internal"),
    ("src/smaug_v1_2_0/kem.rs", "pub fn crypto_kem_keypair_internal"),
    ("src/smaug_v1_2_0/kem.rs", "pub fn crypto_kem_enc_internal"),
    ("src/smaug_v1_2_0/kem.rs", "pub fn crypto_kem_dec_internal"),
];

#[test]
fn seeded_entry_points_are_behind_kat_internal() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut missing = Vec::new();
    for (file, decl) in GATED {
        let text = fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let lines: Vec<&str> = text.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.trim().starts_with(decl))
            .unwrap_or_else(|| panic!("{decl} not declared in {file}"));
        let gated = idx > 0 && lines[idx - 1].trim() == "#[cfg(feature = \"kat-internal\")]";
        if !gated {
            missing.push(format!("{file}: {decl}"));
        }
    }
    assert!(
        missing.is_empty(),
        "seeded entry points compiled without `kat-internal`:\n{}",
        missing.join("\n")
    );
}
