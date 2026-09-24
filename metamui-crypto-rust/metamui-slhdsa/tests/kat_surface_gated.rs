//! Every seeded or known-answer entry point of this crate must be compiled
//! only with the `kat-internal` feature. This test reads the source and fails
//! if one of them is declared without the gate, so the rule survives
//! refactors.

use std::fs;
use std::path::Path;

/// (file, declaration line, as `lines().trim()` sees it)
const GATED: &[(&str, &str)] = &[
    ("src/lib.rs", "pub mod test_vector_generator;"),
    ("src/lib.rs", "pub fn slh_keygen_from_seeds<P: Parameters>("),
    ("src/signing.rs", "pub fn slh_sign_core<P: Parameters>("),
    ("src/signing.rs", "pub fn slh_sign_internal<P: Parameters>("),
];

#[test]
fn seeded_entry_points_are_behind_kat_internal() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut missing = Vec::new();
    for (file, decl) in GATED {
        let text = fs::read_to_string(root.join(file)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.trim() == *decl)
            .unwrap_or_else(|| panic!("`{decl}` not declared in {file}"));
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

#[test]
fn no_public_seeded_entry_point_escapes_the_list() {
    // A new `pub fn` whose parameters name a seed or randomizer must join
    // GATED, or be `pub(crate)`.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for file in ["src/lib.rs", "src/signing.rs", "src/verification.rs", "src/types.rs"] {
        let text = fs::read_to_string(root.join(file)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (i, l) in lines.iter().enumerate() {
            let t = l.trim();
            if !t.starts_with("pub fn ") {
                continue;
            }
            // signature runs to the opening brace
            let sig: String = lines[i..].iter().take_while(|x| !x.contains('{')).cloned().collect::<Vec<_>>().join(" ");
            let seeded = sig.contains("sk_seed") || sig.contains("opt_rand");
            let listed = GATED.iter().any(|(f, d)| *f == file && t == *d);
            let gated = i > 0 && lines[i - 1].trim() == "#[cfg(feature = \"kat-internal\")]";
            // `slh_sign` / `slh_hash_sign_deterministic` / `slh_sign_deterministic` /
            // `slh_sign_randomized` / `slh_verify` take the split key, which the
            // FIPS 205 external interface also does; only an explicit randomizer
            // or a seeds-only keygen is the internal interface.
            let takes_randomizer = sig.contains("opt_rand");
            let seeds_only_keygen = t.contains("from_seeds");
            if seeded && (takes_randomizer || seeds_only_keygen) {
                assert!(listed && gated, "{file}:{}: `{t}` takes a seed or randomizer and is not gated", i + 1);
            }
        }
    }
}
