//! FIPS 203 §6's internal algorithms stay behind `fips203-internal` (#202).
//!
//! `generate_keypair_from_dz`, `encapsulate_deterministic` and
//! `generate_keypair_from_seed` take the randomness from the caller. This test
//! reads the crate's own sources and fails on any public function or
//! re-export with such a name that is not compiled under that feature, so a
//! new parameter set or a refactor cannot put one back on the default surface.
//! The same rule for the release facade is `metamui-crypto`'s
//! `no_test_entropy_surface`.
//!
//! It also fails when the crate's tests stop enabling the feature on
//! themselves: without that dev-dependency the ACVP and KAT gates stop
//! compiling, and the tempting fix — `required-features` — would let
//! `cargo test` skip them silently.

use std::fs;
use std::path::{Path, PathBuf};

const INTERNAL_NAMES: &[&str] = &["from_dz", "from_seed", "deterministic"];
const FEATURE: &str = "fips203-internal";

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// The attribute and doc-comment lines directly above line `n`.
fn attributes_above(lines: &[&str], n: usize) -> Vec<String> {
    let mut attrs = Vec::new();
    let mut i = n;
    while i > 0 {
        i -= 1;
        let t = lines[i].trim_start();
        if t.starts_with("#[") || t.starts_with("///") {
            attrs.push(t.to_string());
        } else {
            break;
        }
    }
    attrs
}

/// A public item that names an internal entry point: `pub fn NAME` or a
/// `pub use` whose (possibly multi-line) list includes NAME.
fn internal_items(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut items = Vec::new();
    let mut n = 0;
    while n < lines.len() {
        let t = lines[n].trim_start();
        if t.starts_with("pub fn ") {
            let name: String = t["pub fn ".len()..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if INTERNAL_NAMES.iter().any(|w| name.contains(w)) {
                items.push((n, name));
            }
        } else if t.starts_with("pub use ") {
            let start = n;
            let mut stmt = t.to_string();
            while !stmt.contains(';') && n + 1 < lines.len() {
                n += 1;
                stmt.push_str(lines[n].trim());
            }
            if INTERNAL_NAMES.iter().any(|w| stmt.contains(w)) {
                items.push((start, stmt));
            }
        }
        n += 1;
    }
    items
}

fn gated(attrs: &[String]) -> bool {
    attrs
        .iter()
        .any(|a| a.starts_with("#[cfg(") && a.contains(&format!("feature = \"{FEATURE}\"")))
}

#[test]
fn every_internal_entry_point_is_compiled_only_with_the_feature() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lib = fs::read_to_string(root.join("src/lib.rs")).unwrap();
    // The engine's functions are `pub` inside a crate-private module; they
    // reach callers only through the per-set wrappers checked below.
    assert!(lib.contains("pub(crate) mod kem;"), "src/lib.rs must keep the engine module crate-private");

    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut checked = 0;
    let mut offenders = Vec::new();
    for path in files {
        let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        // `src/optimized/` is not a module of the crate (lib.rs declares no
        // `mod optimized`), so nothing in it is compiled.
        if rel == "src/kem.rs" || rel.starts_with("src/optimized/") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (n, item) in internal_items(&text) {
            checked += 1;
            if !gated(&attributes_above(&lines, n)) {
                offenders.push(format!("{rel}:{}: {item}", n + 1));
            }
        }
    }
    // Three names on three parameter sets, plus the 768 and crate-root re-exports.
    assert!(checked >= 11, "expected to find the internal entry points, saw {checked}");
    assert!(offenders.is_empty(), "internal entry points outside `{FEATURE}`:\n{}", offenders.join("\n"));
}

#[test]
fn the_crate_tests_enable_the_feature_on_themselves() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let dev = manifest
        .split("[dev-dependencies]")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .expect("Cargo.toml has a [dev-dependencies] table");
    let own = dev
        .lines()
        .find(|l| l.trim_start().starts_with("metamui-mlkem "))
        .expect("metamui-mlkem is a dev-dependency of itself");
    assert!(own.contains("path = \".\"") && own.contains(FEATURE), "self dev-dependency must enable {FEATURE}: {own}");
    assert!(!own.contains("version"), "a versioned self dev-dependency would survive packaging: {own}");
    assert!(cfg!(feature = "fips203-internal"), "this test binary was built without {FEATURE}");

    // A `required-features` on a test target is the silent skip this layout replaces.
    for block in manifest.split("[[test]]").skip(1) {
        let block = block.split("\n[").next().unwrap_or("");
        assert!(!block.contains("required-features"), "a [[test]] target carries required-features:\n{block}");
    }
}
