//! Every seeded entry point of this crate must be compiled only with the
//! `kat-internal` feature. This test reads the three parameter-set sources and
//! fails if `generate_keypair_from_seed` (FIPS 204 `ML-DSA.KeyGen_internal`)
//! is declared without the gate, so the rule survives refactors.
//!
//! `operations::challenge_from_seed` is SampleInBall over the challenge hash,
//! an internal step of every signature, not a seeded entry; `sign_deterministic`
//! and `sign` are the FIPS 204 deterministic variant (`rnd = 0^32`). Neither
//! is gated.

use std::fs;
use std::path::Path;

const SOURCES: &[&str] = &["src/dilithium2.rs", "src/dilithium3.rs", "src/dilithium5.rs"];
const SEEDED: &str = "pub fn generate_keypair_from_seed(";
const GATE: &str = "#[cfg(feature = \"kat-internal\")]";

#[test]
fn seeded_keygen_is_behind_kat_internal() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut missing = Vec::new();
    for src in SOURCES {
        let text = fs::read_to_string(root.join(src)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let hits: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.trim().starts_with(SEEDED))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits.len(), 1, "{src}: expected exactly one `{SEEDED}`, found {}", hits.len());
        let idx = hits[0];
        if idx == 0 || lines[idx - 1].trim() != GATE {
            missing.push(format!("{src}:{}", idx + 1));
        }
    }
    assert!(missing.is_empty(), "seeded key generation compiled without `kat-internal`:\n{}", missing.join("\n"));
}

#[test]
fn seeded_keygen_is_reachable_with_the_feature() {
    // The dev-dependency on this crate turns `kat-internal` on for its own
    // tests, so the gated entry must exist and be the pure function it claims.
    let seed = [7u8; 32];
    let (pk1, sk1) = metamui_dilithium::Dilithium2::generate_keypair_from_seed(&seed);
    let (pk2, sk2) = metamui_dilithium::Dilithium2::generate_keypair_from_seed(&seed);
    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);
}
