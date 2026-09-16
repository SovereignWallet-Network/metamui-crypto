//! Shared helpers for the facade's conformance tests.
//!
//! The fixtures are the repository's vendored upstream answer files under
//! `test-vectors/`; nothing here generates vectors. A missing fixture file is
//! a test failure, never a skip.

#![allow(dead_code)]

use std::path::PathBuf;

use rand_core::{CryptoRng, RngCore, SeedableRng};

/// `test-vectors/<rel>` resolved from this crate's manifest directory.
pub fn vectors_path(rel: &str) -> PathBuf {
    let mut p = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    p.pop(); // metamui-crypto-rust
    p.pop(); // repository root
    p.push("test-vectors");
    p.push(rel);
    p
}

/// Read a fixture; a missing file fails loudly with its path.
pub fn read_fixture(rel: &str) -> String {
    let p = vectors_path(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("fixture {} unreadable: {e}", p.display()))
}

pub fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("hex")
}

/// An RNG that hands out a fixed byte string and then panics.
///
/// This is what lets the upstream KAT be replayed through the *production*
/// entry points: FIPS 203 keygen draws `d ‖ z` and encapsulation draws `m`
/// from the RNG, so queuing exactly those bytes reproduces the answer file
/// without any deterministic API in the crate under test. Running out of
/// bytes is a bug in the test or a change in the backend's draw pattern, and
/// either must surface.
pub struct ScriptedRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl ScriptedRng {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, pos: 0 }
    }

    pub fn exhausted(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

impl RngCore for ScriptedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let end = self.pos + dest.len();
        assert!(end <= self.bytes.len(), "ScriptedRng exhausted: asked {} bytes at offset {}, have {}", dest.len(), self.pos, self.bytes.len());
        dest.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// The scripted stream is test-only; the marker is what the facade's bounds
// require, and it is implemented here, in a test, on purpose.
impl CryptoRng for ScriptedRng {}

/// An unbounded, seeded `CryptoRng` for operations whose draw count is not a
/// fixed part of the specification (Falcon's Gaussian sampler draws until it
/// accepts). Seeded so a failure reproduces; still a caller-side choice that
/// the facade neither offers nor knows about.
pub fn seeded_rng(seed: u8) -> rand_chacha::ChaCha20Rng {
    rand_chacha::ChaCha20Rng::from_seed([seed; 32])
}

/// Minimal NIST `.rsp` record reader: returns each record as a list of
/// `(field, value)` pairs in file order.
pub fn parse_rsp(content: &str) -> Vec<Vec<(String, String)>> {
    let mut records = Vec::new();
    let mut cur: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            if !cur.is_empty() {
                records.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(" = ") {
            cur.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    if !cur.is_empty() {
        records.push(cur);
    }
    records
}

pub fn field<'a>(rec: &'a [(String, String)], name: &str) -> &'a str {
    rec.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).unwrap_or_else(|| panic!("record lacks {name}"))
}
