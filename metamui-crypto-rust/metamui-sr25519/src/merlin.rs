//! Merlin transcript protocol (v1.0) — byte-for-byte compatible with
//! the canonical `merlin` crate used by w3f/schnorrkel.
//!
//! The previous version of this file was close but not spec-correct.
//! Three deviations surfaced during Phase 3 of the sr25519 compliance
//! work (`documents/project/sr25519-compliance-plan.md`):
//!
//!   1. **Initialization** — the real protocol is
//!      `STROBE-128("Merlin v1.0")` followed by
//!      `append_message("dom-sep", <caller-label>)`. The prior code
//!      initialized STROBE directly with the caller label and skipped
//!      the `dom-sep` framing.
//!
//!   2. **`append_message` layout** — spec says
//!      `meta-AD: label || LE32(len(msg))` emitted as a SINGLE
//!      meta-AD (with `more=true` continuation), followed by
//!      `AD: msg`. The prior code emitted a three-part sequence of
//!      length-prefixed meta-AD calls, each with `more=false`.
//!
//!   3. **`challenge_bytes` layout** — same framing story as (2),
//!      followed by `prf(dest)`.
//!
//! Parity is enforced byte-for-byte by
//! `tests/merlin_parity_kat.rs`, which scripts both this impl and
//! `merlin = "=3.0.0"` through the same call sequence and compares
//! challenge outputs.

use super::strobe::Strobe;

/// Domain separator that STROBE is initialized with, before any
/// caller-supplied label. Matches `merlin::constants::MERLIN_PROTOCOL_LABEL`.
const MERLIN_PROTOCOL_LABEL: &[u8] = b"Merlin v1.0";

/// Merlin transcript — wraps a STROBE-128 state with the Merlin v1.0
/// domain-separation and framing conventions.
pub struct MerlinTranscript {
    strobe: Strobe,
}

impl MerlinTranscript {
    /// Build a new transcript. Per RFC-style spec:
    ///
    /// ```text
    /// Strobe-128(b"Merlin v1.0")
    /// append_message(b"dom-sep", label)
    /// ```
    pub fn new(label: &[u8]) -> Self {
        let mut t = Self {
            strobe: Strobe::new(MERLIN_PROTOCOL_LABEL),
        };
        t.append_message(b"dom-sep", label);
        t
    }

    /// Append a `(label, message)` pair under Merlin framing:
    /// `meta-AD: label || LE32(len(message))` (single meta-AD,
    /// `more=true` for the length byte run) then `AD: message`.
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        let len = encode_u32_le(message.len() as u32);
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&len, true);
        self.strobe.ad(message, false);
    }

    /// Convenience wrapper for committing a 64-bit little-endian value.
    pub fn append_u64(&mut self, label: &[u8], value: u64) {
        self.append_message(label, &value.to_le_bytes());
    }

    /// Extract `dest.len()` bytes of challenge output into `dest`.
    /// Layout: `meta-AD: label || LE32(len(dest))` (single meta-AD
    /// with `more=true` continuation), then `PRF(dest)`.
    pub fn challenge_bytes(&mut self, label: &[u8], dest: &mut [u8]) {
        let len = encode_u32_le(dest.len() as u32);
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&len, true);
        let out = self.strobe.prf(dest.len(), false);
        dest.copy_from_slice(&out);
    }

    /// 32-byte challenge, returned by value.
    pub fn challenge_scalar(&mut self, label: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.challenge_bytes(label, &mut out);
        out
    }

    /// 64-byte challenge (used by `Scalar::from_bytes_mod_order_wide`).
    pub fn challenge_scalar_wide(&mut self, label: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.challenge_bytes(label, &mut out);
        out
    }

    /// Deep-clone — the STROBE state is `Clone` so the transcript can
    /// be forked prior to a challenge extraction without mutating the
    /// caller's view.
    pub fn clone(&self) -> Self {
        Self { strobe: self.strobe.clone() }
    }

    /// Convenience: the schnorrkel `SigningContext::new(ctx).bytes(msg)`
    /// transcript in two lines.
    ///
    /// Returns a transcript positioned exactly where `sign_simple` /
    /// `verify_simple` would pass it into `Keypair::sign`.
    pub fn for_signing_context(context: &[u8], message: &[u8]) -> Self {
        let mut t = Self::new(b"SigningContext");
        t.append_message(b"", context);
        t.append_message(b"sign-bytes", message);
        t
    }

    /// Historic HDKD transcript helper — preserved so existing callers
    /// (see derivation.rs) keep compiling during the Phase 3 cut-over.
    pub fn for_schnorrkel() -> Self {
        Self::new(b"SchnorrRistrettoHDKD")
    }
}

#[inline]
fn encode_u32_le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic sanity check — the real byte-level parity test
    /// lives in `tests/merlin_parity_kat.rs` where the reference
    /// `merlin` crate is available.
    #[test]
    fn challenge_is_deterministic_for_same_script() {
        let mut a = MerlinTranscript::new(b"proto");
        let mut b = MerlinTranscript::new(b"proto");
        a.append_message(b"k", b"v");
        b.append_message(b"k", b"v");
        assert_eq!(a.challenge_scalar(b"c"), b.challenge_scalar(b"c"));
    }

    #[test]
    fn different_messages_diverge() {
        let mut a = MerlinTranscript::new(b"proto");
        let mut b = MerlinTranscript::new(b"proto");
        a.append_message(b"k", b"v1");
        b.append_message(b"k", b"v2");
        assert_ne!(a.challenge_scalar(b"c"), b.challenge_scalar(b"c"));
    }
}
