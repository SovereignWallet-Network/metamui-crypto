//! STROBE-128 — byte-for-byte compatible with `merlin::Strobe128`.
//!
//! The prior in-tree STROBE deviated from the spec in at least two
//! places:
//!
//!   * **Init block byte[1]** was `0` instead of `STROBE_R + 2 = 168`.
//!     That meant every transcript built on top started from a
//!     different permutation fixed point, so even a correct Merlin
//!     layout on top produced divergent challenges.
//!   * **Mid-stream rate-crossings** (message or challenge > 166 B)
//!     skipped the `run_f` boundary because `operate()` only ran the
//!     padding-and-permute block on entry to the operation, not when
//!     `pos` hit `STROBE_R` during the operation. The tampered-state
//!     then silently accumulated inside a single rate block until the
//!     next `begin_op`.
//!
//! The rewrite below mirrors the reference `merlin/src/strobe.rs`
//! structure 1:1 — `absorb`/`overwrite`/`squeeze` each advance one
//! byte at a time and call `run_f` as soon as `pos` hits `STROBE_R`,
//! and `begin_op` matches merlin's `absorb(&[old_begin, flags])`
//! convention. Parity is enforced byte-for-byte by
//! `tests/merlin_parity_kat.rs`.

use metamui_sha3::keccak::keccak_f;

extern crate alloc;
use alloc::{vec, vec::Vec};

/// STROBE rate (bytes). Security level 128 → R = 168 - 2 = 166.
pub(crate) const STROBE_R: usize = 166;

// STROBE flag bits. Only `A`, `C`, `I`, `M`, `K` are used downstream;
// `T` (transport / send_clr+recv_clr) is kept as a documentation-only
// constant — `#[allow(dead_code)]` because we don't expose those ops.
pub(crate) const FLAG_I: u8 = 1 << 0;
pub(crate) const FLAG_A: u8 = 1 << 1;
pub(crate) const FLAG_C: u8 = 1 << 2;
#[allow(dead_code)]
pub(crate) const FLAG_T: u8 = 1 << 3;
pub(crate) const FLAG_M: u8 = 1 << 4;
pub(crate) const FLAG_K: u8 = 1 << 5;

/// STROBE-128 state. Byte-addressable view over a `[u64; 25]` Keccak
/// state (little-endian per lane).
#[derive(Clone)]
pub struct Strobe {
    state: [u64; 25],
    pos: usize,
    pos_begin: usize,
    cur_flags: u8,
}

impl Strobe {
    /// Spec init sequence (STROBE v1.0.2):
    ///
    /// ```text
    /// state[0..6]  = [1, R+2, 1, 0, 1, 96]
    /// state[6..18] = b"STROBEv1.0.2"
    /// run keccak-f[1600] once
    /// meta_ad(protocol_label, more=false)
    /// ```
    pub fn new(protocol_label: &[u8]) -> Self {
        let mut s = Self {
            state: [0u64; 25],
            pos: 0,
            pos_begin: 0,
            cur_flags: 0,
        };
        // Header bytes xor-ed in. The magic byte[1] = R+2 = 168 is the
        // one that distinguishes a spec-compliant STROBE from the
        // previous (broken) in-tree version.
        let header: [u8; 18] = [
            0x01, (STROBE_R as u8) + 2, 0x01, 0x00, 0x01, 0x60,
            b'S', b'T', b'R', b'O', b'B', b'E',
            b'v', b'1', b'.', b'0', b'.', b'2',
        ];
        for (i, &b) in header.iter().enumerate() {
            s.xor_state_byte(i, b);
        }
        keccak_f(&mut s.state);

        // meta-AD the caller-supplied protocol label.
        s.meta_ad(protocol_label, false);
        s
    }

    // -----------------------------------------------------------------
    // Public STROBE operations. `more = true` continues the current op
    // without emitting a new op boundary (spec: skip the begin-op
    // absorption of `[old_begin, flags]`).
    // -----------------------------------------------------------------

    pub fn ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A, more);
        self.absorb(data);
    }

    pub fn meta_ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_A, more);
        self.absorb(data);
    }

    pub fn key(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A | FLAG_C, more);
        self.overwrite(data);
    }

    pub fn prf(&mut self, length: usize, more: bool) -> Vec<u8> {
        self.begin_op(FLAG_I | FLAG_A | FLAG_C, more);
        let mut out = vec![0u8; length];
        self.squeeze(&mut out);
        out
    }

    // -----------------------------------------------------------------
    // Internal: run_f / absorb / overwrite / squeeze / begin_op
    // -----------------------------------------------------------------

    /// Standard STROBE padding + permutation. Matches merlin exactly.
    fn run_f(&mut self) {
        self.xor_state_byte(self.pos, self.pos_begin as u8);
        self.xor_state_byte(self.pos + 1, 0x04);
        self.xor_state_byte(STROBE_R + 1, 0x80);
        keccak_f(&mut self.state);
        self.pos = 0;
        self.pos_begin = 0;
    }

    /// XOR bytes into state one at a time, running F at rate boundaries.
    fn absorb(&mut self, data: &[u8]) {
        for &b in data {
            self.xor_state_byte(self.pos, b);
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    /// Overwrite state bytes (used by `key`). Same rate-boundary rules.
    fn overwrite(&mut self, data: &[u8]) {
        for &b in data {
            self.set_state_byte(self.pos, b);
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    /// Extract state bytes, zeroing them as they leave (squeeze with
    /// erasure, per STROBE v1.0.2 §4 PRF semantics).
    fn squeeze(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            *byte = self.get_state_byte(self.pos);
            self.set_state_byte(self.pos, 0);
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    /// `more = true` asserts flag-continuity and skips the begin
    /// sentinel; `more = false` emits `[old_begin, flags]` and — if
    /// the op requires cipher state (C or K flag) and `pos != 0` —
    /// forces a permutation.
    fn begin_op(&mut self, flags: u8, more: bool) {
        if more {
            debug_assert_eq!(
                self.cur_flags, flags,
                "STROBE: continuation (more=true) with different flags"
            );
            return;
        }
        let old_begin = self.pos_begin as u8;
        self.pos_begin = self.pos + 1;
        self.cur_flags = flags;
        self.absorb(&[old_begin, flags]);

        let force_f = (flags & (FLAG_C | FLAG_K)) != 0;
        if force_f && self.pos != 0 {
            self.run_f();
        }
    }

    // -----------------------------------------------------------------
    // Byte-addressable view into the Keccak `[u64; 25]` state.
    // Little-endian per lane — matches merlin's `AlignedKeccakState`
    // transmute behaviour on every little-endian platform (x86,
    // aarch64, wasm32).
    // -----------------------------------------------------------------

    #[inline]
    fn xor_state_byte(&mut self, i: usize, v: u8) {
        let lane = i / 8;
        let bit = (i % 8) * 8;
        self.state[lane] ^= (v as u64) << bit;
    }

    #[inline]
    fn set_state_byte(&mut self, i: usize, v: u8) {
        let lane = i / 8;
        let bit = (i % 8) * 8;
        let mask = !(0xffu64 << bit);
        self.state[lane] = (self.state[lane] & mask) | ((v as u64) << bit);
    }

    #[inline]
    fn get_state_byte(&self, i: usize) -> u8 {
        let lane = i / 8;
        let bit = (i % 8) * 8;
        ((self.state[lane] >> bit) & 0xff) as u8
    }
}

// Public module constants used by legacy callers (debug logging etc.)
pub const STROBE_RATE: usize = STROBE_R;

#[cfg(test)]
mod tests {
    use super::*;

    /// `init → meta_ad → prf` conformance — the single most direct
    /// check that our STROBE implementation tracks state correctly.
    /// Byte-for-byte parity with the reference `merlin::Strobe128`
    /// is enforced by `tests/merlin_parity_kat.rs`; this is a local
    /// smoke test to catch gross regressions without pulling in the
    /// dev-dep.
    #[test]
    fn strobe_smoke_prf_is_nonzero() {
        let mut s = Strobe::new(b"test");
        s.meta_ad(b"label", false);
        let out = s.prf(32, false);
        assert_eq!(out.len(), 32);
        assert!(out.iter().any(|&b| b != 0), "PRF output must not be all zeros");
    }

    #[test]
    fn strobe_message_larger_than_rate_does_not_panic() {
        // Feeds 500 bytes through both `ad` and `prf` — 500 > R=166
        // so the rate-boundary logic inside absorb/squeeze is
        // exercised multiple times.
        let mut s = Strobe::new(b"test");
        s.meta_ad(b"long", false);
        s.ad(&vec![0xcc; 500], false);
        let out = s.prf(200, false);
        assert_eq!(out.len(), 200);
    }
}
