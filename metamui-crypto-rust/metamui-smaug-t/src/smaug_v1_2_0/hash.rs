// SPDX-License-Identifier: Apache-2.0
//
// Hash function wrappers for SMAUG-T v1.2.0, over the in-house MetaMUI
// primitives: `metamui_shake` (SHAKE-128/256) and `metamui_sha3`
// (SHA3-256/512). No RustCrypto crate is in this crate's dependency closure
// (issue #232 follow-up recorded on #199).
//
// Mirrors `include/hash.h` and `include/fips202.h` of the KS X 123456
// reference:
//   - `hash_h(out, in, len)`   = SHA3-256
//   - `hash_g(out, outlen, in1, len1, in2, len2)` = SHAKE-256 absorb-twice-squeeze
//   - `shake128(out, outlen, in, inlen)` = single-shot SHAKE-128
//   - `shake256(out, outlen, in, inlen)` = single-shot SHAKE-256
//   - `sha3_512(out, in, inlen)` = SHA3-512 → 64-byte digest
//   - `sha3_256(out, in, inlen)` = SHA3-256 → 32-byte digest

use metamui_shake::{Shake128, Shake256};

/// SHA3-256 → 32-byte digest. Used as `hash_h` in the KEM.
pub fn sha3_256(out: &mut [u8], input: &[u8]) {
    out.copy_from_slice(&metamui_sha3::sha3_256(input));
}

/// SHA3-512 → 64-byte digest. Used in `indcpa_keypair` to expand the
/// 32-byte input seed into (s-seed, pk-seed).
pub fn sha3_512(out: &mut [u8], input: &[u8]) {
    out.copy_from_slice(&metamui_sha3::sha3_512(input));
}

/// SHAKE-128 single-shot XOF. Used by `expand_A` to derive matrix-A
/// coefficient bytes per (i, j) cell.
pub fn shake128(out: &mut [u8], input: &[u8]) {
    let mut h = Shake128::new();
    h.update(input);
    h.finalize_xof().read_into(out);
}

/// SHAKE-256 single-shot XOF. Used by `expand_r`, `expand_s` (via `hwt`),
/// and `d_gaussian_poly`.
pub fn shake256(out: &mut [u8], input: &[u8]) {
    let mut state = Shake256State::new();
    state.absorb(input);
    state.squeeze_into(out);
}

/// SHAKE-256 absorb-twice-squeeze (the macro-expanded `hash_g`). Used
/// to derive `buf = K || r_seed` from `mu` and `H(pk)` (or `H(ct)` on
/// the rejection path).
pub fn shake256_absorb_twice_squeeze(
    out: &mut [u8],
    input1: &[u8],
    input2: &[u8],
) {
    let mut state = Shake256State::new();
    state.absorb(input1);
    state.absorb(input2);
    state.squeeze_into(out);
}

/// Streaming SHAKE-256 (used by `hwt` which absorbs the seed once and
/// squeezes the body + sign bytes separately).
pub struct Shake256State(Shake256);

impl Shake256State {
    pub fn new() -> Self {
        Self(Shake256::new())
    }

    pub fn absorb(&mut self, input: &[u8]) {
        // `update` only fails after finalization, which this type's
        // ownership rules make unreachable (`squeeze_into` consumes self).
        self.0
            .update(input)
            .expect("SHAKE-256 state is absorbing until squeeze_into");
    }

    /// Finalize and squeeze `out.len()` bytes. After calling `squeeze`,
    /// subsequent `squeeze` calls continue the same stream — matching
    /// the upstream behavior of `shake256_init` / `shake256_absorb_once` /
    /// `shake256_squeeze` (called multiple times).
    pub fn squeeze_into(self, out: &mut [u8]) -> Shake256Reader {
        let mut r = Shake256Reader(self.0.finalize_xof());
        r.squeeze(out);
        r
    }
}

impl Default for Shake256State {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Shake256Reader(metamui_shake::Shake256Reader);

impl Shake256Reader {
    pub fn squeeze(&mut self, out: &mut [u8]) {
        let bytes = self.0.read(out.len());
        out.copy_from_slice(&bytes);
    }
}
