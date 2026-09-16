//! cSHAKE128 and cSHAKE256 (NIST SP 800-185 §3) plus the string-encoding
//! primitives the whole standard is built on (§2.3).
//!
//! `cSHAKE(X, L, N, S)`: when both the function name `N` and the
//! customization `S` are empty it IS `SHAKE(X, L)` (same `1111` suffix);
//! otherwise it absorbs `bytepad(encode_string(N) ‖ encode_string(S), rate)`
//! before `X` and closes with the `00` suffix. `X` may be any bit string
//! (`finalize_xof_bits`); `N` and `S` are byte strings here.
//!
//! Byte-exact to NIST ACVP cSHAKE-128/-256 1.0 (`test-vectors/sp800-185/`).

use crate::keccak::{KeccakReader, KeccakSponge};
use alloc::vec::Vec;

/// `left_encode(x)` (§2.3.1): big-endian `x` in the fewest bytes, preceded by
/// that byte count.
pub fn left_encode(x: u64) -> Vec<u8> {
    let mut n = 1;
    while n < 8 && (x >> (8 * n)) != 0 {
        n += 1;
    }
    let mut out = Vec::with_capacity(n + 1);
    out.push(n as u8);
    for i in (0..n).rev() {
        out.push((x >> (8 * i)) as u8);
    }
    out
}

/// `right_encode(x)` (§2.3.1): big-endian `x` in the fewest bytes, followed
/// by that byte count.
pub fn right_encode(x: u64) -> Vec<u8> {
    let mut n = 1;
    while n < 8 && (x >> (8 * n)) != 0 {
        n += 1;
    }
    let mut out = Vec::with_capacity(n + 1);
    for i in (0..n).rev() {
        out.push((x >> (8 * i)) as u8);
    }
    out.push(n as u8);
    out
}

/// `encode_string(S)` (§2.3.2) for a byte string: `left_encode(8·|S|) ‖ S`.
pub fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut out = left_encode((s.len() as u64) * 8);
    out.extend_from_slice(s);
    out
}

/// `bytepad(X, w)` (§2.3.3): `left_encode(w) ‖ X`, zero-padded to a multiple
/// of `w` bytes.
pub fn bytepad(x: &[u8], w: usize) -> Vec<u8> {
    let mut out = left_encode(w as u64);
    out.extend_from_slice(x);
    while out.len() % w != 0 {
        out.push(0);
    }
    out
}

/// Suffix bits for plain SHAKE (`1111`, LSB-first) and cSHAKE (`00`).
const SHAKE_SUFFIX: (u8, usize) = (0x0F, 4);
const CSHAKE_SUFFIX: (u8, usize) = (0x00, 2);

/// Generic cSHAKE over a byte rate `RATE`.
#[derive(Clone)]
pub struct Cshake<const RATE: usize> {
    sponge: KeccakSponge,
    /// `N` and `S` both empty: behave exactly as SHAKE.
    plain: bool,
}

/// cSHAKE128 (rate 168 bytes, 128-bit security).
pub type Cshake128 = Cshake<168>;
/// cSHAKE256 (rate 136 bytes, 256-bit security).
pub type Cshake256 = Cshake<136>;

impl<const RATE: usize> Cshake<RATE> {
    /// Start `cSHAKE(·, ·, function_name, customization)`.
    pub fn new(function_name: &[u8], customization: &[u8]) -> Self {
        let mut sponge = KeccakSponge::new(RATE);
        let plain = function_name.is_empty() && customization.is_empty();
        if !plain {
            let mut prefix = encode_string(function_name);
            prefix.extend_from_slice(&encode_string(customization));
            sponge.absorb(&bytepad(&prefix, RATE));
        }
        Self { sponge, plain }
    }

    /// Absorb whole message bytes.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.sponge.absorb(data);
        self
    }

    /// Absorb the first `nbits` bits of `data` (FIPS 202 `h2b`: a trailing
    /// partial byte holds its bits in the low positions).
    pub fn update_bits(&mut self, data: &[u8], nbits: usize) -> &mut Self {
        self.sponge.absorb_bits(data, nbits);
        self
    }

    /// Finish absorbing; the reader squeezes any number of bytes or bits.
    pub fn finalize_xof(self) -> KeccakReader {
        let (suffix, bits) = if self.plain { SHAKE_SUFFIX } else { CSHAKE_SUFFIX };
        self.sponge.finalize(suffix, bits)
    }

    /// Finish and squeeze `output_len` bytes.
    pub fn finalize(self, output_len: usize) -> Vec<u8> {
        self.finalize_xof().read(output_len)
    }

    /// One-shot over a byte string.
    pub fn hash(message: &[u8], output_len: usize, function_name: &[u8], customization: &[u8]) -> Vec<u8> {
        let mut c = Self::new(function_name, customization);
        c.update(message);
        c.finalize(output_len)
    }

    /// One-shot over the first `msg_bits` bits of `message`, producing
    /// `out_bits` bits (`ceil(out_bits / 8)` bytes, last byte low-aligned) —
    /// the NIST ACVP bit-oriented form.
    pub fn hash_bits(message: &[u8], msg_bits: usize, out_bits: usize, function_name: &[u8], customization: &[u8]) -> Vec<u8> {
        let mut c = Self::new(function_name, customization);
        c.update_bits(message, msg_bits);
        c.finalize_xof().read_bits(out_bits)
    }
}

/// `cSHAKE128(X, L, N, S)` with `L` in bytes.
pub fn cshake128(message: &[u8], output_len: usize, function_name: &[u8], customization: &[u8]) -> Vec<u8> {
    Cshake128::hash(message, output_len, function_name, customization)
}

/// `cSHAKE256(X, L, N, S)` with `L` in bytes.
pub fn cshake256(message: &[u8], output_len: usize, function_name: &[u8], customization: &[u8]) -> Vec<u8> {
    Cshake256::hash(message, output_len, function_name, customization)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings_match_sp800_185_examples() {
        assert_eq!(left_encode(0), [0x01, 0x00]);
        assert_eq!(left_encode(168), [0x01, 0xA8]);
        assert_eq!(left_encode(256), [0x02, 0x01, 0x00]);
        assert_eq!(right_encode(0), [0x00, 0x01]);
        assert_eq!(right_encode(256), [0x01, 0x00, 0x02]);
        assert_eq!(encode_string(b""), [0x01, 0x00]);
        assert_eq!(bytepad(&encode_string(b"KMAC"), 168).len(), 168);
    }

    #[test]
    fn empty_n_and_s_is_shake() {
        let msg = b"The quick brown fox";
        assert_eq!(cshake128(msg, 64, b"", b""), crate::shake128(msg, 64));
        assert_eq!(cshake256(msg, 64, b"", b""), crate::shake256(msg, 64));
        assert_ne!(cshake128(msg, 64, b"", b"x"), crate::shake128(msg, 64));
    }
}
