//! KMAC128, KMAC256 and their XOF forms (NIST SP 800-185 §4).
//!
//! `KMAC(K, X, L, S) = cSHAKE(bytepad(encode_string(K), rate) ‖ X ‖
//! right_encode(L), L, "KMAC", S)`; the XOF form encodes `L = 0` and may be
//! squeezed indefinitely. `K` and `X` may be bit strings (ACVP exercises
//! both); `S` is a byte string. Byte-exact to NIST ACVP KMAC-128/-256 1.0
//! (`test-vectors/sp800-185/`), including the MAC-verification groups.

use crate::cshake::{bytepad, left_encode, right_encode, Cshake};
use crate::keccak::KeccakReader;
use alloc::vec::Vec;

/// Generic KMAC over a byte rate `RATE`.
#[derive(Clone)]
pub struct Kmac<const RATE: usize> {
    inner: Cshake<RATE>,
}

/// KMAC128 (cSHAKE128 based).
pub type Kmac128 = Kmac<168>;
/// KMAC256 (cSHAKE256 based).
pub type Kmac256 = Kmac<136>;

impl<const RATE: usize> Kmac<RATE> {
    /// Start `KMAC(key, ·, ·, customization)` with a byte-string key.
    pub fn new(key: &[u8], customization: &[u8]) -> Self {
        Self::new_bits(key, key.len() * 8, customization)
    }

    /// Start with a key of `key_bits` bits.
    ///
    /// The key bit string is the leading `key_bits` bits of `key` read
    /// MSB-first — the order SP 800-185 and NIST ACVP write bit strings in —
    /// so a partial last byte carries its key bits in the HIGH positions and
    /// `encode_string`'s zero padding lands in the low ones. This is the
    /// opposite of the message path (`update_bits`), which follows FIPS 202's
    /// `h2b` order because that is what the Keccak sponge absorbs; NIST's
    /// ACVP KMAC vectors (`test-vectors/sp800-185/kmac*-acvp.json`) are only
    /// reproduced with exactly this pairing, and every one of their 400
    /// bit-length-key records is checked by the gate.
    pub fn new_bits(key: &[u8], key_bits: usize, customization: &[u8]) -> Self {
        assert!(key_bits <= key.len() * 8, "key_bits exceeds the key bytes supplied");
        let mut inner = Cshake::<RATE>::new(b"KMAC", customization);
        // bytepad(encode_string(K), rate): left_encode(rate) ‖ left_encode(|K|)
        // ‖ K zero-padded to a byte ‖ zero bytes to a multiple of the rate.
        let mut enc = left_encode(key_bits as u64);
        let key_bytes = key_bits.div_ceil(8);
        enc.extend_from_slice(&key[..key_bytes]);
        if key_bits % 8 != 0 {
            let last = enc.len() - 1;
            enc[last] &= 0xFFu8 << (8 - key_bits % 8);
        }
        inner.update(&bytepad(&enc, RATE));
        Self { inner }
    }

    /// Absorb whole message bytes.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Absorb the first `nbits` bits of `data`.
    pub fn update_bits(&mut self, data: &[u8], nbits: usize) -> &mut Self {
        self.inner.update_bits(data, nbits);
        self
    }

    /// Finish with an output of `mac_bits` bits: `right_encode(mac_bits)` is
    /// absorbed, then `ceil(mac_bits / 8)` bytes are squeezed (last byte
    /// low-aligned when `mac_bits` is not a multiple of 8).
    pub fn finalize_bits(mut self, mac_bits: usize) -> Vec<u8> {
        self.inner.update(&right_encode(mac_bits as u64));
        self.inner.finalize_xof().read_bits(mac_bits)
    }

    /// Finish with a `mac_len`-byte tag.
    pub fn finalize(self, mac_len: usize) -> Vec<u8> {
        self.finalize_bits(mac_len * 8)
    }

    /// Finish as KMACXOF (`L = 0`); the reader squeezes any length.
    pub fn finalize_xof(mut self) -> KeccakReader {
        self.inner.update(&right_encode(0));
        self.inner.finalize_xof()
    }

    /// One-shot `KMAC(key, message, 8·mac_len, customization)`.
    pub fn mac(key: &[u8], message: &[u8], mac_len: usize, customization: &[u8]) -> Vec<u8> {
        let mut k = Self::new(key, customization);
        k.update(message);
        k.finalize(mac_len)
    }

    /// One-shot `KMACXOF(key, message, 8·out_len, customization)`.
    pub fn xof(key: &[u8], message: &[u8], out_len: usize, customization: &[u8]) -> Vec<u8> {
        let mut k = Self::new(key, customization);
        k.update(message);
        k.finalize_xof().read(out_len)
    }

    /// Constant-time verification of a `mac_len`-byte KMAC tag (non-XOF form).
    ///
    /// The caller states the MAC length its protocol uses. It is part of the
    /// KMAC input (`right_encode(L)`), so it must not come from the tag being
    /// checked: taking it from `expected` let an empty tag verify for every
    /// message, and let whoever presents a tag choose L. A tag that is not
    /// `mac_len` bytes fails.
    ///
    /// # Panics
    /// If `mac_len` is below [`KMAC_MIN_TAG_BYTES`] — SP 800-185 §8.4.2: a
    /// MAC output shall not be shorter than 32 bits.
    pub fn verify(key: &[u8], message: &[u8], customization: &[u8], expected: &[u8], mac_len: usize) -> bool {
        assert!(
            mac_len >= KMAC_MIN_TAG_BYTES,
            "KMAC tag length {mac_len} bytes is below the SP 800-185 minimum of {KMAC_MIN_TAG_BYTES}"
        );
        if expected.len() != mac_len {
            return false;
        }
        let got = Self::mac(key, message, mac_len, customization);
        let mut diff = 0u8;
        for (a, b) in got.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// Shortest KMAC tag `verify` accepts: 4 bytes. SP 800-185 §8.4.2 — a MAC
/// output length L shall not be less than 32 bits, and 32–64 bits only after
/// a careful risk analysis.
pub const KMAC_MIN_TAG_BYTES: usize = 4;

/// `KMAC128(K, X, 8·mac_len, S)`.
pub fn kmac128(key: &[u8], message: &[u8], mac_len: usize, customization: &[u8]) -> Vec<u8> {
    Kmac128::mac(key, message, mac_len, customization)
}

/// `KMAC256(K, X, 8·mac_len, S)`.
pub fn kmac256(key: &[u8], message: &[u8], mac_len: usize, customization: &[u8]) -> Vec<u8> {
    Kmac256::mac(key, message, mac_len, customization)
}

/// `KMACXOF128(K, X, 8·out_len, S)`.
pub fn kmacxof128(key: &[u8], message: &[u8], out_len: usize, customization: &[u8]) -> Vec<u8> {
    Kmac128::xof(key, message, out_len, customization)
}

/// `KMACXOF256(K, X, 8·out_len, S)`.
pub fn kmacxof256(key: &[u8], message: &[u8], out_len: usize, customization: &[u8]) -> Vec<u8> {
    Kmac256::xof(key, message, out_len, customization)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xof_and_mac_differ_and_streaming_matches_one_shot() {
        let key = [0x40u8; 32];
        let msg = b"\x00\x01\x02\x03";
        let mac = kmac128(&key, msg, 32, b"");
        let xof = kmacxof128(&key, msg, 32, b"");
        assert_ne!(mac, xof, "KMAC and KMACXOF encode different L");
        let mut k = Kmac128::new(&key, b"");
        k.update(&msg[..1]).update(&msg[1..]);
        assert_eq!(k.finalize(32), mac);
        assert!(Kmac128::verify(&key, msg, b"", &mac, 32));
        assert!(!Kmac128::verify(&key, msg, b"x", &mac, 32));
    }
}
