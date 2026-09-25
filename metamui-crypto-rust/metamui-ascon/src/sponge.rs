//! The rate-8 hashing sponge shared by Ascon-Hash256, Ascon-XOF128 and
//! Ascon-CXOF128 (NIST SP 800-232 §5).
//!
//! All three functions are the same construction — initialise with a
//! function-specific IV, absorb 8-byte blocks with p^12 between them, pad the
//! final block with 10*, then squeeze 8 bytes per p^12 — and differ only in the
//! IV, in whether a customization string is absorbed first (CXOF), and in the
//! output length. This module implements the construction once, streaming, and
//! the three public types wrap it.

use crate::permutation::{ascon_permutation, load64_le_partial, pad, store64_le_partial};

/// Rate of the hashing modes in bytes (one 64-bit word).
pub(crate) const RATE: usize = 8;

/// Number of permutation rounds between blocks (p^12 for every hashing mode).
const ROUNDS: u8 = 12;

/// Streaming absorb phase of the hashing sponge.
#[derive(Clone)]
pub(crate) struct HashSponge {
    state: [u64; 5],
    buf: [u8; RATE],
    buf_len: usize,
}

impl HashSponge {
    /// Initialise the state as `[iv, 0, 0, 0, 0]` and apply p^12.
    pub(crate) fn new(iv: u64) -> Self {
        let mut state = [iv, 0, 0, 0, 0];
        ascon_permutation(&mut state, ROUNDS);
        Self { state, buf: [0u8; RATE], buf_len: 0 }
    }

    /// XOR a whole 64-bit word into the rate and permute. CXOF uses this to
    /// absorb the customization bit length as its own block.
    pub(crate) fn absorb_word(&mut self, word: u64) {
        debug_assert_eq!(self.buf_len, 0, "absorb_word on a partially filled block");
        self.state[0] ^= word;
        ascon_permutation(&mut self.state, ROUNDS);
    }

    /// Absorb an arbitrary number of bytes, buffering the partial block.
    pub(crate) fn absorb(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = core::cmp::min(RATE - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == RATE {
                self.state[0] ^= load64_le_partial(&self.buf, RATE);
                ascon_permutation(&mut self.state, ROUNDS);
                self.buf_len = 0;
            }
        }
        while data.len() >= RATE {
            self.state[0] ^= load64_le_partial(data, RATE);
            ascon_permutation(&mut self.state, ROUNDS);
            data = &data[RATE..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Absorb the final partial block with 10* padding and permute. After this
    /// the sponge is back at a block boundary and can absorb the next domain
    /// (CXOF: customization, then message) or be squeezed.
    pub(crate) fn pad_and_permute(&mut self) {
        self.state[0] ^= load64_le_partial(&self.buf, self.buf_len);
        self.state[0] ^= pad(self.buf_len);
        ascon_permutation(&mut self.state, ROUNDS);
        self.buf = [0u8; RATE];
        self.buf_len = 0;
    }

    /// Finish absorbing and switch to squeezing.
    pub(crate) fn finalize(mut self) -> SqueezeState {
        self.pad_and_permute();
        SqueezeState { state: self.state, block_used: 0 }
    }
}

/// Streaming squeeze phase of the hashing sponge.
///
/// Matches the reference exactly: the rate word is emitted, and p^12 is applied
/// only when more output is requested after it — never after the last block.
#[derive(Clone)]
pub(crate) struct SqueezeState {
    state: [u64; 5],
    /// Bytes of the current rate word already handed out (0..=RATE).
    block_used: usize,
}

impl SqueezeState {
    /// Fill `out` with the next output bytes.
    pub(crate) fn squeeze_into(&mut self, out: &mut [u8]) {
        let mut pos = 0;
        while pos < out.len() {
            if self.block_used == RATE {
                ascon_permutation(&mut self.state, ROUNDS);
                self.block_used = 0;
            }
            let avail = RATE - self.block_used;
            let take = core::cmp::min(avail, out.len() - pos);
            let word = self.state[0] >> (8 * self.block_used);
            store64_le_partial(&mut out[pos..pos + take], word, take);
            self.block_used += take;
            pos += take;
        }
    }
}
