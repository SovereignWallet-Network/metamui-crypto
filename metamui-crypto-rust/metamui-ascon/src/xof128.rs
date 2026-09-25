//! Ascon-XOF128 (NIST SP 800-232 §5.2): extendable-output function with
//! 128-bit security.
//!
//! Identical to Ascon-Hash256 except for the IV (`0x0000080000CC0003`: variant
//! 3, no fixed output length) and the arbitrary-length squeeze. Byte-exact to
//! the reference `crypto_hash/asconxof128` KAT (`LWC_XOF_KAT_128_512.txt`,
//! 512-bit outputs), replayed in full by `upstream_sp800232_gate`.

use crate::sponge::{HashSponge, SqueezeState};
use alloc::vec;
use alloc::vec::Vec;

/// IV constant for Ascon-XOF128 (SP 800-232 Table 8).
const ASCON_XOF128_IV: u64 = 0x0000_0800_00CC_0003;

/// Ascon-XOF128, streaming absorb.
#[derive(Clone)]
pub struct AsconXof128 {
    sponge: HashSponge,
}

impl Default for AsconXof128 {
    fn default() -> Self {
        Self::new()
    }
}

impl AsconXof128 {
    /// Start a new XOF computation.
    pub fn new() -> Self {
        Self { sponge: HashSponge::new(ASCON_XOF128_IV) }
    }

    /// Absorb more message bytes.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.sponge.absorb(data);
        self
    }

    /// Finish absorbing and return a reader that squeezes any number of bytes.
    pub fn finalize_xof(self) -> AsconXof128Reader {
        AsconXof128Reader { inner: self.sponge.finalize() }
    }

    /// Finish and squeeze exactly `output_len` bytes.
    pub fn finalize(self, output_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; output_len];
        self.finalize_xof().read_into(&mut out);
        out
    }

    /// One-shot: `output_len` bytes of Ascon-XOF128(`message`).
    pub fn hash(message: &[u8], output_len: usize) -> Vec<u8> {
        let mut x = Self::new();
        x.update(message);
        x.finalize(output_len)
    }
}

/// Squeeze side of Ascon-XOF128. Successive reads continue the same output
/// stream, so `read(8)` twice equals one `read(16)`.
#[derive(Clone)]
pub struct AsconXof128Reader {
    inner: SqueezeState,
}

impl AsconXof128Reader {
    /// Fill `out` with the next output bytes.
    pub fn read_into(&mut self, out: &mut [u8]) {
        self.inner.squeeze_into(out);
    }

    /// Return the next `len` output bytes.
    pub fn read(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.read_into(&mut out);
        out
    }
}

/// Convenience free function: `output_len` bytes of Ascon-XOF128(`message`).
pub fn ascon_xof128(message: &[u8], output_len: usize) -> Vec<u8> {
    AsconXof128::hash(message, output_len)
}
