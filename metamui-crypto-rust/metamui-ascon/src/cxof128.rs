//! Ascon-CXOF128 (NIST SP 800-232 §5.3): customizable extendable-output
//! function with 128-bit security.
//!
//! Construction (reference `crypto_cxof/asconcxof128/ref/hash.c`):
//! initialise with IV `0x0000080000CC0004` and p^12; absorb the customization
//! string's length **in bits** as one 64-bit word (`x0 ^= 8·|Z|`, p^12); absorb
//! the customization string itself as ordinary rate-8 blocks with 10* padding
//! (an empty string still absorbs one padding block); then absorb the message
//! the same way and squeeze. The customization string is limited to 2048 bits
//! (256 bytes) by SP 800-232 §5.3 and the reference alike; longer strings are
//! rejected, never truncated. Byte-exact to `LWC_CXOF_KAT_128_512.txt`,
//! replayed in full by `upstream_sp800232_gate`.

use crate::sponge::{HashSponge, SqueezeState};
use crate::{AsconError, Result};
use alloc::vec;
use alloc::vec::Vec;

/// IV constant for Ascon-CXOF128 (SP 800-232 Table 8).
const ASCON_CXOF128_IV: u64 = 0x0000_0800_00CC_0004;

/// Maximum customization-string length in bytes (2048 bits, SP 800-232 §5.3).
pub const MAX_CUSTOMIZATION_LEN: usize = 256;

/// Ascon-CXOF128, streaming absorb.
#[derive(Clone)]
pub struct AsconCxof128 {
    sponge: HashSponge,
}

impl AsconCxof128 {
    /// Start a new CXOF computation bound to `customization` (at most 256
    /// bytes; `&[]` is valid and distinct from Ascon-XOF128).
    pub fn new(customization: &[u8]) -> Result<Self> {
        if customization.len() > MAX_CUSTOMIZATION_LEN {
            return Err(AsconError::CustomizationTooLong);
        }
        let mut sponge = HashSponge::new(ASCON_CXOF128_IV);
        // Length of Z in bits, as the first absorbed block.
        sponge.absorb_word((customization.len() as u64) * 8);
        // Z itself, 10*-padded, even when empty.
        sponge.absorb(customization);
        sponge.pad_and_permute();
        Ok(Self { sponge })
    }

    /// Absorb more message bytes.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.sponge.absorb(data);
        self
    }

    /// Finish absorbing and return a reader that squeezes any number of bytes.
    pub fn finalize_xof(self) -> AsconCxof128Reader {
        AsconCxof128Reader { inner: self.sponge.finalize() }
    }

    /// Finish and squeeze exactly `output_len` bytes.
    pub fn finalize(self, output_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; output_len];
        self.finalize_xof().read_into(&mut out);
        out
    }

    /// One-shot: `output_len` bytes of Ascon-CXOF128(`message`, `customization`).
    pub fn hash(message: &[u8], customization: &[u8], output_len: usize) -> Result<Vec<u8>> {
        let mut x = Self::new(customization)?;
        x.update(message);
        Ok(x.finalize(output_len))
    }
}

/// Squeeze side of Ascon-CXOF128.
#[derive(Clone)]
pub struct AsconCxof128Reader {
    inner: SqueezeState,
}

impl AsconCxof128Reader {
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

/// Convenience free function: `output_len` bytes of
/// Ascon-CXOF128(`message`, `customization`).
pub fn ascon_cxof128(message: &[u8], customization: &[u8], output_len: usize) -> Result<Vec<u8>> {
    AsconCxof128::hash(message, customization, output_len)
}
