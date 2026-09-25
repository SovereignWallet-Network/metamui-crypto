//! Ascon-Hash256 (NIST SP 800-232 §5.1): fixed 256-bit digest.
//!
//! IV = `0x0000080100CC0002` (variant 2, p^12, 256-bit output, rate 8), rate
//! 8 bytes, p^12 throughout. Byte-exact to the reference
//! `crypto_hash/asconhash256` KAT (`LWC_HASH_KAT_128_256.txt`), which the
//! `upstream_sp800232_gate` test replays in full.

use crate::sponge::HashSponge;

/// IV constant for Ascon-Hash256 (SP 800-232 Table 8).
const ASCON_HASH256_IV: u64 = 0x0000_0801_00CC_0002;

/// Output length in bytes (256 bits).
pub const DIGEST_LEN: usize = 32;

/// Ascon-Hash256, streaming.
///
/// `AsconHash256::hash(msg)` is the one-shot form; `new` / `update` / `finalize`
/// absorb incrementally.
#[derive(Clone)]
pub struct AsconHash256 {
    sponge: HashSponge,
}

impl Default for AsconHash256 {
    fn default() -> Self {
        Self::new()
    }
}

impl AsconHash256 {
    /// Start a new hash computation.
    pub fn new() -> Self {
        Self { sponge: HashSponge::new(ASCON_HASH256_IV) }
    }

    /// Absorb more message bytes.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.sponge.absorb(data);
        self
    }

    /// Finish and return the 32-byte digest.
    pub fn finalize(self) -> [u8; DIGEST_LEN] {
        let mut out = [0u8; DIGEST_LEN];
        self.sponge.finalize().squeeze_into(&mut out);
        out
    }

    /// Compute the Ascon-Hash256 digest of `message` in one call.
    pub fn hash(message: &[u8]) -> [u8; DIGEST_LEN] {
        let mut h = Self::new();
        h.update(message);
        h.finalize()
    }
}

/// Convenience free function: compute the Ascon-Hash256 digest of `message`.
pub fn ascon_hash256(message: &[u8]) -> [u8; DIGEST_LEN] {
    AsconHash256::hash(message)
}
