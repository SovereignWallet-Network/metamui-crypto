//! Deterministic KAT entry points (Tier-B byte-exact diagnostics).
//!
//! The official Round-3 KAT generator (`falcon-round3/KAT/generator`, `nist.c`)
//! derives every random input from the NIST AES-256 CTR_DRBG (`katrng.c`,
//! no derivation function) seeded by the record's 48-byte `seed`:
//!
//! ```text
//!   crypto_sign_keypair: randombytes(kg_seed, 48); keygen(SHAKE256(kg_seed))
//!   crypto_sign:         randombytes(nonce, 40);
//!                        randombytes(sig_seed, 48); sign_dyn(SHAKE256(sig_seed))
//! ```
//!
//! [`derive_kat_inputs`] replays exactly that DRBG schedule so that a binding
//! needs neither the DRBG nor the schedule — only "keygen from a SHAKE256
//! stream" and "sign with an explicit nonce and a SHAKE256 stream". Byte
//! equality with the upstream `pk`/`sk`/`sm` additionally requires that keygen
//! and the sampler consume the SHAKE stream in the reference order; this crate
//! is a clean-room port and does not yet (see
//! `tests/falcon_upstream_kat.rs::upstream_reproduce_falcon512_byte_exact`,
//! which reports the first divergent stage). These functions are the seam that
//! diagnostic drives; they are not production signing entry points.

use alloc::vec::Vec;

use crate::error::{Falcon512Error, Result};
use crate::shake::{Shake256Context, Shake256Reader};
use crate::{KeyPair, PrivateKey, PublicKey};
use metamui_aes_ctr_drbg::NistKatRng;
use rand::RngCore;

/// Random inputs the NIST KAT generator derives from one record's `seed`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KatInputs {
    /// 48-byte seed the reference expands with SHAKE256 to drive keygen.
    pub kg_seed: [u8; 48],
    /// 40-byte signature nonce (salt).
    pub nonce: [u8; 40],
    /// 48-byte seed the reference expands with SHAKE256 to drive `sign_dyn`.
    pub sig_seed: [u8; 48],
}

/// Replay the NIST CTR_DRBG schedule of `PQCgenKAT_sign` + `nist.c` for one
/// record (`seed` is the record's 48-byte `seed` field).
pub fn derive_kat_inputs(seed: &[u8; 48]) -> Result<KatInputs> {
    let mut drbg = NistKatRng::new(seed).map_err(|_| Falcon512Error::InvalidParameter)?;
    let mut kg_seed = [0u8; 48];
    let mut nonce = [0u8; 40];
    let mut sig_seed = [0u8; 48];
    drbg.randombytes_into(&mut kg_seed).map_err(|_| Falcon512Error::InvalidParameter)?;
    drbg.randombytes_into(&mut nonce).map_err(|_| Falcon512Error::InvalidParameter)?;
    drbg.randombytes_into(&mut sig_seed).map_err(|_| Falcon512Error::InvalidParameter)?;
    Ok(KatInputs { kg_seed, nonce, sig_seed })
}

/// `RngCore` over a SHAKE256 XOF, the reference's `inner_shake256` PRNG shape.
pub struct ShakeRng {
    reader: Shake256Reader,
}

impl ShakeRng {
    /// SHAKE256 absorbing `seed`, then squeezing on demand.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut ctx = Shake256Context::new();
        ctx.update(seed);
        ShakeRng { reader: ctx.finalize_xof() }
    }
}

impl RngCore for ShakeRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.reader.read(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.reader.read(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reader.read(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand::Error> {
        self.reader.read(dest);
        Ok(())
    }
}

/// Key generation driven by SHAKE256(`kg_seed`), the reference's keygen PRNG.
pub fn keypair_from_kg_seed(kg_seed: &[u8; 48]) -> Result<KeyPair> {
    let mut rng = ShakeRng::from_seed(kg_seed);
    crate::generate_keypair(&mut rng)
}

/// Sign `message` with an explicit `nonce` and a sampler driven by
/// SHAKE256(`sig_seed`). Output is the detached compressed signature
/// `(0x39) ‖ nonce ‖ comp(s1)` (our framing; the KAT `esig` uses `0x29`).
pub fn sign_with_nonce_seed(
    private_key: &PrivateKey,
    message: &[u8],
    nonce: &[u8; 40],
    sig_seed: &[u8; 48],
) -> Result<Vec<u8>> {
    let mut rng = ShakeRng::from_seed(sig_seed);
    let (_s0, s1) = crate::falcon_complete::sign_core_with_nonce(message, private_key, nonce, &mut rng)?;
    let sig = crate::nist_encoding::encode_signature(&s1, nonce, crate::constants::LOGN);
    if sig.len() > crate::sizes::falcon512::SIG_COMPRESSED_MAX {
        return Err(Falcon512Error::SignatureTooLong);
    }
    Ok(sig)
}

/// Convenience: the public key our keygen derives from a KAT `kg_seed`.
pub fn public_key_from_kg_seed(kg_seed: &[u8; 48]) -> Result<PublicKey> {
    Ok(keypair_from_kg_seed(kg_seed)?.public_key)
}
