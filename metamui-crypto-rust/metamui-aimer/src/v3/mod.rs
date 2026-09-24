//! AIMer, specification **v3** (Samsung SDS, KpqC final, 2026-08-26).
//!
//! A faithful port of the reference package vendored at
//! `metamui-crypto-reference/c/samsungsds-AIMer-v3/`, gated byte-for-byte
//! against the authors' own KAT files in `test-vectors/aimer-upstream/`
//! (`tests/aimer_v3_upstream_kat.rs`: keygen, signature and verification).
//!
//! v3 is a new construction relative to the v2.1 `Aim2er*` types kept in
//! this crate for existing signatures: the one-way function is AIM3
//! (`y = x^{2^e−1} + x^{−1}` S-boxes between IV-derived affine layers), key
//! generation rejects zero S-box inputs and retries, and the MPC-in-the-head
//! multiplication check carries one challenge per S-box. No key or signature
//! byte is compatible between the two.
//!
//! Wire formats: `pk = iv ‖ ct`, `sk = pt ‖ iv ‖ ct`, signature =
//! `salt ‖ h₁ ‖ h₂ ‖ τ proofs`; the attached form is `m ‖ sig`.
//!
//! Every code path here is portable scalar Rust; there is no SIMD, assembly
//! or GPU path and no CPU-feature detection. Key generation, signing and
//! verification go through [`backend::backend`], which is `None` — the
//! reference in [`mod@sign`] — unless a separately maintained crate installed an
//! implementation of the same scheme with [`backend::install`] before the
//! first v3 operation; this crate ships none. `sign::{keypair_from_pt_iv_ref,
//! sign_internal_ref, verify_internal_ref}` always run the reference.

pub mod aim3;
pub mod backend;
pub mod field;
pub mod hash;
pub mod params;
pub mod sign;
pub mod tree;

pub use backend::{ParamSet, V3Backend};
pub use params::{Aimer128f, Aimer128s, Aimer192f, Aimer192s, Aimer256f, Aimer256s, AimerV3Params};
pub use sign::{generate_keypair_with, keypair_from_pt_iv, sign_internal, sign_with_rnd, verify_internal, verify_with_ctx};

use alloc::vec;
use alloc::vec::Vec;

/// Errors of the v3 API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V3Error {
    /// A key or randomness buffer has the wrong length for the parameter set.
    InvalidLength,
    /// The context string exceeds 255 bytes.
    ContextTooLong,
    /// `(pt, iv)` hits a zero S-box input; key generation must retry.
    ZeroSboxInput,
    /// The OS random source failed.
    Rng,
}

impl core::fmt::Display for V3Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            V3Error::InvalidLength => "invalid length",
            V3Error::ContextTooLong => "context longer than 255 bytes",
            V3Error::ZeroSboxInput => "zero S-box input; retry key generation",
            V3Error::Rng => "random source failure",
        };
        f.write_str(s)
    }
}

/// `crypto_sign_keypair` with OS randomness.
pub fn generate_keypair<P: AimerV3Params>() -> Result<(Vec<u8>, Vec<u8>), V3Error> {
    generate_keypair_with::<P, _>(|buf| getrandom::getrandom(buf).map_err(|_| V3Error::Rng))
}

/// `crypto_sign_signature` with OS randomness (randomized signing, as the
/// reference's `RANDOMIZED_SIGNING` build).
pub fn sign_with_ctx<P: AimerV3Params>(m: &[u8], ctx: &[u8], sk: &[u8]) -> Result<Vec<u8>, V3Error> {
    let mut rnd = vec![0u8; P::FB];
    getrandom::getrandom(&mut rnd).map_err(|_| V3Error::Rng)?;
    sign_with_rnd::<P>(m, ctx, &rnd, sk)
}

/// Empty-context signing.
pub fn sign<P: AimerV3Params>(m: &[u8], sk: &[u8]) -> Result<Vec<u8>, V3Error> {
    sign_with_ctx::<P>(m, &[], sk)
}

/// Empty-context verification.
pub fn verify<P: AimerV3Params>(sig: &[u8], m: &[u8], pk: &[u8]) -> bool {
    verify_with_ctx::<P>(sig, m, &[], pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_128f_with_context() {
        let (pk, sk) = generate_keypair::<Aimer128f>().unwrap();
        assert_eq!(pk.len(), Aimer128f::PK_BYTES);
        assert_eq!(sk.len(), Aimer128f::SK_BYTES);
        let sig = sign_with_ctx::<Aimer128f>(b"hello", b"ctx", &sk).unwrap();
        assert_eq!(sig.len(), Aimer128f::SIG_BYTES);
        assert!(verify_with_ctx::<Aimer128f>(&sig, b"hello", b"ctx", &pk));
        assert!(!verify_with_ctx::<Aimer128f>(&sig, b"hello", b"", &pk));
        assert!(!verify_with_ctx::<Aimer128f>(&sig, b"hellp", b"ctx", &pk));
        let mut bad = sig.clone();
        bad[Aimer128f::FB + 3] ^= 1;
        assert!(!verify_with_ctx::<Aimer128f>(&bad, b"hello", b"ctx", &pk));
    }
}
