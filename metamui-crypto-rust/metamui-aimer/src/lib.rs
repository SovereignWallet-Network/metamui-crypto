//! # AIMer - MPC-in-the-Head Digital Signature
//!
//! AIMer is a digital signature scheme based on the MPC-in-the-Head paradigm,
//! jointly developed by Samsung SDS and KAIST for the KPQC competition.
//!
//! ## Features
//! - Security based only on symmetric primitives (AIM)
//! - Smallest signature size among symmetric-based schemes
//! - MPC-in-the-Head zero-knowledge proofs
//! - Resistance to public randomness reuse
//!
//! ## Optimizations (from Samsung SDS research)
//! - Mer operation optimization: up to 97.9% performance improvement
//! - Linear layer operation simplification
//!
//! ## Specification v3 (2026-08-26) — `v3` module
//!
//! AIMer was re-issued as specification **v3** (AIM3 one-way function, per-S-box
//! multiplication checks, keygen retry; new signature sizes). The [`v3`] module
//! is the faithful port, gated byte-for-byte against the authors' KAT in
//! `test-vectors/aimer-upstream/` (`tests/aimer_v3_upstream_kat.rs`), and is
//! what new code should use. The `Aim2er*` types below are the v2.1 scheme,
//! kept because a downstream consumer verifies AIM2-128s signatures on a
//! consensus path; their oracle now lives in `test-vectors/aimer-upstream/v2.1/`.
//! The two are not interoperable.
//!
//! Every code path is portable scalar Rust: no SIMD, assembly or GPU path and
//! no CPU-feature detection. The v3 functions go through the hook in
//! [`v3::backend`], which a separately maintained crate may fill with an
//! implementation of the same scheme; none is shipped here.
//!
//! ## Genuine-upstream conformance of the v2.1 types (spec v260130, fixed 2026-06-01)
//!
//! This crate is byte-for-byte interoperable with the **genuine upstream**
//! Samsung SDS AIMer reference (spec v260130), in both directions:
//! - **Verify**: accepts genuine upstream signatures — `tests/aimer_upstream_kat.rs`.
//! - **Sign**: deterministic keygen+sign from a NIST AES-CTR-DRBG seed produces
//!   `pk`/`sk`/`sig` byte-equal to the upstream KAT — `tests/aimer_sign_kat.rs`.
//!
//! Both gates run against the vendored upstream vectors under
//! `test-vectors/aimer-upstream/v2.1/` (from samsungsds AIMer commit `e47c497f`).
//!
//! Critical hash absorb sequences (must NOT drift from upstream):
//! - **H₀ (μ)** = `SHAKE_λ(H0_PREFIX ‖ iv ‖ ct ‖ pre ‖ msg, 2λ)`
//!   - `H0_PREFIX` is **per parameter set**: 128f=0x00, 128s=0x10, 192f=0x20,
//!     192s=0x30, 256f=0x40, 256s=0x50 (`AIMER_HASH_PREFIX_0` upstream).
//!   - `pre = [ctxlen ‖ ctx]`; the public API has no context, so `pre = [0x00]`.
//!     (These two were the v260130 fix vs the older reference this port had
//!     mirrored — see `signing::h0_hash`.)
//!   - λ chooses SHAKE128 (128-bit sets) vs SHAKE256 (192/256).
//! - **H₃** = `SHAKE_λ(0x03 ‖ pt ‖ μ ‖ ρ, λ + τ·λ)` — `pt` first, then `μ`, then `ρ`.
//!
//! The earlier in-repo KPQC C reference (the `kpqclean` submodule's `AIMer*`
//! dirs) and the self-generated `aimer-kpqc-official/` KAT were an older AIMer
//! vintage and have been retired as a conformance source; `aimer-upstream/` is
//! the source of truth.

#![cfg_attr(not(feature = "std"), no_std)]

// Link the wasm32 `getrandom` backend. This crate is a cdylib, so cargo links
// it for wasm32 and that link needs `__getrandom_custom` resolved; the
// definition lives in `metamui-getrandom-unavailable`. An unreferenced
// dependency is never loaded, and therefore never linked, so the import is
// what pulls the rlib in — `as _` because only its linkage is wanted.
#[cfg(target_arch = "wasm32")]
use metamui_getrandom_unavailable as _;


extern crate alloc;

pub mod params;
pub mod field;
pub mod aim2;
pub mod mpc_in_head;
pub mod signing;
pub mod verification;
pub mod error;
pub mod tree;
pub mod v3;

pub use params::AimerParams;
pub use params::{Aim2erI, Aim2erIF, Aim2erIII, Aim2erIIIF, Aim2erV, Aim2erVF};
pub use error::AimerError;
pub use signing::{PublicKey, SecretKey, Signature};

/// AIMer signature scheme
pub struct Aimer<P: AimerParams> {
    _phantom: core::marker::PhantomData<P>,
}

impl<P: AimerParams> Aimer<P> {
    /// Generate a new keypair
    pub fn generate_keypair() -> Result<(PublicKey, SecretKey), AimerError> {
        signing::generate_keypair::<P>()
    }
    
    /// Sign a message
    pub fn sign(msg: &[u8], sk: &SecretKey) -> Result<Signature, AimerError> {
        signing::sign::<P>(msg, sk)
    }
    
    /// Verify a signature
    pub fn verify(msg: &[u8], sig: &Signature, pk: &PublicKey) -> Result<bool, AimerError> {
        verification::verify::<P>(msg, sig, pk)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // AIM2 (spec v260130) tests
    // ========================================================================

    mod aim2_tests {
        use super::*;
        use crate::params::{Aim2erI, Aim2erIF, Aim2erIII, Aim2erIIIF, Aim2erV, Aim2erVF};

        #[test]
        fn test_aim2er_i_sign_verify() {
            let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().unwrap();
            let msg = b"Test message for AIM2er-I";
            let sig = Aimer::<Aim2erI>::sign(msg, &sk).unwrap();
            assert!(sig.is_well_formed(), "AIM2 signature should use compact format");
            assert!(Aimer::<Aim2erI>::verify(msg, &sig, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_iii_sign_verify() {
            let (pk, sk) = Aimer::<Aim2erIII>::generate_keypair().unwrap();
            let msg = b"Test message for AIM2er-III";
            let sig = Aimer::<Aim2erIII>::sign(msg, &sk).unwrap();
            assert!(sig.is_well_formed());
            assert!(Aimer::<Aim2erIII>::verify(msg, &sig, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_v_sign_verify() {
            let (pk, sk) = Aimer::<Aim2erV>::generate_keypair().unwrap();
            let msg = b"Test message for AIM2er-V";
            let sig = Aimer::<Aim2erV>::sign(msg, &sk).unwrap();
            assert!(sig.is_well_formed());
            assert!(Aimer::<Aim2erV>::verify(msg, &sig, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_wrong_message() {
            let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().unwrap();
            let msg = b"Original message";
            let sig = Aimer::<Aim2erI>::sign(msg, &sk).unwrap();
            let wrong_msg = b"Tampered message";
            assert!(!Aimer::<Aim2erI>::verify(wrong_msg, &sig, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_wrong_key() {
            let (_pk1, sk1) = Aimer::<Aim2erI>::generate_keypair().unwrap();
            let (pk2, _sk2) = Aimer::<Aim2erI>::generate_keypair().unwrap();
            let msg = b"Test message";
            let sig = Aimer::<Aim2erI>::sign(msg, &sk1).unwrap();
            assert!(!Aimer::<Aim2erI>::verify(msg, &sig, &pk2).unwrap());
        }

        #[test]
        fn test_aim2er_tampered_h1() {
            let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().unwrap();
            let msg = b"Test message";
            let mut sig = Aimer::<Aim2erI>::sign(msg, &sk).unwrap();
            sig.h1[0] ^= 0xFF;
            assert!(!Aimer::<Aim2erI>::verify(msg, &sig, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_tampered_h2() {
            let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().unwrap();
            let msg = b"Test message";
            let mut sig = Aimer::<Aim2erI>::sign(msg, &sk).unwrap();
            sig.h2[0] ^= 0xFF;
            assert!(!Aimer::<Aim2erI>::verify(msg, &sig, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_empty_message() {
            let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().unwrap();
            let msg = b"";
            let sig = Aimer::<Aim2erI>::sign(msg, &sk).unwrap();
            assert!(Aimer::<Aim2erI>::verify(msg, &sig, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_i_roundtrip() {
            let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().unwrap();
            let msg = b"roundtrip test";
            let sig = Aimer::<Aim2erI>::sign(msg, &sk).unwrap();
            let bytes = sig.to_bytes::<Aim2erI>();
            assert_eq!(bytes.len(), crate::params::Aim2erI::SIGNATURE_SIZE);
            let sig2 = Signature::from_bytes::<Aim2erI>(&bytes).unwrap();
            assert!(Aimer::<Aim2erI>::verify(msg, &sig2, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_if_roundtrip() {
            let (pk, sk) = Aimer::<Aim2erIF>::generate_keypair().unwrap();
            let msg = b"roundtrip test IF";
            let sig = Aimer::<Aim2erIF>::sign(msg, &sk).unwrap();
            let bytes = sig.to_bytes::<Aim2erIF>();
            assert_eq!(bytes.len(), crate::params::Aim2erIF::SIGNATURE_SIZE);
            let sig2 = Signature::from_bytes::<Aim2erIF>(&bytes).unwrap();
            assert!(Aimer::<Aim2erIF>::verify(msg, &sig2, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_iii_roundtrip() {
            let (pk, sk) = Aimer::<Aim2erIII>::generate_keypair().unwrap();
            let msg = b"roundtrip test III";
            let sig = Aimer::<Aim2erIII>::sign(msg, &sk).unwrap();
            let bytes = sig.to_bytes::<Aim2erIII>();
            assert_eq!(bytes.len(), crate::params::Aim2erIII::SIGNATURE_SIZE);
            let sig2 = Signature::from_bytes::<Aim2erIII>(&bytes).unwrap();
            assert!(Aimer::<Aim2erIII>::verify(msg, &sig2, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_iiif_roundtrip() {
            let (pk, sk) = Aimer::<Aim2erIIIF>::generate_keypair().unwrap();
            let msg = b"roundtrip test IIIF";
            let sig = Aimer::<Aim2erIIIF>::sign(msg, &sk).unwrap();
            let bytes = sig.to_bytes::<Aim2erIIIF>();
            assert_eq!(bytes.len(), crate::params::Aim2erIIIF::SIGNATURE_SIZE);
            let sig2 = Signature::from_bytes::<Aim2erIIIF>(&bytes).unwrap();
            assert!(Aimer::<Aim2erIIIF>::verify(msg, &sig2, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_v_roundtrip() {
            let (pk, sk) = Aimer::<Aim2erV>::generate_keypair().unwrap();
            let msg = b"roundtrip test V";
            let sig = Aimer::<Aim2erV>::sign(msg, &sk).unwrap();
            let bytes = sig.to_bytes::<Aim2erV>();
            assert_eq!(bytes.len(), crate::params::Aim2erV::SIGNATURE_SIZE);
            let sig2 = Signature::from_bytes::<Aim2erV>(&bytes).unwrap();
            assert!(Aimer::<Aim2erV>::verify(msg, &sig2, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_vf_roundtrip() {
            let (pk, sk) = Aimer::<Aim2erVF>::generate_keypair().unwrap();
            let msg = b"roundtrip test VF";
            let sig = Aimer::<Aim2erVF>::sign(msg, &sk).unwrap();
            let bytes = sig.to_bytes::<Aim2erVF>();
            assert_eq!(bytes.len(), crate::params::Aim2erVF::SIGNATURE_SIZE);
            let sig2 = Signature::from_bytes::<Aim2erVF>(&bytes).unwrap();
            assert!(Aimer::<Aim2erVF>::verify(msg, &sig2, &pk).unwrap());
        }

        #[test]
        fn test_aim2er_randomized_signatures() {
            let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().unwrap();
            let msg = b"Test message";
            let sig1 = Aimer::<Aim2erI>::sign(msg, &sk).unwrap();
            let sig2 = Aimer::<Aim2erI>::sign(msg, &sk).unwrap();
            assert!(Aimer::<Aim2erI>::verify(msg, &sig1, &pk).unwrap());
            assert!(Aimer::<Aim2erI>::verify(msg, &sig2, &pk).unwrap());
            assert_ne!(sig1.salt, sig2.salt);
        }

        #[test]
        fn test_aim2er_i_signature_size() {
            let (_pk, sk) = Aimer::<Aim2erI>::generate_keypair().unwrap();
            let msg = b"Size test";
            let sig = Aimer::<Aim2erI>::sign(msg, &sk).unwrap();

            // Compute actual serialized size
            let lambda_bytes = Aim2erI::SECURITY_BITS / 8;
            let fs = Aim2erI::FIELD_SIZE;
            let l = Aim2erI::AIM2_NUM_SBOXES;
            let tau = Aim2erI::MPC_ROUNDS;
            let log_n = Aim2erI::LOG_N;

            let salt_size = lambda_bytes;
            let h1_size = 2 * lambda_bytes;
            let h2_size = 2 * lambda_bytes;
            let per_rep = log_n * lambda_bytes   // path
                        + 2 * lambda_bytes       // com_excluded
                        + fs                     // delta_pt
                        + l * fs                 // delta_ts
                        + fs                     // delta_c
                        + fs;                    // alpha_excluded
            let total = salt_size + h1_size + h2_size + tau * per_rep;

            assert_eq!(total, Aim2erI::SIGNATURE_SIZE,
                "Computed size should match SIGNATURE_SIZE constant");

            // Verify actual signature data matches
            assert_eq!(sig.salt.len(), salt_size);
            assert_eq!(sig.h1.len(), h1_size);
            assert_eq!(sig.h2.len(), h2_size);
            assert_eq!(sig.proofs.len(), tau);
            for proof in &sig.proofs {
                assert_eq!(proof.path.len(), log_n);
                for seed in &proof.path {
                    assert_eq!(seed.len(), lambda_bytes);
                }
                assert_eq!(proof.com_excluded.len(), 2 * lambda_bytes);
                assert_eq!(proof.delta_pt.len(), fs);
                assert_eq!(proof.delta_ts.len(), l);
                for dt in &proof.delta_ts {
                    assert_eq!(dt.len(), fs);
                }
                assert_eq!(proof.delta_c.len(), fs);
                assert_eq!(proof.alpha_excluded.len(), fs);
            }
        }
    }
}