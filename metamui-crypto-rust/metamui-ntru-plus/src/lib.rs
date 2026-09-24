//! # NTRU+ — the KpqC final-round NTRU-based KEM
//!
//! A port of the ntruplus.org reference implementation (commit 621c667,
//! specification dated 2026-02-02), vendored under
//! `metamui-crypto-reference/c/ntruplus-ref/`. Ring: R_q = Z_q[X]/(X^N -
//! X^{N/2} + 1), q = 3457 (prime).
//!
//! - Three parameter sets: 768 (Level 1), 864 (Level 3), 1152 (Level 5).
//!   The 2025 KpqClean revision's 576 set was dropped by the 2026 revision.
//! - SHAKE-256 for every hash (hash_f/g/h and the keygen tape)
//! - Mixed-radix NTT with Montgomery/Barrett reduction, ported butterfly for
//!   butterfly so serialized NTT-domain bytes match the reference
//! - CCA-secure KEM via a Fujisaki-Okamoto transform with SOTP encoding
//!
//! Conformance is gated byte-for-byte against the reference's own
//! `PQCkemKAT_*.rsp` files in `tests/upstream_ntru_plus_kat.rs`. The
//! deterministic entry points that gate replays the NIST DRBG through —
//! `kem::generate_keypair_det` and `kem::encapsulate_det`, which take the
//! `randombytes` source from the caller — are compiled only with the
//! `kat-internal` feature; an application is never offered a seed.
//! `NtruPlus::<P>::{generate_keypair, encapsulate, decapsulate}` are the
//! application surface.

#![cfg_attr(not(feature = "std"), no_std)]

// Link the wasm32 `getrandom` backend. This crate is a cdylib, so cargo links
// it for wasm32 and that link needs `__getrandom_custom` resolved; the
// definition lives in `metamui-getrandom-unavailable`. An unreferenced
// dependency is never loaded, and therefore never linked, so the import is
// what pulls the rlib in — `as _` because only its linkage is wanted.
#[cfg(target_arch = "wasm32")]
use metamui_getrandom_unavailable as _;

extern crate alloc;

pub mod error;
pub mod kem;
pub mod ntt;
pub mod params;
pub mod poly;
pub mod symmetric;

pub use error::NtruPlusError;
pub use kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
pub use params::{NtruPlus1152, NtruPlus768, NtruPlus864, NtruPlusParams};

/// NTRU+ KEM interface, parameterised by the parameter set.
pub struct NtruPlus<P: NtruPlusParams> {
    _phantom: core::marker::PhantomData<P>,
}

impl<P: NtruPlusParams> NtruPlus<P> {
    /// Generate a keypair.
    pub fn generate_keypair() -> Result<(PublicKey, SecretKey), NtruPlusError> {
        kem::generate_keypair::<P>()
    }

    /// Encapsulate a shared secret.
    pub fn encapsulate(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), NtruPlusError> {
        kem::encapsulate::<P>(pk)
    }

    /// Decapsulate to recover the shared secret.
    pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> Result<SharedSecret, NtruPlusError> {
        kem::decapsulate::<P>(ct, sk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly::Poly;

    fn roundtrip<P: NtruPlusParams>() {
        let (pk, sk) = NtruPlus::<P>::generate_keypair().expect("keygen failed");
        assert_eq!(pk.h.len(), P::PUBLIC_KEY_SIZE);
        assert_eq!(sk.to_bytes().len(), P::SECRET_KEY_SIZE);
        let (ct, ss_enc) = NtruPlus::<P>::encapsulate(&pk).expect("encaps failed");
        assert_eq!(ct.c.len(), P::CIPHERTEXT_SIZE);
        let ss_dec = NtruPlus::<P>::decapsulate(&ct, &sk).expect("decaps failed");
        assert_eq!(ss_enc.ss, ss_dec.ss, "{}: shared secrets must match", P::NAME);

        // Key codec round trip.
        let sk2 = SecretKey::from_bytes::<P>(&sk.to_bytes()).unwrap();
        assert_eq!(NtruPlus::<P>::decapsulate(&ct, &sk2).unwrap().ss, ss_enc.ss);
        assert_eq!(PublicKey::from_bytes::<P>(&pk.to_bytes()).unwrap().h, pk.h);
    }

    fn wrong_key_and_tamper<P: NtruPlusParams>() {
        let (pk1, _sk1) = NtruPlus::<P>::generate_keypair().unwrap();
        let (_pk2, sk2) = NtruPlus::<P>::generate_keypair().unwrap();
        let (ct, ss_enc) = NtruPlus::<P>::encapsulate(&pk1).unwrap();
        let ss_wrong = NtruPlus::<P>::decapsulate(&ct, &sk2).unwrap();
        assert_ne!(ss_enc.ss, ss_wrong.ss, "{}: wrong key must not recover ss", P::NAME);
        assert_eq!(ss_wrong.ss, [0u8; 32], "{}: failure is signalled by an all-zero ss", P::NAME);

        let (_pk, sk) = NtruPlus::<P>::generate_keypair().unwrap();
        let (mut ct, ss_enc) = NtruPlus::<P>::encapsulate(&_pk).unwrap();
        ct.c[0] ^= 0xFF;
        ct.c[10] ^= 0x42;
        let ss_dec = NtruPlus::<P>::decapsulate(&ct, &sk).unwrap();
        assert_ne!(ss_enc.ss, ss_dec.ss, "{}: tampered ct must not recover ss", P::NAME);
    }

    /// INTT(NTT(a)) == a mod q: the 2026 reference keeps NTT-domain values in
    /// the plain (non-Montgomery) domain, so the transform pair is an exact
    /// identity, not an identity up to an R factor.
    fn ntt_identity<P: NtruPlusParams>() {
        let n = P::N;
        let mut a = Poly::zero(n);
        for (i, c) in a.coeffs.iter_mut().enumerate() {
            *c = ((i * 7919 + 13) % 7) as i16 - 3;
        }
        let mut b = a.clone();
        poly::poly_ntt::<P>(&mut b);
        poly::poly_invntt::<P>(&mut b);
        for i in 0..n {
            let d = (b.coeffs[i] as i32 - a.coeffs[i] as i32).rem_euclid(P::Q);
            assert_eq!(d, 0, "{}: coefficient {i} not recovered", P::NAME);
        }
    }

    #[test]
    fn kem_roundtrip_768() { roundtrip::<NtruPlus768>(); }
    #[test]
    fn kem_roundtrip_864() { roundtrip::<NtruPlus864>(); }
    #[test]
    fn kem_roundtrip_1152() { roundtrip::<NtruPlus1152>(); }

    #[test]
    fn wrong_key_and_tamper_768() { wrong_key_and_tamper::<NtruPlus768>(); }
    #[test]
    fn wrong_key_and_tamper_864() { wrong_key_and_tamper::<NtruPlus864>(); }
    #[test]
    fn wrong_key_and_tamper_1152() { wrong_key_and_tamper::<NtruPlus1152>(); }

    #[test]
    fn ntt_identity_768() { ntt_identity::<NtruPlus768>(); }
    #[test]
    fn ntt_identity_864() { ntt_identity::<NtruPlus864>(); }
    #[test]
    fn ntt_identity_1152() { ntt_identity::<NtruPlus1152>(); }

    #[test]
    fn params_match_reference_api_h() {
        // CRYPTO_{PUBLICKEY,SECRETKEY,CIPHERTEXT}BYTES from the reference api.h
        assert_eq!((NtruPlus768::N, NtruPlus768::Q), (768, 3457));
        assert_eq!((NtruPlus768::PUBLIC_KEY_SIZE, NtruPlus768::SECRET_KEY_SIZE, NtruPlus768::CIPHERTEXT_SIZE), (1152, 2336, 1152));
        assert_eq!((NtruPlus864::N, NtruPlus864::BASEMUL_DEGREE), (864, 3));
        assert_eq!((NtruPlus864::PUBLIC_KEY_SIZE, NtruPlus864::SECRET_KEY_SIZE, NtruPlus864::CIPHERTEXT_SIZE), (1296, 2624, 1296));
        assert_eq!((NtruPlus1152::N, NtruPlus1152::BASEMUL_DEGREE), (1152, 4));
        assert_eq!((NtruPlus1152::PUBLIC_KEY_SIZE, NtruPlus1152::SECRET_KEY_SIZE, NtruPlus1152::CIPHERTEXT_SIZE), (1728, 3488, 1728));
    }
}
