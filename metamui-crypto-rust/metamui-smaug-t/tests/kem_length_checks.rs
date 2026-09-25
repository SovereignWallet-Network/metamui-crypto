//! Every `crypto_kem_*` entry point rejects a wrong-length argument with a
//! typed `SmaugV1Error` and writes nothing.
//!
//! These lengths were `debug_assert!`s until 2026-09. A release build (the
//! one that ships, and the one the WASM wrapper runs) then panicked on a
//! short buffer — a trap in WASM — and silently accepted a long one. For
//! TiMER that meant a 32-byte `mu`: G hashed all 32 bytes, D2 encoded only
//! the first 16, so decapsulation re-derived a different secret and implicit
//! rejection handed the two parties different keys. Run under `--release`
//! these tests fail on the old code (panic or silent acceptance).

use metamui_smaug_t::smaug_v1_2_0::{
    crypto_kem_dec, crypto_kem_dec_internal, crypto_kem_enc, crypto_kem_enc_internal, crypto_kem_keypair,
    crypto_kem_keypair_internal, Params, MODE1, MODE3, MODE5, MODET,
};
use metamui_smaug_t::{SmaugTV1, SmaugV1Error, SmaugV1Mode};
use rand::rngs::StdRng;
use rand::SeedableRng;

const ALL: [&Params; 4] = [&MODE1, &MODE3, &MODE5, &MODET];
const FILL: u8 = 0xA5;

/// A correct keypair for `p`, from fixed randomness.
fn keypair(p: &Params) -> (Vec<u8>, Vec<u8>) {
    let mut pk = vec![0u8; p.publickey_bytes()];
    let mut sk = vec![0u8; p.kem_secretkey_bytes()];
    crypto_kem_keypair_internal(p, &mut pk, &mut sk, &[1u8; 32], &[2u8; 32]).expect("valid keypair");
    (pk, sk)
}

/// One byte short and one byte long of `n`, plus empty.
fn wrong(n: usize) -> [usize; 3] {
    [0, n - 1, n + 1]
}

fn untouched(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == FILL)
}

#[test]
fn keypair_rejects_every_wrong_length() {
    for p in ALL {
        let (pk_n, sk_n) = (p.publickey_bytes(), p.kem_secretkey_bytes());
        for n in wrong(pk_n) {
            let (mut pk, mut sk) = (vec![FILL; n], vec![FILL; sk_n]);
            let e = crypto_kem_keypair_internal(p, &mut pk, &mut sk, &[1u8; 32], &[2u8; 32]).unwrap_err();
            assert_eq!(e, SmaugV1Error::InvalidPublicKeyLength { expected: pk_n, got: n }, "{:?}", p.mode);
            assert!(untouched(&pk) && untouched(&sk), "{:?}: wrote on error", p.mode);
            let e = crypto_kem_keypair(p, &mut pk, &mut sk, &mut StdRng::seed_from_u64(1)).unwrap_err();
            assert_eq!(e, SmaugV1Error::InvalidPublicKeyLength { expected: pk_n, got: n }, "{:?}", p.mode);
        }
        for n in wrong(sk_n) {
            let (mut pk, mut sk) = (vec![FILL; pk_n], vec![FILL; n]);
            let e = crypto_kem_keypair_internal(p, &mut pk, &mut sk, &[1u8; 32], &[2u8; 32]).unwrap_err();
            assert_eq!(e, SmaugV1Error::InvalidSecretKeyLength { expected: sk_n, got: n }, "{:?}", p.mode);
            assert!(untouched(&pk) && untouched(&sk), "{:?}: wrote on error", p.mode);
        }
        for n in wrong(32) {
            let (mut pk, mut sk) = (vec![FILL; pk_n], vec![FILL; sk_n]);
            let e = crypto_kem_keypair_internal(p, &mut pk, &mut sk, &vec![1u8; n], &[2u8; 32]).unwrap_err();
            assert_eq!(e, SmaugV1Error::InvalidSeedLength { expected: 32, got: n }, "{:?}: d", p.mode);
            let e = crypto_kem_keypair_internal(p, &mut pk, &mut sk, &[1u8; 32], &vec![2u8; n]).unwrap_err();
            assert_eq!(e, SmaugV1Error::InvalidSeedLength { expected: 32, got: n }, "{:?}: seed", p.mode);
            assert!(untouched(&pk) && untouched(&sk), "{:?}: wrote on error", p.mode);
        }
    }
}

#[test]
fn enc_rejects_every_wrong_length() {
    for p in ALL {
        let (pk, _) = keypair(p);
        let (ct_n, pk_n, mu_n) = (p.ciphertext_bytes(), p.publickey_bytes(), p.msg_bytes);
        let mu = vec![7u8; mu_n];
        let enc = |ct: &mut [u8], ss: &mut [u8], pk: &[u8], mu: &[u8]| {
            let a = crypto_kem_enc_internal(p, ct, ss, pk, mu);
            // The randomized entry point draws a correct `mu`, so only the
            // three buffer lengths can be wrong there.
            if mu.len() == mu_n {
                assert_eq!(crypto_kem_enc(p, ct, ss, pk, &mut StdRng::seed_from_u64(2)), a, "{:?}", p.mode);
            }
            a
        };
        for n in wrong(ct_n) {
            let (mut ct, mut ss) = (vec![FILL; n], vec![FILL; 32]);
            assert_eq!(enc(&mut ct, &mut ss, &pk, &mu), Err(SmaugV1Error::InvalidCiphertextLength { expected: ct_n, got: n }));
            assert!(untouched(&ct) && untouched(&ss), "{:?}: wrote on error", p.mode);
        }
        for n in wrong(32) {
            let (mut ct, mut ss) = (vec![FILL; ct_n], vec![FILL; n]);
            assert_eq!(enc(&mut ct, &mut ss, &pk, &mu), Err(SmaugV1Error::InvalidSharedSecretLength { expected: 32, got: n }));
            assert!(untouched(&ct) && untouched(&ss), "{:?}: wrote on error", p.mode);
        }
        for n in wrong(pk_n) {
            let (mut ct, mut ss) = (vec![FILL; ct_n], vec![FILL; 32]);
            let bad_pk = vec![0u8; n];
            assert_eq!(enc(&mut ct, &mut ss, &bad_pk, &mu), Err(SmaugV1Error::InvalidPublicKeyLength { expected: pk_n, got: n }));
            assert!(untouched(&ct) && untouched(&ss), "{:?}: wrote on error", p.mode);
        }
        for n in wrong(mu_n) {
            let (mut ct, mut ss) = (vec![FILL; ct_n], vec![FILL; 32]);
            let bad_mu = vec![7u8; n];
            assert_eq!(enc(&mut ct, &mut ss, &pk, &bad_mu), Err(SmaugV1Error::InvalidMessageLength { expected: mu_n, got: n }));
            assert!(untouched(&ct) && untouched(&ss), "{:?}: wrote on error", p.mode);
        }
    }
}

#[test]
fn dec_rejects_every_wrong_length() {
    for p in ALL {
        let (_, sk) = keypair(p);
        let (ct_n, sk_n) = (p.ciphertext_bytes(), p.kem_secretkey_bytes());
        let ct = vec![0u8; ct_n];
        let dec = |ss: &mut [u8], ct: &[u8], sk: &[u8]| {
            let a = crypto_kem_dec(p, ss, ct, sk);
            assert_eq!(crypto_kem_dec_internal(p, ss, ct, sk), a, "{:?}", p.mode);
            a
        };
        for n in wrong(32) {
            let mut ss = vec![FILL; n];
            assert_eq!(dec(&mut ss, &ct, &sk), Err(SmaugV1Error::InvalidSharedSecretLength { expected: 32, got: n }));
            assert!(untouched(&ss), "{:?}: wrote on error", p.mode);
        }
        for n in wrong(ct_n) {
            let mut ss = vec![FILL; 32];
            assert_eq!(dec(&mut ss, &vec![0u8; n], &sk), Err(SmaugV1Error::InvalidCiphertextLength { expected: ct_n, got: n }));
            assert!(untouched(&ss), "{:?}: wrote on error", p.mode);
        }
        for n in wrong(sk_n) {
            let mut ss = vec![FILL; 32];
            assert_eq!(dec(&mut ss, &ct, &vec![0u8; n]), Err(SmaugV1Error::InvalidSecretKeyLength { expected: sk_n, got: n }));
            assert!(untouched(&ss), "{:?}: wrote on error", p.mode);
        }
    }
}

/// TiMER's message is 16 bytes (D2 encoding), not the 32 of the other sets.
/// A 32-byte `mu` used to be accepted and produce a ciphertext whose
/// decapsulation disagreed with the encapsulator's secret.
#[test]
fn timer_mu_is_sixteen_bytes() {
    let p = &MODET;
    assert_eq!(p.msg_bytes, 16);
    assert_eq!(SmaugTV1::new(SmaugV1Mode::ModeT).message_bytes(), 16);
    let (pk, sk) = keypair(p);

    let (mut ct, mut ss) = (vec![0u8; p.ciphertext_bytes()], vec![0u8; 32]);
    assert_eq!(
        crypto_kem_enc_internal(p, &mut ct, &mut ss, &pk, &[7u8; 32]),
        Err(SmaugV1Error::InvalidMessageLength { expected: 16, got: 32 })
    );
    assert_eq!(
        SmaugTV1::new(SmaugV1Mode::ModeT).encapsulate_internal(&pk, &[7u8; 32]).unwrap_err(),
        SmaugV1Error::InvalidMessageLength { expected: 16, got: 32 }
    );

    // The correct length round-trips.
    crypto_kem_enc_internal(p, &mut ct, &mut ss, &pk, &[7u8; 16]).unwrap();
    let mut ss_dec = vec![0u8; 32];
    crypto_kem_dec(p, &mut ss_dec, &ct, &sk).unwrap();
    assert_eq!(ss, ss_dec);
}
