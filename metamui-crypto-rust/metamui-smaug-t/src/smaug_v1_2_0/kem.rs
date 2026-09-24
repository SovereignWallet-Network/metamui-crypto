// SPDX-License-Identifier: MIT
//
// KEM API for SMAUG-T v1.2.0 — port of `src/kem.c`.
//
// The public API has both deterministic (`*_internal`) and randomized
// (default) variants. The KAT byte-equality test uses the `_internal`
// variants to feed in the AES-CTR-DRBG-derived `d` / `seed` / `mu`
// bytes from the upstream `.req` file; production code uses the
// randomized variants with `OsRng` (or any `rand_core::RngCore`).

use rand_core::RngCore;

use super::hash::{sha3_256, shake256_absorb_twice_squeeze};
use super::indcpa::{indcpa_dec, indcpa_enc, indcpa_keypair};
use super::params::{
    Params, CRYPTO_BYTES, DELTA_BYTES, T_BYTES,
};

/// Constant-time conditional move — `r[i] ^= b & (r[i] ^ x[i])`.
/// `b ∈ {0, 1}`. If b=1, r becomes x; if b=0, r is unchanged.
fn cmov(r: &mut [u8], x: &[u8], b: u8) {
    let mask = 0u8.wrapping_sub(b);
    for i in 0..r.len() {
        r[i] ^= mask & (r[i] ^ x[i]);
    }
}

/// Constant-time byte-array equality. Returns 0 if equal, 1 otherwise.
fn verify(a: &[u8], b: &[u8]) -> u8 {
    debug_assert_eq!(a.len(), b.len());
    let mut r: u8 = 0;
    for i in 0..a.len() {
        r |= a[i] ^ b[i];
    }
    // (-r as u64) >> 63 — 0 if r==0, 1 otherwise
    if r == 0 { 0 } else { 1 }
}

/// `crypto_kem_keypair_internal` — deterministic keypair generation
/// from caller-supplied randomness `d` (`T_BYTES`) and `seed`
/// (`CRYPTO_BYTES`). Output `pk` and `sk` lengths are
/// `publickey_bytes()` and `kem_secretkey_bytes()` respectively.
///
/// Compiled only with the `kat-internal` feature: it is the NIST KAT flow's
/// entry point, for conformance gates and fixture generators; an application
/// is never offered a seed. The randomized `crypto_kem_keypair` draws `d`
/// and `seed` itself and shares the body below.
#[cfg(feature = "kat-internal")]
pub fn crypto_kem_keypair_internal(
    p: &Params,
    pk: &mut [u8],
    sk: &mut [u8],
    d: &[u8],
    seed: &[u8],
) {
    keypair_internal(p, pk, sk, d, seed);
}

pub(crate) fn keypair_internal(p: &Params, pk: &mut [u8], sk: &mut [u8], d: &[u8], seed: &[u8]) {
    debug_assert_eq!(pk.len(), p.publickey_bytes());
    debug_assert_eq!(sk.len(), p.kem_secretkey_bytes());
    debug_assert_eq!(d.len(), T_BYTES);
    debug_assert_eq!(seed.len(), CRYPTO_BYTES);

    let pke_sk_bytes = p.pke_secretkey_bytes();

    indcpa_keypair(p, pk, &mut sk[..pke_sk_bytes], seed);
    sk[pke_sk_bytes..pke_sk_bytes + T_BYTES].copy_from_slice(d);
    sk[pke_sk_bytes + T_BYTES..].copy_from_slice(pk);
}

/// `crypto_kem_keypair` — randomized keypair generation.
pub fn crypto_kem_keypair<R: RngCore>(p: &Params, pk: &mut [u8], sk: &mut [u8], rng: &mut R) {
    let mut d = [0u8; T_BYTES];
    let mut seed = [0u8; CRYPTO_BYTES];
    rng.fill_bytes(&mut d);
    rng.fill_bytes(&mut seed);
    keypair_internal(p, pk, sk, &d, &seed);
}

/// `crypto_kem_enc_internal` — deterministic encapsulation given a
/// caller-supplied message `mu` (`msg_bytes` long). Returns ciphertext
/// `ctxt` and shared secret `ss`.
///
/// Compiled only with the `kat-internal` feature (see
/// `crypto_kem_keypair_internal`); the randomized `crypto_kem_enc` draws
/// `mu` itself and shares the body below.
#[cfg(feature = "kat-internal")]
pub fn crypto_kem_enc_internal(
    p: &Params,
    ctxt: &mut [u8],
    ss: &mut [u8],
    pk: &[u8],
    mu: &[u8],
) {
    enc_internal(p, ctxt, ss, pk, mu);
}

pub(crate) fn enc_internal(p: &Params, ctxt: &mut [u8], ss: &mut [u8], pk: &[u8], mu: &[u8]) {
    debug_assert_eq!(ctxt.len(), p.ciphertext_bytes());
    debug_assert_eq!(ss.len(), CRYPTO_BYTES);
    debug_assert_eq!(pk.len(), p.publickey_bytes());
    debug_assert_eq!(mu.len(), p.msg_bytes);

    // Step 1: `seed_r[0..32] = H(pk)`. Reuse `seed_r` buffer for both H output
    // and the subsequent hash_g output (which overwrites it).
    let mut seed_r = vec![0u8; DELTA_BYTES + CRYPTO_BYTES];
    sha3_256(&mut seed_r[..32], pk);

    // Step 2: `seed_r = G(mu || H(pk))` — re-uses seed_r as input AND output.
    // Match the C reference's in-place pattern: capture the pk-hash first,
    // then write the SHAKE-256 output back to `seed_r`.
    let pk_hash = seed_r[..32].to_vec();
    shake256_absorb_twice_squeeze(&mut seed_r, mu, &pk_hash);

    // Step 3: encrypt
    indcpa_enc(p, ctxt, pk, mu, &seed_r[..DELTA_BYTES]);

    // Step 4: ss = seed_r[DELTA_BYTES..DELTA_BYTES + CRYPTO_BYTES]
    for b in ss.iter_mut() { *b = 0; }
    cmov(ss, &seed_r[DELTA_BYTES..DELTA_BYTES + CRYPTO_BYTES], 1);
}

/// `crypto_kem_enc` — randomized encapsulation.
pub fn crypto_kem_enc<R: RngCore>(
    p: &Params,
    ctxt: &mut [u8],
    ss: &mut [u8],
    pk: &[u8],
    rng: &mut R,
) {
    let mut mu = vec![0u8; p.msg_bytes];
    rng.fill_bytes(&mut mu);
    enc_internal(p, ctxt, ss, pk, &mu);
}

/// `crypto_kem_dec_internal` — deterministic decapsulation.
///
/// On verify failure, returns the rejection-path pseudo-random secret
/// derived from `sk[PKE_SECRETKEY..PKE_SECRETKEY + T_BYTES]` (the
/// embedded `d`) and `H(ctxt)`.
///
/// Takes no seed, but it is the reference's `_internal` name and is kept off
/// the default surface with the other two so the KAT flow is one feature;
/// `crypto_kem_dec` is the same computation.
#[cfg(feature = "kat-internal")]
pub fn crypto_kem_dec_internal(p: &Params, ss: &mut [u8], ctxt: &[u8], sk: &[u8]) {
    dec_internal(p, ss, ctxt, sk);
}

pub(crate) fn dec_internal(p: &Params, ss: &mut [u8], ctxt: &[u8], sk: &[u8]) {
    debug_assert_eq!(ss.len(), CRYPTO_BYTES);
    debug_assert_eq!(ctxt.len(), p.ciphertext_bytes());
    debug_assert_eq!(sk.len(), p.kem_secretkey_bytes());

    let pke_sk_bytes = p.pke_secretkey_bytes();
    let pk = &sk[pke_sk_bytes + T_BYTES..];

    // Step 1: decrypt → mu
    let mut mu = vec![0u8; p.msg_bytes];
    indcpa_dec(p, &mut mu, &sk[..pke_sk_bytes], ctxt);

    // Step 2: success-path buffer = G(mu || H(pk))
    let mut hash_res = [0u8; 32];
    sha3_256(&mut hash_res, pk);
    let mut buf = vec![0u8; DELTA_BYTES + CRYPTO_BYTES];
    shake256_absorb_twice_squeeze(&mut buf, &mu, &hash_res);

    // Step 3: re-encap to ctxt_temp and verify
    let mut ctxt_temp = vec![0u8; p.ciphertext_bytes()];
    indcpa_enc(p, &mut ctxt_temp, pk, &mu, &buf[..DELTA_BYTES]);
    let fail = verify(ctxt, &ctxt_temp);

    // Step 4: rejection-path buffer = G(d || H(ctxt))
    sha3_256(&mut hash_res, ctxt);
    let d = &sk[pke_sk_bytes..pke_sk_bytes + T_BYTES];
    let mut buf_tmp = vec![0u8; DELTA_BYTES + CRYPTO_BYTES];
    shake256_absorb_twice_squeeze(&mut buf_tmp, d, &hash_res);

    // Step 5: select success vs rejection in constant time
    for b in ss.iter_mut() { *b = 0; }
    let buf_tmp_tail = buf_tmp[DELTA_BYTES..DELTA_BYTES + CRYPTO_BYTES].to_vec();
    cmov(&mut buf[DELTA_BYTES..DELTA_BYTES + CRYPTO_BYTES], &buf_tmp_tail, fail);
    cmov(ss, &buf[DELTA_BYTES..DELTA_BYTES + CRYPTO_BYTES], 1);
}

/// `crypto_kem_dec` — public decapsulation. Wrapper around `_internal`.
pub fn crypto_kem_dec(p: &Params, ss: &mut [u8], ctxt: &[u8], sk: &[u8]) {
    dec_internal(p, ss, ctxt, sk);
}
