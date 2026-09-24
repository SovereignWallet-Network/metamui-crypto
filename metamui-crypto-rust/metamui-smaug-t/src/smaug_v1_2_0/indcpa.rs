// SPDX-License-Identifier: MIT
//
// IND-CPA encryption layer — port of `src/indcpa.c` v1.2.0.

use super::cbd::sp_cbd;
use super::ciphertext::{compute_c1, compute_c2};
use super::hash::{sha3_512, shake256};
use super::key::{expand_s, gen_pub_key};
use super::pack::{pack_ct, pack_deck, pack_enck, unpack_ct, unpack_deck, unpack_enck};
use super::params::{
    Mode, Params, CRYPTO_BYTES, DEC_ADD, DELTA_BYTES, MODULUS_16_LOG_T, N, PKSEED_BYTES,
};
use super::poly_ops::{d2_dcd, vec_vec_mult_add};
use super::poly_types::{Ciphertext, PolyVec, PublicKey, SecretKey};

/// `expand_r` — derive ephemeral ternary vector r from a 32-byte seed.
/// Uses SHAKE-256 + `sp_cbd` (mode-dispatched CBD).
pub fn expand_r(p: &Params, r: &mut PolyVec, seed: &[u8]) {
    debug_assert_eq!(seed.len(), DELTA_BYTES);
    let mut buf = vec![0u8; p.cbdseed_bytes];
    let mut extseed = vec![0u8; DELTA_BYTES + 1];
    extseed[..DELTA_BYTES].copy_from_slice(seed);
    for i in 0..p.k {
        extseed[DELTA_BYTES] = i as u8;
        shake256(&mut buf, &extseed);
        sp_cbd(p, &mut r.vec[i], &buf);
    }
}

/// `indcpa_keypair` — deterministic PKE key generation from a 32-byte seed.
///
/// Steps (mirrors C `indcpa.c::indcpa_keypair`):
///   1. `extseed = SHA3-512(seed)` → 64 bytes split into (s-seed, pk-seed)
///   2. `expand_s(extseed[..32])` → secret-key polyvec
///   3. `pk.seed = extseed[32..64]`
///   4. `gen_pub_key` → matrix A + b vector
///   5. `pack_enck(pk_bytes, pk_tmp)` + `pack_deck(sk_bytes, sk_tmp)`
pub fn indcpa_keypair(
    p: &Params,
    pk_bytes: &mut [u8],
    sk_bytes: &mut [u8],
    seed: &[u8],
) {
    debug_assert_eq!(seed.len(), CRYPTO_BYTES);

    let mut extseed = [0u8; CRYPTO_BYTES + PKSEED_BYTES]; // 64
    sha3_512(&mut extseed, seed);

    let mut sk_tmp = SecretKey::new(p.k);
    expand_s(p, &mut sk_tmp, &extseed[..CRYPTO_BYTES]);

    let mut pk_tmp = PublicKey::new(p.k);
    pk_tmp.seed.copy_from_slice(&extseed[CRYPTO_BYTES..CRYPTO_BYTES + PKSEED_BYTES]);
    gen_pub_key(p, &mut pk_tmp, &sk_tmp, &extseed[..CRYPTO_BYTES]);

    for b in pk_bytes.iter_mut() { *b = 0; }
    for b in sk_bytes.iter_mut() { *b = 0; }
    pack_enck(p, pk_bytes, &pk_tmp);
    pack_deck(p, sk_bytes, &sk_tmp);
}

/// `indcpa_enc` — deterministic PKE encryption.
///
/// `seed` must be exactly `DELTA_BYTES = 32` bytes (the r-seed).
/// `mu` is `msg_bytes` long (32 for non-TiMER, 16 for TiMER).
pub fn indcpa_enc(
    p: &Params,
    ctxt: &mut [u8],
    pk: &[u8],
    mu: &[u8],
    seed: &[u8],
) {
    debug_assert_eq!(mu.len(), p.msg_bytes);
    debug_assert_eq!(seed.len(), DELTA_BYTES);

    let mut pk_tmp = PublicKey::new(p.k);
    unpack_enck(p, &mut pk_tmp, pk);

    let mut r = PolyVec::new(p.k);
    expand_r(p, &mut r, seed);

    let mut ctxt_tmp = Ciphertext::new(p.k);
    compute_c1(p, &mut ctxt_tmp.c1, &pk_tmp.a, &r);
    compute_c2(p, &mut ctxt_tmp.c2, mu, &pk_tmp.b, &r);

    pack_ct(p, ctxt, &ctxt_tmp);
}

/// `indcpa_dec` — deterministic PKE decryption.
pub fn indcpa_dec(p: &Params, mu: &mut [u8], sk: &[u8], ctxt: &[u8]) {
    debug_assert_eq!(mu.len(), p.msg_bytes);

    let mut sk_tmp = SecretKey::new(p.k);
    unpack_deck(p, &mut sk_tmp, sk);

    let mut ctxt_tmp = Ciphertext::new(p.k);
    unpack_ct(p, &mut ctxt_tmp, ctxt);

    // Shift c1 (each coefficient up by 16 - log_p), c2 (up by 16 - log_p').
    let shift_p = p.modulus_16_log_p();
    let shift_p_prime = p.modulus_16_log_p_prime();
    let mut c1 = ctxt_tmp.c1.clone();
    let mut delta = ctxt_tmp.c2.clone();

    for j in 0..N {
        delta.coeffs[j] = delta.coeffs[j].wrapping_shl(shift_p_prime as u32);
    }
    for i in 0..p.k {
        for j in 0..N {
            c1.vec[i].coeffs[j] = c1.vec[i].coeffs[j].wrapping_shl(shift_p as u32);
        }
    }

    // delta = delta + c1^T · s
    vec_vec_mult_add(&mut delta, &c1, &sk_tmp, shift_p);

    if p.mode == Mode::ModeT {
        d2_dcd(mu, &delta);
    } else {
        // Standard rounding: delta = (delta + DEC_ADD) >> (16 - log_t)
        for j in 0..N {
            let v = delta.coeffs[j].wrapping_add(DEC_ADD);
            // Logical right shift on i16 — use as u16.
            delta.coeffs[j] = ((v as u16) >> MODULUS_16_LOG_T) as i16;
            delta.coeffs[j] &= 0x01;
        }
        for byte in mu.iter_mut() { *byte = 0; }
        for i in 0..DELTA_BYTES {
            for j in 0..8 {
                let bit = (delta.coeffs[8 * i + j] as u8) << j;
                mu[i] ^= bit;
            }
        }
    }
}
