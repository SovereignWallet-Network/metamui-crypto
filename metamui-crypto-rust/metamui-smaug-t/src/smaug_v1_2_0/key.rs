// SPDX-License-Identifier: MIT
//
// Key generation primitives — port of `src/key.c` v1.2.0.
//
//   expand_A — derives matrix A from a 32-byte seed via SHAKE-128 +
//              `unpack_ring` (new v1.2.0 R2_q codec).
//   expand_b — `b = e - A*s` where e is a Gaussian noise polyvec.
//   expand_s — samples k sparse-ternary `s` polynomials via `hwt`,
//              retrying with an incremented counter byte on rejection.
//   gen_pub_key — composes expand_A + expand_b to produce the full
//                 public key (seed + matrix + b vector).

use super::dg::d_gaussian;
use super::hash::shake128;
use super::hwt::hwt;
use super::pack::unpack_ring;
use super::params::{Params, CRYPTO_BYTES, PKSEED_BYTES};
use super::poly_ops::matrix_vec_mult_sub;
use super::poly_types::{Matrix, PolyVec, PublicKey, SecretKey};

/// `expand_A` — derive the k × k matrix A from a public seed.
///
/// For each (i, j) cell, hash `seed || i || j` with SHAKE-128 to derive
/// `SMAUGT_PKPOLY_BYTES` bytes, then decode as an Rq polynomial via
/// the v1.2.0 `unpack_ring` (R2_10 or R2_11).
pub fn expand_a(p: &Params, a: &mut Matrix, seed: &[u8; PKSEED_BYTES]) {
    let pkpoly_bytes = p.pkpoly_bytes();
    let mut extseed = vec![0u8; PKSEED_BYTES + 2];
    extseed[..PKSEED_BYTES].copy_from_slice(seed);

    let mut buf = vec![0u8; pkpoly_bytes];
    for i in 0..p.k {
        for j in 0..p.k {
            extseed[PKSEED_BYTES] = i as u8;
            extseed[PKSEED_BYTES + 1] = j as u8;
            shake128(&mut buf, &extseed);
            unpack_ring(p, &mut a[i].vec[j], &buf);
        }
    }
}

/// `expand_b` — `b = e - A*s` where `e` is Gaussian.
///
/// Caller must zero-initialize `b` before calling.
pub fn expand_b(
    p: &Params,
    b: &mut PolyVec,
    a: &[PolyVec],
    s: &SecretKey,
    e_seed: &[u8],
) {
    debug_assert_eq!(e_seed.len(), CRYPTO_BYTES);
    // b = e
    d_gaussian(p, b, e_seed);
    // b = -A*s + e
    matrix_vec_mult_sub(p, b, a, s);
}

/// `expand_s` — sample k sparse-ternary polynomials. For each row `i`,
/// derive a seed `base_seed || (i*k) || counter` and call `hwt` with
/// incrementing `counter` until it accepts.
pub fn expand_s(p: &Params, sk: &mut SecretKey, seed: &[u8]) {
    debug_assert_eq!(seed.len(), CRYPTO_BYTES);
    let mut extseed = vec![0u8; CRYPTO_BYTES + 2];
    extseed[..CRYPTO_BYTES].copy_from_slice(seed);

    for i in 0..p.k {
        extseed[CRYPTO_BYTES] = (i * p.k) as u8;
        let mut j: u8 = 0;
        loop {
            extseed[CRYPTO_BYTES + 1] = j;
            if hwt(p, &mut sk.vec[i].coeffs, &extseed) {
                break;
            }
            j = j.wrapping_add(1);
        }
    }
}

/// `gen_pub_key` — given a secret key and an error seed, derive the
/// full public key. The `pk.seed` must already be populated by the
/// caller (it's taken from the SHA3-512 expansion in `indcpa_keypair`).
pub fn gen_pub_key(p: &Params, pk: &mut PublicKey, sk: &SecretKey, err_seed: &[u8]) {
    expand_a(p, &mut pk.a, &pk.seed);
    // Zero pk.b before expand_b (which assigns the Gaussian then subtracts).
    for v in pk.b.vec.iter_mut() {
        for c in v.coeffs.iter_mut() {
            *c = 0;
        }
    }
    expand_b(p, &mut pk.b, &pk.a, sk, err_seed);
}
