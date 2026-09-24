// SPDX-License-Identifier: MIT
//
// Pack / unpack functions — port of `src/pack.c` v1.2.0.
//
// This module is a thin wrapper around `crate::pack_ring` (the v1.2.0
// R2_q bit-packing primitives ported in commit 73589d512). The wrapper
// dispatches on `Params.log_q`, `log_p`, and `log_p_prime` to pick the
// right `pack_R2_q` / `unpack_R2_q` pair.
//
// Adds the `pack_s_poly` / `unpack_s_poly` codec for ternary secret
// keys (2 bits per coefficient, value = 1 - encoded_pair).

use super::params::{Params, N, PKSEED_BYTES};
use super::poly_types::{Ciphertext, Poly, PolyVec, PublicKey, SecretKey};
use super::pack_ring;

// ============================================================================
// pack_ring / unpack_ring — Rq polynomial codec (dispatches on log_q)
// ============================================================================

pub fn pack_ring(p: &Params, bytes: &mut [u8], data: &Poly) {
    match p.log_q {
        10 => pack_ring::pack_r2_10(bytes, data_as_canonical_poly(data)),
        11 => pack_ring::pack_r2_11(bytes, data_as_canonical_poly(data)),
        _ => unreachable!("v1.2.0 only supports log_q in [10, 11]"),
    }
}

pub fn unpack_ring(p: &Params, data: &mut Poly, bytes: &[u8]) {
    let mut tmp = Poly { coeffs: [0i16; N] };
    match p.log_q {
        10 => pack_ring::unpack_r2_10(&mut tmp, bytes),
        11 => pack_ring::unpack_r2_11(&mut tmp, bytes),
        _ => unreachable!("v1.2.0 only supports log_q in [10, 11]"),
    }
    data.coeffs.copy_from_slice(&tmp.coeffs);
}

// ============================================================================
// pack_ring_p / unpack_ring_p — Rp polynomial codec (dispatches on log_p)
// ============================================================================

pub fn pack_ring_p(p: &Params, bytes: &mut [u8], data: &Poly) {
    match p.log_p {
        8 => pack_ring::pack_r2_8(bytes, data_as_canonical_poly(data)),
        9 => pack_ring::pack_r2_9(bytes, data_as_canonical_poly(data)),
        _ => unreachable!("v1.2.0 only supports log_p in [8, 9]"),
    }
}

pub fn unpack_ring_p(p: &Params, data: &mut Poly, bytes: &[u8]) {
    let mut tmp = Poly { coeffs: [0i16; N] };
    match p.log_p {
        8 => pack_ring::unpack_r2_8(&mut tmp, bytes),
        9 => pack_ring::unpack_r2_9(&mut tmp, bytes),
        _ => unreachable!("v1.2.0 only supports log_p in [8, 9]"),
    }
    data.coeffs.copy_from_slice(&tmp.coeffs);
}

// ============================================================================
// pack_ring_p_prime / unpack_ring_p_prime — Rp' polynomial codec
// ============================================================================

pub fn pack_ring_p_prime(p: &Params, bytes: &mut [u8], data: &Poly) {
    match p.log_p_prime {
        3 => pack_ring::pack_r2_3(bytes, data_as_canonical_poly(data)),
        4 => pack_ring::pack_r2_4(bytes, data_as_canonical_poly(data)),
        5 => pack_ring::pack_r2_5(bytes, data_as_canonical_poly(data)),
        7 => pack_ring::pack_r2_7(bytes, data_as_canonical_poly(data)),
        _ => unreachable!("v1.2.0 only supports log_p_prime in [3, 4, 5, 7]"),
    }
}

pub fn unpack_ring_p_prime(p: &Params, data: &mut Poly, bytes: &[u8]) {
    let mut tmp = Poly { coeffs: [0i16; N] };
    match p.log_p_prime {
        3 => pack_ring::unpack_r2_3(&mut tmp, bytes),
        4 => pack_ring::unpack_r2_4(&mut tmp, bytes),
        5 => pack_ring::unpack_r2_5(&mut tmp, bytes),
        7 => pack_ring::unpack_r2_7(&mut tmp, bytes),
        _ => unreachable!("v1.2.0 only supports log_p_prime in [3, 4, 5, 7]"),
    }
    data.coeffs.copy_from_slice(&tmp.coeffs);
}

// ============================================================================
// Vector / matrix variants (just iterate)
// ============================================================================

pub fn pack_ring_vec(p: &Params, bytes: &mut [u8], data: &PolyVec) {
    let stride = p.pkpoly_bytes();
    for i in 0..p.k {
        pack_ring(p, &mut bytes[i * stride..(i + 1) * stride], &data.vec[i]);
    }
}

pub fn unpack_ring_vec(p: &Params, data: &mut PolyVec, bytes: &[u8]) {
    let stride = p.pkpoly_bytes();
    for i in 0..p.k {
        unpack_ring(p, &mut data.vec[i], &bytes[i * stride..(i + 1) * stride]);
    }
}

pub fn pack_ring_p_vec(p: &Params, bytes: &mut [u8], data: &PolyVec) {
    let stride = p.ctpoly1_bytes();
    for i in 0..p.k {
        pack_ring_p(p, &mut bytes[i * stride..(i + 1) * stride], &data.vec[i]);
    }
}

pub fn unpack_ring_p_vec(p: &Params, data: &mut PolyVec, bytes: &[u8]) {
    let stride = p.ctpoly1_bytes();
    for i in 0..p.k {
        unpack_ring_p(p, &mut data.vec[i], &bytes[i * stride..(i + 1) * stride]);
    }
}

// ============================================================================
// Secret-key polynomial codec — 2 bits per coefficient (value = 1 - bits)
// ============================================================================

/// `pack_s_poly` — encode one sparse-ternary polynomial (coefficients in
/// {-1, 0, +1}) to N/4 = 64 bytes. Each byte packs 4 coefficients.
///
/// Encoding: `byte = ((1 - c0) & 3) | ((1 - c1) & 3) << 2 | (1 - c2) & 3) << 4 | ((1 - c3) & 3) << 6`
/// where the (1 - c) maps {-1 → 2, 0 → 1, +1 → 0}.
pub fn pack_s_poly(bytes: &mut [u8], s: &Poly) {
    for i in 0..N / 4 {
        let d = i * 4;
        let c0 = ((1i16.wrapping_sub(s.coeffs[d])) & 0x03) as u8;
        let c1 = ((1i16.wrapping_sub(s.coeffs[d + 1])) & 0x03) as u8;
        let c2 = ((1i16.wrapping_sub(s.coeffs[d + 2])) & 0x03) as u8;
        let c3 = ((1i16.wrapping_sub(s.coeffs[d + 3])) & 0x03) as u8;
        bytes[i] = c0 | (c1 << 2) | (c2 << 4) | (c3 << 6);
    }
}

pub fn unpack_s_poly(s: &mut Poly, bytes: &[u8]) {
    for i in 0..N / 4 {
        let d = i * 4;
        let b = bytes[i];
        s.coeffs[d] = 1i16.wrapping_sub((b & 0x03) as i16);
        s.coeffs[d + 1] = 1i16.wrapping_sub(((b >> 2) & 0x03) as i16);
        s.coeffs[d + 2] = 1i16.wrapping_sub(((b >> 4) & 0x03) as i16);
        s.coeffs[d + 3] = 1i16.wrapping_sub(((b >> 6) & 0x03) as i16);
    }
}

// ============================================================================
// Composite encoders/decoders (pack_enck / pack_deck / pack_ct)
// ============================================================================

/// `pack_enck` — encode a public key as `seed || pack_ring_vec(b)`.
pub fn pack_enck(p: &Params, output: &mut [u8], pk: &PublicKey) {
    output[..PKSEED_BYTES].copy_from_slice(&pk.seed);
    pack_ring_vec(p, &mut output[PKSEED_BYTES..], &pk.b);
}

/// `unpack_enck` — decode a public key. Also recomputes the matrix A
/// from the seed via `expand_A`.
pub fn unpack_enck(p: &Params, pk: &mut PublicKey, input: &[u8]) {
    pk.seed.copy_from_slice(&input[..PKSEED_BYTES]);
    super::key::expand_a(p, &mut pk.a, &pk.seed);
    unpack_ring_vec(p, &mut pk.b, &input[PKSEED_BYTES..]);
}

/// `pack_deck` — encode the PKE secret key (k polynomials, each N/4 bytes).
pub fn pack_deck(p: &Params, output: &mut [u8], sk: &SecretKey) {
    let stride = p.skpoly_bytes();
    for i in 0..p.k {
        pack_s_poly(&mut output[i * stride..(i + 1) * stride], &sk.vec[i]);
    }
}

pub fn unpack_deck(p: &Params, sk: &mut SecretKey, input: &[u8]) {
    let stride = p.skpoly_bytes();
    for i in 0..p.k {
        unpack_s_poly(&mut sk.vec[i], &input[i * stride..(i + 1) * stride]);
    }
}

/// `pack_ct` — encode a ciphertext as `pack_ring_p_vec(c1) || pack_ring_p_prime(c2)`.
pub fn pack_ct(p: &Params, output: &mut [u8], ct: &Ciphertext) {
    pack_ring_p_vec(p, &mut output[..p.ctpolyvec_bytes()], &ct.c1);
    pack_ring_p_prime(p, &mut output[p.ctpolyvec_bytes()..], &ct.c2);
}

pub fn unpack_ct(p: &Params, ct: &mut Ciphertext, input: &[u8]) {
    unpack_ring_p_vec(p, &mut ct.c1, &input[..p.ctpolyvec_bytes()]);
    unpack_ring_p_prime(p, &mut ct.c2, &input[p.ctpolyvec_bytes()..]);
}

// ============================================================================
// Bridge: our `Poly` ↔ `Poly`
// ============================================================================
//
// `pack_ring` (the existing module) takes the canonical Poly type. Our
// v1.2.0 Poly is structurally identical — both are `[i16; 256]` — but
// they're distinct nominal types. We need a way to reinterpret a
// `&v1_1_1::Poly` as `&canonical::Poly` without copying.

fn data_as_canonical_poly(p: &Poly) -> &Poly {
    // SAFETY: both types are `#[repr(Rust)]` structs with a single
    // `[i16; 256]` field. They have identical memory layout — the only
    // difference is the nominal type. Reinterpreting is sound because
    // (a) layouts match, (b) we're producing a shared reference (no
    // aliasing risk beyond what `&T` already permits), and (c) the
    // underlying data is `Copy`.
    //
    // We could avoid this by making `pack_ring::pack_r2_*` generic over
    // the poly type or by re-exporting the canonical type from
    // `smaug_v1_2_0::poly_types`, but that would couple the modules.
    unsafe { &*(p as *const Poly as *const Poly) }
}
