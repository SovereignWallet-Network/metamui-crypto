// SPDX-License-Identifier: MIT
//
// Ciphertext computation — port of `src/ciphertext.c` v1.2.0.

use super::params::{Mode, Params, N};
use super::poly_ops::{d2_ecd, matrix_vec_mult_add, vec_vec_mult_add};
use super::poly_types::{Poly, PolyVec};

/// `round1` — q → p rounding for c1.
/// `coeff = ((coeff + rd_add) & rd_and) >> (16 - log_p)`.
fn round1(p: &Params, a: &mut PolyVec) {
    let shift = p.modulus_16_log_p();
    for i in 0..p.k {
        for j in 0..N {
            let v = (a.vec[i].coeffs[j] as u16).wrapping_add(p.rd_add) & p.rd_and;
            a.vec[i].coeffs[j] = (v >> shift) as i16;
        }
    }
}

/// `round2` — q → p' rounding for c2.
fn round2(p: &Params, a: &mut Poly) {
    let shift = p.modulus_16_log_p_prime();
    for j in 0..N {
        let v = (a.coeffs[j] as u16).wrapping_add(p.rd_add2) & p.rd_and2;
        a.coeffs[j] = (v >> shift) as i16;
    }
}

/// `computeC1` — c1 = round(p/q · (A · r)). Calls `matrix_vec_mult_add`
/// (which zeroes its output internally) then `round1`.
pub fn compute_c1(p: &Params, c1: &mut PolyVec, a: &[PolyVec], r: &PolyVec) {
    matrix_vec_mult_add(p, c1, a, r);
    round1(p, c1);
}

/// `computeC2` — c2 = round(p'/q · (b·r + Encode(delta))).
///
/// For the non-TiMER modes, `Encode(delta)` is the trivial bit-shifted
/// encoding `coeff[8*i + j] = delta_bit << (16 - log_t)`. For TiMER, we
/// use the D2 encoder `d2_ecd` which spreads each plaintext bit over
/// TWO coefficient slots (j and j+128) for error reconciliation.
pub fn compute_c2(p: &Params, c2: &mut Poly, delta: &[u8], b: &PolyVec, r: &PolyVec) {
    let shift_t = super::params::MODULUS_16_LOG_T;
    if p.mode == Mode::ModeT {
        d2_ecd(c2, delta);
    } else {
        // c2 = (q/2) * delta — each delta bit goes to a single coefficient slot.
        debug_assert_eq!(delta.len(), super::params::DELTA_BYTES);
        for i in 0..super::params::DELTA_BYTES {
            for j in 0..8 {
                let bit = ((delta[i] >> j) & 0x01) as u16;
                c2.coeffs[8 * i + j] = bit.wrapping_shl(shift_t as u32) as i16;
            }
        }
    }

    // c2 += b · r (in q-domain).
    vec_vec_mult_add(c2, b, r, p.modulus_16_log_q());

    // Rounding q → p'.
    round2(p, c2);
}
