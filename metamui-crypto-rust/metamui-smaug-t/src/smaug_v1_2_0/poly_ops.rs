// SPDX-License-Identifier: MIT
//
// Polynomial / vector / matrix operations — port of `src/poly.c` v1.2.0.
//
// Toom-Cook 4-way multiplication is structurally identical to the v1.0
// reference (verified by `diff`); we delegate `poly_mul_acc` to the
// existing `smaug_canonical::poly_mul_acc` rather than re-porting
// `toomcook.c`. The poly operations on this layer mirror v1.2.0's
// `poly.c` exactly.

use super::params::{Params, MODULUS_SCALED_Q_HALF, N};
use super::poly_types::{Poly, PolyVec};

/// `poly_add` — coefficient-wise addition, no modular reduction.
fn poly_add(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        r.coeffs[i] = a.coeffs[i].wrapping_add(b.coeffs[i]);
    }
}

/// `poly_sub` — coefficient-wise subtraction, no modular reduction.
fn poly_sub(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        r.coeffs[i] = a.coeffs[i].wrapping_sub(b.coeffs[i]);
    }
}

/// `poly_mul_acc` — `res[k] += (a * b)[k] mod x^N + 1`, mod 2^16.
/// Delegates to the Toom-Cook 4-way implementation below (toomcook.c is
/// unchanged between v1.0 and v1.2.0).
fn poly_mul_acc(a: &Poly, b: &Poly, res: &mut Poly) {
    poly_mul_acc_raw(&a.coeffs, &b.coeffs, &mut res.coeffs);
}

/// `vec_vec_mult` — inner product of two polyvecs.
pub fn vec_vec_mult(r: &mut Poly, a: &PolyVec, b: &PolyVec) {
    debug_assert_eq!(a.vec.len(), b.vec.len());
    for i in 0..a.vec.len() {
        poly_mul_acc(&a.vec[i], &b.vec[i], r);
    }
}

/// `vec_vec_mult_add` — `r += (a · b) mod q` via the scale-down /
/// multiply / scale-up trick. `mod_shift` is the right-shift amount
/// (either `16 - log_p` or `16 - log_q`).
pub fn vec_vec_mult_add(r: &mut Poly, a: &PolyVec, b: &PolyVec, mod_shift: u8) {
    let k = a.vec.len();
    let mut al = PolyVec::new(k);

    for i in 0..k {
        for j in 0..N {
            al.vec[i].coeffs[j] = a.vec[i].coeffs[j] >> mod_shift;
        }
    }

    let mut res = Poly::zero();
    vec_vec_mult(&mut res, &al, b);
    for j in 0..N {
        res.coeffs[j] = res.coeffs[j].wrapping_shl(mod_shift as u32);
    }

    let tmp = r.clone();
    poly_add(r, &tmp, &res);
}

/// `matrix_vec_mult_add` — `r = transpose(a) · b` in the q-domain.
///
/// `a` is a k×k matrix indexed as `a[i].vec[j]` (row major). The
/// transpose lives in temporary `at` per outer iteration `i`.
pub fn matrix_vec_mult_add(p: &Params, r: &mut PolyVec, a: &[PolyVec], b: &PolyVec) {
    let k = p.k;
    let shift = p.modulus_16_log_q();

    for i in 0..k {
        // Transpose column i (i.e., `at[j] = a[j][i] >> shift`).
        let mut at = PolyVec::new(k);
        for j in 0..k {
            for kk in 0..N {
                at.vec[j].coeffs[kk] = a[j].vec[i].coeffs[kk] >> shift;
            }
        }
        // Reset r.vec[i] to zero before accumulation.
        for kk in 0..N {
            r.vec[i].coeffs[kk] = 0;
        }
        vec_vec_mult(&mut r.vec[i], &at, b);
        for j in 0..N {
            r.vec[i].coeffs[j] = r.vec[i].coeffs[j].wrapping_shl(shift as u32);
        }
    }
}

/// `matrix_vec_mult_sub` — `r -= a · b` (no transpose). Used by `expand_b`
/// to compute `b = e - A·s`.
pub fn matrix_vec_mult_sub(p: &Params, r: &mut PolyVec, a: &[PolyVec], b: &PolyVec) {
    let k = p.k;
    let shift = p.modulus_16_log_q();

    for i in 0..k {
        let mut al = PolyVec::new(k);
        for j in 0..k {
            for kk in 0..N {
                al.vec[j].coeffs[kk] = a[i].vec[j].coeffs[kk] >> shift;
            }
        }
        let mut res = Poly::zero();
        vec_vec_mult(&mut res, &al, b);
        for j in 0..N {
            res.coeffs[j] = res.coeffs[j].wrapping_shl(shift as u32);
        }
        let tmp = r.vec[i].clone();
        poly_sub(&mut r.vec[i], &tmp, &res);
    }
}

// ============================================================================
// TiMER D2 encoding (`flipabs`, `d2_ecd`, `d2_dcd`)
// ============================================================================

/// `flipabs` — `|(x mod q) - Q/2|`. Used in the D2 decoder for TiMER.
fn flipabs(x: u16) -> u16 {
    let r = (x as i16).wrapping_sub(MODULUS_SCALED_Q_HALF);
    let m = r >> 15;
    ((r.wrapping_add(m)) ^ m) as u16
}

/// `d2_ecd` — TiMER D2 encoding: 16-byte message → polynomial.
/// Each plaintext bit goes to TWO coefficient slots (j and j+128).
pub fn d2_ecd(r: &mut Poly, msg: &[u8]) {
    debug_assert_eq!(msg.len(), 16);
    for i in 0..16 {
        for j in 0..8 {
            let bit = ((msg[i] >> j) & 1) as i32;
            // mask = (bit * Q_HALF) & Q_HALF — selects Q_HALF or 0.
            let mask = ((bit * MODULUS_SCALED_Q_HALF as i32) & MODULUS_SCALED_Q_HALF as i32) as i16;
            r.coeffs[8 * i + j] = mask;
            r.coeffs[8 * i + j + 128] = mask;
        }
    }
}

/// `d2_dcd` — TiMER D2 decoding: polynomial → 16-byte message.
pub fn d2_dcd(msg: &mut [u8], x: &Poly) {
    debug_assert_eq!(msg.len(), 16);
    for byte in msg.iter_mut() { *byte = 0; }
    for i in 0..N / 2 {
        let mut t = flipabs(x.coeffs[i] as u16);
        t = t.wrapping_add(flipabs(x.coeffs[i + 128] as u16));
        let t = t.wrapping_sub(MODULUS_SCALED_Q_HALF as u16);
        let t_bit = (t >> 15) & 1;
        msg[i >> 3] |= (t_bit as u8) << (i & 7);
    }
}


// ---------------------------------------------------------------------------
// Negacyclic polynomial multiply (x^n + 1), Toom-Cook 4-way over Karatsuba.
//
// Moved here from the deleted `smaug_canonical` module, which was the last
// thing the v1.2.0 code reached back into the 2023 draft core for. The
// arithmetic is unchanged and is covered by the v1.2.0 byte-equality gates
// against `test-vectors/smaug-t/v1.2.0-kat/`.
// ---------------------------------------------------------------------------

const KARATSUBA_N: usize = 64;

#[inline]
fn overflowing_mul(x: u16, y: u16) -> u16 {
    ((x as u32).wrapping_mul(y as u32)) as u16
}
const N_SB: usize = N >> 2; // 64
const N_SB_RES: usize = 2 * N_SB - 1; // 127

pub(crate) fn poly_mul_acc_raw(a: &[i16; N], b: &[i16; N], res: &mut [i16; N]) {
    // Note: tested empirically against crate::toomcook_exact::poly_mul_acc
    // (which is documented as "Exact trans-copy of reference Toom-Cook from
    // SMAUG-T_public"). Both produce IDENTICAL output bytes for the same
    // inputs — confirmed via Finding #29 byte-equality regression net. So
    // both implementations of Toom-Cook are behaviorally equivalent; the
    // T3/T5 byte-equality bug is not in this multiply.
    let mut c = [0u16; 2 * N];

    // Cast i16 slices to u16 slices for toom_cook
    let a_u16: &[u16; N] = unsafe { &*(a as *const [i16; N] as *const [u16; N]) };
    let b_u16: &[u16; N] = unsafe { &*(b as *const [i16; N] as *const [u16; N]) };

    toom_cook_4way(a_u16, b_u16, &mut c);

    // Reduction: x^n + 1
    for i in N..2 * N {
        res[i - N] = res[i - N]
            .wrapping_add((c[i - N].wrapping_sub(c[i])) as i16);
    }
}

fn toom_cook_4way(a1: &[u16], b1: &[u16], result: &mut [u16]) {
    let inv3: u16 = 43691;
    let inv9: u16 = 36409;
    let inv15: u16 = 61167;

    let mut aw1 = [0u16; N_SB];
    let mut aw2 = [0u16; N_SB];
    let mut aw3 = [0u16; N_SB];
    let mut aw4 = [0u16; N_SB];
    let mut aw5 = [0u16; N_SB];
    let mut aw6 = [0u16; N_SB];
    let mut aw7 = [0u16; N_SB];
    let mut bw1 = [0u16; N_SB];
    let mut bw2 = [0u16; N_SB];
    let mut bw3 = [0u16; N_SB];
    let mut bw4 = [0u16; N_SB];
    let mut bw5 = [0u16; N_SB];
    let mut bw6 = [0u16; N_SB];
    let mut bw7 = [0u16; N_SB];

    let mut w1 = [0u16; N_SB_RES];
    let mut w2 = [0u16; N_SB_RES];
    let mut w3 = [0u16; N_SB_RES];
    let mut w4 = [0u16; N_SB_RES];
    let mut w5 = [0u16; N_SB_RES];
    let mut w6 = [0u16; N_SB_RES];
    let mut w7 = [0u16; N_SB_RES];

    // EVALUATION for a
    for j in 0..N_SB {
        let r0 = a1[j];
        let r1 = a1[N_SB + j];
        let r2 = a1[2 * N_SB + j];
        let r3 = a1[3 * N_SB + j];
        let r4 = r0.wrapping_add(r2);
        let r5 = r1.wrapping_add(r3);
        let r6 = r4.wrapping_add(r5);
        let r7 = r4.wrapping_sub(r5);
        aw3[j] = r6;
        aw4[j] = r7;
        let r4 = ((r0 << 2).wrapping_add(r2)) << 1;
        let r5 = (r1 << 2).wrapping_add(r3);
        let r6 = r4.wrapping_add(r5);
        let r7 = r4.wrapping_sub(r5);
        aw5[j] = r6;
        aw6[j] = r7;
        let r4 = (r3 << 3)
            .wrapping_add(r2 << 2)
            .wrapping_add(r1 << 1)
            .wrapping_add(r0);
        aw2[j] = r4;
        aw7[j] = r0;
        aw1[j] = r3;
    }

    // EVALUATION for b
    for j in 0..N_SB {
        let r0 = b1[j];
        let r1 = b1[N_SB + j];
        let r2 = b1[2 * N_SB + j];
        let r3 = b1[3 * N_SB + j];
        let r4 = r0.wrapping_add(r2);
        let r5 = r1.wrapping_add(r3);
        let r6 = r4.wrapping_add(r5);
        let r7 = r4.wrapping_sub(r5);
        bw3[j] = r6;
        bw4[j] = r7;
        let r4 = ((r0 << 2).wrapping_add(r2)) << 1;
        let r5 = (r1 << 2).wrapping_add(r3);
        let r6 = r4.wrapping_add(r5);
        let r7 = r4.wrapping_sub(r5);
        bw5[j] = r6;
        bw6[j] = r7;
        let r4 = (r3 << 3)
            .wrapping_add(r2 << 2)
            .wrapping_add(r1 << 1)
            .wrapping_add(r0);
        bw2[j] = r4;
        bw7[j] = r0;
        bw1[j] = r3;
    }

    // MULTIPLICATION
    karatsuba_simple(&aw1, &bw1, &mut w1);
    karatsuba_simple(&aw2, &bw2, &mut w2);
    karatsuba_simple(&aw3, &bw3, &mut w3);
    karatsuba_simple(&aw4, &bw4, &mut w4);
    karatsuba_simple(&aw5, &bw5, &mut w5);
    karatsuba_simple(&aw6, &bw6, &mut w6);
    karatsuba_simple(&aw7, &bw7, &mut w7);

    // INTERPOLATION
    for i in 0..N_SB_RES {
        let r0 = w1[i];
        let r1 = w2[i];
        let r2 = w3[i];
        let r3 = w4[i];
        let r4 = w5[i];
        let r5 = w6[i];
        let r6 = w7[i];

        let r1 = r1.wrapping_add(r4);
        let r5 = r5.wrapping_sub(r4);
        let r3 = (r3.wrapping_sub(r2)) >> 1;
        let r4 = r4.wrapping_sub(r0);
        let r4 = r4.wrapping_sub(r6 << 6);
        let r4 = (r4 << 1).wrapping_add(r5);
        let r2 = r2.wrapping_add(r3);
        let r1 = r1.wrapping_sub((r2 << 6).wrapping_add(r2));
        let r2 = r2.wrapping_sub(r6);
        let r2 = r2.wrapping_sub(r0);
        let r1 = r1.wrapping_add(overflowing_mul(45, r2));
        let r4 = (overflowing_mul(r4.wrapping_sub(r2 << 3), inv3)) >> 3;
        let r5 = r5.wrapping_add(r1);
        let r1 = (overflowing_mul(r1.wrapping_add(r3 << 4), inv9)) >> 1;
        let r3 = (0u16).wrapping_sub(r3.wrapping_add(r1));
        let r5 = overflowing_mul(
            overflowing_mul(30, r1).wrapping_sub(r5),
            inv15,
        ) >> 2;
        let r2 = r2.wrapping_sub(r4);
        let r1 = r1.wrapping_sub(r5);

        result[i] = result[i].wrapping_add(r6);
        result[i + 64] = result[i + 64].wrapping_add(r5);
        result[i + 128] = result[i + 128].wrapping_add(r4);
        result[i + 192] = result[i + 192].wrapping_add(r3);
        result[i + 256] = result[i + 256].wrapping_add(r2);
        result[i + 320] = result[i + 320].wrapping_add(r1);
        result[i + 384] = result[i + 384].wrapping_add(r0);
    }
}

fn karatsuba_simple(a_1: &[u16], b_1: &[u16], result_final: &mut [u16]) {
    let mut d01 = [0u16; KARATSUBA_N / 2 - 1];
    let mut d0123 = [0u16; KARATSUBA_N / 2 - 1];
    let mut d23 = [0u16; KARATSUBA_N / 2 - 1];
    let mut result_d01 = [0u16; KARATSUBA_N - 1];

    for i in 0..KARATSUBA_N / 4 {
        let acc1 = a_1[i];
        let acc2 = a_1[i + KARATSUBA_N / 4];
        let acc3 = a_1[i + 2 * KARATSUBA_N / 4];
        let acc4 = a_1[i + 3 * KARATSUBA_N / 4];

        for j in 0..KARATSUBA_N / 4 {
            let acc5 = b_1[j];
            let acc6 = b_1[j + KARATSUBA_N / 4];

            result_final[i + j + 0 * KARATSUBA_N / 4] =
                result_final[i + j + 0 * KARATSUBA_N / 4]
                    .wrapping_add(overflowing_mul(acc1, acc5));
            result_final[i + j + 2 * KARATSUBA_N / 4] =
                result_final[i + j + 2 * KARATSUBA_N / 4]
                    .wrapping_add(overflowing_mul(acc2, acc6));

            let acc7 = acc5.wrapping_add(acc6);
            let acc8 = acc1.wrapping_add(acc2);
            d01[i + j] = d01[i + j].wrapping_add(overflowing_mul(acc7, acc8));

            let acc7b = b_1[j + 2 * KARATSUBA_N / 4];
            let acc8b = b_1[j + 3 * KARATSUBA_N / 4];
            result_final[i + j + 4 * KARATSUBA_N / 4] =
                result_final[i + j + 4 * KARATSUBA_N / 4]
                    .wrapping_add(overflowing_mul(acc7b, acc3));
            result_final[i + j + 6 * KARATSUBA_N / 4] =
                result_final[i + j + 6 * KARATSUBA_N / 4]
                    .wrapping_add(overflowing_mul(acc8b, acc4));

            let acc9 = acc3.wrapping_add(acc4);
            let acc10 = acc7b.wrapping_add(acc8b);
            d23[i + j] = d23[i + j].wrapping_add(overflowing_mul(acc9, acc10));

            let acc5c = acc5.wrapping_add(acc7b);
            let acc7c = acc1.wrapping_add(acc3);
            result_d01[i + j + 0 * KARATSUBA_N / 4] =
                result_d01[i + j + 0 * KARATSUBA_N / 4]
                    .wrapping_add(overflowing_mul(acc5c, acc7c));

            let acc6c = acc6.wrapping_add(acc8b);
            let acc8c = acc2.wrapping_add(acc4);
            result_d01[i + j + 2 * KARATSUBA_N / 4] =
                result_d01[i + j + 2 * KARATSUBA_N / 4]
                    .wrapping_add(overflowing_mul(acc6c, acc8c));

            let acc5d = acc5c.wrapping_add(acc6c);
            let acc7d = acc7c.wrapping_add(acc8c);
            d0123[i + j] = d0123[i + j].wrapping_add(overflowing_mul(acc5d, acc7d));
        }
    }

    // 2nd last stage
    for i in 0..KARATSUBA_N / 2 - 1 {
        d0123[i] = d0123[i]
            .wrapping_sub(result_d01[i + 0 * KARATSUBA_N / 4])
            .wrapping_sub(result_d01[i + 2 * KARATSUBA_N / 4]);
        d01[i] = d01[i]
            .wrapping_sub(result_final[i + 0 * KARATSUBA_N / 4])
            .wrapping_sub(result_final[i + 2 * KARATSUBA_N / 4]);
        d23[i] = d23[i]
            .wrapping_sub(result_final[i + 4 * KARATSUBA_N / 4])
            .wrapping_sub(result_final[i + 6 * KARATSUBA_N / 4]);
    }

    for i in 0..KARATSUBA_N / 2 - 1 {
        result_d01[i + 1 * KARATSUBA_N / 4] =
            result_d01[i + 1 * KARATSUBA_N / 4].wrapping_add(d0123[i]);
        result_final[i + 1 * KARATSUBA_N / 4] =
            result_final[i + 1 * KARATSUBA_N / 4].wrapping_add(d01[i]);
        result_final[i + 5 * KARATSUBA_N / 4] =
            result_final[i + 5 * KARATSUBA_N / 4].wrapping_add(d23[i]);
    }

    // Last stage
    for i in 0..KARATSUBA_N - 1 {
        result_d01[i] = result_d01[i]
            .wrapping_sub(result_final[i])
            .wrapping_sub(result_final[i + KARATSUBA_N]);
    }

    for i in 0..KARATSUBA_N - 1 {
        result_final[i + 1 * KARATSUBA_N / 2] =
            result_final[i + 1 * KARATSUBA_N / 2].wrapping_add(result_d01[i]);
    }
}
