// SPDX-License-Identifier: MIT
//
// Constant-time discrete Gaussian sampler — port of `src/dg.c` v1.2.0.
//
// v1.2.0 fixed `load64_littleendian`: v1.1.1 wrote every unpacked block of the
// SHAKE tape to `out[0..10]`, so the words for coefficients 64..255 of each
// polynomial were never written and three quarters of the Gaussian error was
// zero. Every pk/sk/ct/ss byte differs from v1.1.1 for the same seed.
//
// Boolean-formula sampler from:
//   A. Karmakar, S. S. Roy, O. Reparaz, F. Vercauteren, I. Verbauwhede,
//   "Constant-Time Discrete Gaussian Sampling," IEEE Trans. Comp. 67(11),
//   pp. 1561-1571, Nov. 2018, doi:10.1109/TC.2018.2814587.
//
// Each output polynomial consumes
//   `SMAUGT_DG_RAND_BITS × N / 8 = 10 × 256 / 8 = 320` bytes of SHAKE-256
// output, transposed into a column-major u64 layout (10 u64s per 64 coeffs).

use super::hash::shake256;
use super::params::{Params, CRYPTO_BYTES, DG_RAND_BITS, DG_SEED_LEN, N};
use super::poly_types::{Poly, PolyVec};

/// `load64_littleendian` — transpose `outlen × 8` bytes from row-major
/// `8 × outlen` (which is how SHAKE produces bytes, contiguously) into
/// the column-major u64 stream the boolean formulas consume.
///
/// Reads in chunks of 10 u64s (`SMAUGT_DG_RAND_BITS` per Gaussian
/// sample) and groups each chunk's i-th byte across 8 source positions.
fn load64_le_transposed(out: &mut [u64], outlen: usize, inb: &[u8]) {
    let mut pos = 0;
    for i in 0..outlen / 10 {
        for j in 0..10 {
            out[10 * i + j] = (inb[pos + j] as u64)
                | ((inb[pos + 10 + j] as u64) << 8)
                | ((inb[pos + 20 + j] as u64) << 16)
                | ((inb[pos + 30 + j] as u64) << 24)
                | ((inb[pos + 40 + j] as u64) << 32)
                | ((inb[pos + 50 + j] as u64) << 40)
                | ((inb[pos + 60 + j] as u64) << 48)
                | ((inb[pos + 70 + j] as u64) << 56);
        }
        pos += 80;
    }
}

/// `d_gaussian_poly` — sample one discrete Gaussian polynomial, add it
/// to `op` (which is initialized to zero by caller in v1.1.1's keygen).
/// The seed is `[CRYPTO_BYTES]base || [1]index_byte` — total length is
/// `CRYPTO_BYTES + 1 = 33` bytes.
pub fn d_gaussian_poly(p: &Params, op: &mut Poly, seed: &[u8]) {
    debug_assert_eq!(seed.len(), CRYPTO_BYTES + 1);

    // SHAKE-256 squeeze SEED_LEN u64s × 8 bytes each.
    let mut buf = vec![0u8; DG_SEED_LEN * 8];
    shake256(&mut buf, seed);

    let mut seed_temp = vec![0u64; DG_SEED_LEN];
    load64_le_transposed(&mut seed_temp, DG_SEED_LEN, &buf);

    let log_q_shift = p.modulus_16_log_q();

    // The C reference reuses the SAME buffer as a sliding window: it
    // reads x[0..10] (10 entries) per outer iteration, then advances
    // `j += DG_RAND_BITS` (10). For N=256, that's 4 iterations, total
    // bytes consumed = 4 × 10 u64 = 40 u64 = SEED_LEN exactly.
    let mut j = 0usize;
    let mut i = 0usize;
    while i < N {
        let x = &seed_temp[j..];

        // Boolean formula for s[0] (low bit of magnitude)
        let s0: u64 = (x[0] & x[1] & x[2] & x[3] & x[4] & x[5] & x[7] & !x[8])
            | (x[0] & x[3] & x[4] & x[5] & x[6] & x[8])
            | (x[1] & x[3] & x[4] & x[5] & x[6] & x[8])
            | (x[2] & x[3] & x[4] & x[5] & x[6] & x[8])
            | (!x[2] & !x[3] & !x[6] & x[8])
            | (!x[1] & !x[3] & !x[6] & x[8])
            | (x[6] & x[7] & !x[8])
            | (!x[5] & !x[6] & x[8])
            | (!x[4] & !x[6] & x[8])
            | (!x[7] & x[8]);
        // Boolean formula for s[1] (high bit of magnitude)
        let s1: u64 = (x[1] & x[2] & x[4] & x[5] & x[7] & x[8])
            | (x[3] & x[4] & x[5] & x[7] & x[8])
            | (x[6] & x[7] & x[8]);

        for k in 0..64 {
            let mag = (((s0 >> k) & 0x01) as i16)
                | ((((s1 >> k) & 0x01) as i16) << 1);
            // Sign bit comes from x[9] (the 10th u64, last bit per slot).
            let sign = ((x[9] >> k) & 0x01) as u16;
            // Two's-complement absolute-value flip then left-shift to the
            // q-domain. Matches C: `op->coeffs[..] = (((-sign) ^ coeff) + sign) << _16_LOG_Q`.
            //   sign=0 → coeff stays as `mag`
            //   sign=1 → coeff becomes `-mag` (via `(-1)^mag + 1`)
            let sign_neg = (0u16).wrapping_sub(sign);
            let unsigned = (sign_neg ^ (mag as u16)).wrapping_add(sign);
            // Assign (NOT add) — `expand_b` resets `b` before calling
            // `d_gaussian`, then layers `matrix_vec_mult_sub` after.
            op.coeffs[i + k] = (unsigned as i16).wrapping_shl(log_q_shift as u32);
        }
        j += DG_RAND_BITS;
        i += 64;
    }
}

/// `d_gaussian` — sample a vector of k Gaussian polys into `op`.
/// Caller passes `op` zero-initialized.
pub fn d_gaussian(p: &Params, op: &mut PolyVec, seed: &[u8]) {
    debug_assert_eq!(seed.len(), CRYPTO_BYTES);
    let mut extseed = vec![0u8; CRYPTO_BYTES + 1];
    extseed[..CRYPTO_BYTES].copy_from_slice(seed);
    for i in 0..p.k {
        // Domain separator: `SMAUGT_K * i` (e.g., 0, k, 2k, ...).
        extseed[CRYPTO_BYTES] = (p.k * i) as u8;
        d_gaussian_poly(p, &mut op.vec[i], &extseed);
    }
}
