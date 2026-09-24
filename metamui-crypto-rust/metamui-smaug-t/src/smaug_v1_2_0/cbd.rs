// SPDX-License-Identifier: MIT
//
// Centered binomial distribution samplers — port of `src/cbd.c` v1.2.0.
//
// Each mode uses a different CBD variant for sampling the ephemeral
// `r` polynomial in `expand_r`:
//   - Mode1, ModeT: `sp_cbd1` (eta=2 modified, p(0)=3/4, p(±1)=1/8)
//                   reads 3 bytes per 8 coefficients (24-bit chunks)
//   - Mode3:        `cbd`     (eta=1, classical centered binomial)
//                   reads 4 bytes per 16 coefficients (2 bits each)
//   - Mode5:        `sp_cbd2` (eta=2 modified, p(0)=5/8, p(±1)=3/16)
//                   reads 4 bytes per 8 coefficients (32-bit chunks)
//
// Output coefficients are in {-1, 0, +1} (sparse ternary).

use super::params::{Mode, Params, N};
use super::poly_types::Poly;

#[inline(always)]
fn load24_le(x: &[u8]) -> u32 {
    (x[0] as u32) | ((x[1] as u32) << 8) | ((x[2] as u32) << 16)
}

#[inline(always)]
fn load32_le(x: &[u8]) -> u32 {
    (x[0] as u32)
        | ((x[1] as u32) << 8)
        | ((x[2] as u32) << 16)
        | ((x[3] as u32) << 24)
}

/// `sp_cbd1` — used by Mode1 and ModeT (TiMER). 3 bytes per 8 coefficients.
///
/// Bit layout per 3-bit field: low bit + middle bit ANDed give the
/// magnitude; high bit gives the sign (1 → flip sign).
fn sp_cbd1(r: &mut Poly, buf: &[u8]) {
    for i in 0..N / 8 {
        let t = load24_le(&buf[3 * i..]);
        let d_lo = t & 0x0024_9249;
        let d = d_lo & ((t >> 1) & 0x0024_9249);
        let s = (t >> 2) & 0x0024_9249;

        for j in 0..8 {
            let a = ((d >> (3 * j)) & 0x1) as i16;
            // Upstream: `(((((s >> (3*j)) & 0x1) - 1) ^ -2) | 1)`
            //   • s_bit=0 → ((0 - 1) ^ -2) | 1 = (-1 ^ -2) | 1 = 1 | 1 = +1
            //   • s_bit=1 → ((1 - 1) ^ -2) | 1 = ( 0 ^ -2) | 1 = -2 | 1 = -1
            let s_bit = ((s >> (3 * j)) & 0x1) as i16;
            let sign: i16 = ((s_bit.wrapping_sub(1)) ^ -2) | 1;
            r.coeffs[8 * i + j] = a * sign;
        }
    }
}

/// `cbd` — classical CBD with eta=1, used by Mode3.
/// 4 bytes per 16 coefficients; each coefficient is `bit_a - bit_b`.
fn cbd_eta1(r: &mut Poly, buf: &[u8]) {
    for i in 0..N / 16 {
        let t = load32_le(&buf[4 * i..]);
        for j in 0..16 {
            let a = ((t >> (2 * j)) & 0x01) as i16;
            let b = ((t >> (2 * j + 1)) & 0x01) as i16;
            r.coeffs[16 * i + j] = a - b;
        }
    }
}

/// `sp_cbd2` — modified CBD with eta=2 (p(0)=5/8), used by Mode5.
/// 4 bytes per 8 coefficients.
fn sp_cbd2(r: &mut Poly, buf: &[u8]) {
    for i in 0..N / 8 {
        let t = load32_le(&buf[4 * i..]);
        let d_lo = t & 0x1111_1111;
        let d = d_lo | ((t >> 1) & 0x1111_1111);
        let d = d & ((t >> 2) & 0x1111_1111);
        let s = (t >> 3) & 0x1111_1111;
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x1) as i16;
            let s_bit = ((s >> (4 * j)) & 0x1) as i16;
            let sign: i16 = ((s_bit.wrapping_sub(1)) ^ -2) | 1;
            r.coeffs[8 * i + j] = a * sign;
        }
    }
}

/// `sp_cbd` — public dispatch on mode. Caller supplies a buffer of
/// length `p.cbdseed_bytes`.
pub fn sp_cbd(p: &Params, r: &mut Poly, buf: &[u8]) {
    match p.mode {
        Mode::Mode1 | Mode::ModeT => sp_cbd1(r, buf),
        Mode::Mode3 => cbd_eta1(r, buf),
        Mode::Mode5 => sp_cbd2(r, buf),
    }
}
