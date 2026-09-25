//! Polynomial layer for NTRU+ — a port of `poly.c` from the ntruplus.org
//! reference implementation (commit 621c667, spec dated 2026-02-02).
//!
//! Polynomials live in R_q = Z_q[X]/(X^N - X^{N/2} + 1), q = 3457, with i16
//! coefficients. Serialization packs two 12-bit coefficients into three bytes
//! sequentially; the centered-binomial sampler and the SOTP encoder pair byte
//! `i` of the random tape with byte `i + N/8`. Both layouts changed in the 2026
//! revision (the 2025 KpqClean revision interleaved 64-coefficient blocks and
//! 16-bit words), which is why they are ported here rather than kept generic.

use crate::ntt;
use crate::params::NtruPlusParams;
use alloc::vec;
use alloc::vec::Vec;

/// A polynomial with N coefficients in Z_q.
#[derive(Clone)]
pub struct Poly {
    pub coeffs: Vec<i16>,
}

impl Poly {
    /// Create a zero polynomial of size n.
    pub fn zero(n: usize) -> Self {
        Self { coeffs: vec![0i16; n] }
    }
}

// ── serialization ──────────────────────────────────────────────────────

/// Serialize: coefficient pairs (2i, 2i+1) → bytes (3i, 3i+1, 3i+2), each
/// coefficient first lifted to [0, q).
pub fn poly_tobytes<P: NtruPlusParams>(r: &mut [u8], a: &Poly) {
    let q = P::Q as i16;
    for i in 0..P::N / 2 {
        let mut t0 = a.coeffs[2 * i];
        t0 = t0.wrapping_add((t0 >> 15) & q);
        let mut t1 = a.coeffs[2 * i + 1];
        t1 = t1.wrapping_add((t1 >> 15) & q);
        r[3 * i] = t0 as u8;
        r[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        r[3 * i + 2] = (t1 >> 4) as u8;
    }
}

/// Deserialize: inverse of [`poly_tobytes`]. Returns 1 if any 12-bit
/// coefficient is `>= q`, else 0.
///
/// Specification 2026-07-10 §6.3: every algorithm aborts when Decode_q yields
/// a coefficient outside `0..q-1`. A 12-bit field holds values up to 4095 and
/// q = 3457, so every coefficient `v <= 638` has a second encoding `v + q`
/// that the arithmetic reduces to the same residue; decapsulation compares
/// recomputed polynomials rather than ciphertext bytes, so without this check
/// a modified ciphertext decapsulates to the original shared secret. The flag
/// is accumulated without branching, as in the reference (e12445a).
pub fn poly_frombytes<P: NtruPlusParams>(r: &mut Poly, a: &[u8]) -> u8 {
    let q_minus_1 = (P::Q - 1) as u32;
    let mut fail = 0u32;
    for i in 0..P::N / 2 {
        let t0 = ((a[3 * i] as u16) | ((a[3 * i + 1] as u16) << 8)) & 0xFFF;
        let t1 = (((a[3 * i + 1] as u16) >> 4) | ((a[3 * i + 2] as u16) << 4)) & 0xFFF;
        r.coeffs[2 * i] = t0 as i16;
        r.coeffs[2 * i + 1] = t1 as i16;
        fail |= q_minus_1.wrapping_sub(t0 as u32);
        fail |= q_minus_1.wrapping_sub(t1 as u32);
    }
    (fail >> 31) as u8
}

// ── coefficient-domain arithmetic ──────────────────────────────────────

/// r = a - b
pub fn poly_sub(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..a.coeffs.len() {
        r.coeffs[i] = a.coeffs[i].wrapping_sub(b.coeffs[i]);
    }
}

/// r = 3 * a
pub fn poly_triple(r: &mut Poly, a: &Poly) {
    for i in 0..a.coeffs.len() {
        r.coeffs[i] = a.coeffs[i].wrapping_mul(3);
    }
}

/// Centered representative of `a` mod 3, in {-1, 0, 1}, for `a` in (-2q, 2q).
#[inline(always)]
fn crepmod3(a: i16) -> i16 {
    const Q: i16 = 3457;
    const V: i32 = ((1 << 15) + 3 / 2) / 3;
    let mut a = a;
    a = a.wrapping_add((a >> 15) & Q);
    a = a.wrapping_sub((Q + 1) / 2);
    a = a.wrapping_add((a >> 15) & Q);
    a = a.wrapping_sub((Q - 1) / 2);
    let t = ((V * (a as i32) + (1 << 14)) >> 15) as i16;
    a.wrapping_sub(t.wrapping_mul(3))
}

/// Apply [`crepmod3`] to every coefficient.
pub fn poly_crepmod3(r: &mut Poly, a: &Poly) {
    for i in 0..a.coeffs.len() {
        r.coeffs[i] = crepmod3(a.coeffs[i]);
    }
}

// ── NTT dispatch ───────────────────────────────────────────────────────

/// Forward NTT, in place.
pub fn poly_ntt<P: NtruPlusParams>(r: &mut Poly) {
    let z = P::zetas();
    match P::N {
        768 => ntt::ntt_768(&mut r.coeffs, z),
        864 => ntt::ntt_864(&mut r.coeffs, z),
        1152 => ntt::ntt_1152(&mut r.coeffs, z),
        _ => unreachable!("no NTT for N = {}", P::N),
    }
}

/// Inverse NTT, in place.
pub fn poly_invntt<P: NtruPlusParams>(r: &mut Poly) {
    let z = P::zetas();
    match P::N {
        768 => ntt::invntt_768(&mut r.coeffs, z),
        864 => ntt::invntt_864(&mut r.coeffs, z),
        1152 => ntt::invntt_1152(&mut r.coeffs, z),
        _ => unreachable!("no NTT for N = {}", P::N),
    }
}

/// Index of the first base-ring twiddle: the reference reads `zetas[96 + i]`
/// for N=768 and `zetas[144 + i]` for N=864/1152, i.e. the second half of
/// the table.
#[inline(always)]
fn base_zeta_offset<P: NtruPlusParams>() -> usize {
    P::ZETAS_LEN / 2
}

/// NTT-domain multiplication: r = a * b.
pub fn poly_basemul<P: NtruPlusParams>(r: &mut Poly, a: &Poly, b: &Poly) {
    let z = P::zetas();
    let off = base_zeta_offset::<P>();
    let d = P::BASEMUL_DEGREE;
    for i in 0..P::N / (2 * d) {
        let (lo, hi) = (2 * d * i, 2 * d * i + d);
        match d {
            4 => {
                ntt::basemul4(&mut r.coeffs[lo..hi], &a.coeffs[lo..hi], &b.coeffs[lo..hi], z[off + i]);
                ntt::basemul4(&mut r.coeffs[hi..hi + d], &a.coeffs[hi..hi + d], &b.coeffs[hi..hi + d], -z[off + i]);
            }
            3 => {
                ntt::basemul3(&mut r.coeffs[lo..hi], &a.coeffs[lo..hi], &b.coeffs[lo..hi], z[off + i]);
                ntt::basemul3(&mut r.coeffs[hi..hi + d], &a.coeffs[hi..hi + d], &b.coeffs[hi..hi + d], -z[off + i]);
            }
            _ => unreachable!(),
        }
    }
}

/// NTT-domain fused multiply-add: r = a * b + c.
pub fn poly_basemul_add<P: NtruPlusParams>(r: &mut Poly, a: &Poly, b: &Poly, c: &Poly) {
    let z = P::zetas();
    let off = base_zeta_offset::<P>();
    let d = P::BASEMUL_DEGREE;
    for i in 0..P::N / (2 * d) {
        let (lo, hi) = (2 * d * i, 2 * d * i + d);
        match d {
            4 => {
                ntt::basemul_add4(&mut r.coeffs[lo..hi], &a.coeffs[lo..hi], &b.coeffs[lo..hi], &c.coeffs[lo..hi], z[off + i]);
                ntt::basemul_add4(&mut r.coeffs[hi..hi + d], &a.coeffs[hi..hi + d], &b.coeffs[hi..hi + d], &c.coeffs[hi..hi + d], -z[off + i]);
            }
            3 => {
                ntt::basemul_add3(&mut r.coeffs[lo..hi], &a.coeffs[lo..hi], &b.coeffs[lo..hi], &c.coeffs[lo..hi], z[off + i]);
                ntt::basemul_add3(&mut r.coeffs[hi..hi + d], &a.coeffs[hi..hi + d], &b.coeffs[hi..hi + d], &c.coeffs[hi..hi + d], -z[off + i]);
            }
            _ => unreachable!(),
        }
    }
}

/// NTT-domain inversion: r = a^{-1}. Returns 0 on success; on a
/// non-invertible input returns 1 and zeroes `r`, as the reference does.
pub fn poly_baseinv<P: NtruPlusParams>(r: &mut Poly, a: &Poly) -> i32 {
    let z = P::zetas();
    let off = base_zeta_offset::<P>();
    let d = P::BASEMUL_DEGREE;
    for i in 0..P::N / (2 * d) {
        let (lo, hi) = (2 * d * i, 2 * d * i + d);
        let (fail_lo, fail_hi) = match d {
            4 => (
                ntt::baseinv4(&mut r.coeffs[lo..hi], &a.coeffs[lo..hi], z[off + i]),
                ntt::baseinv4(&mut r.coeffs[hi..hi + d], &a.coeffs[hi..hi + d], -z[off + i]),
            ),
            3 => (
                ntt::baseinv3(&mut r.coeffs[lo..hi], &a.coeffs[lo..hi], z[off + i]),
                ntt::baseinv3(&mut r.coeffs[hi..hi + d], &a.coeffs[hi..hi + d], -z[off + i]),
            ),
            _ => unreachable!(),
        };
        if fail_lo != 0 || fail_hi != 0 {
            for x in r.coeffs.iter_mut() {
                *x = 0;
            }
            return 1;
        }
    }
    0
}

// ── sampling: CBD1 and SOTP ────────────────────────────────────────────

/// Centered binomial sampler with eta = 1 over an N/4-byte tape:
/// coefficient 8i+j = bit j of byte i minus bit j of byte i + N/8.
pub fn poly_cbd1<P: NtruPlusParams>(r: &mut Poly, buf: &[u8]) {
    let n = P::N;
    for i in 0..n / 8 {
        let mut t1 = buf[i];
        let mut t2 = buf[i + n / 8];
        for j in 0..8 {
            r.coeffs[8 * i + j] = (t1 & 1) as i16 - (t2 & 1) as i16;
            t1 >>= 1;
            t2 >>= 1;
        }
    }
}

/// SOTP encode: XOR the N/8-byte message into the first half of the tape,
/// then sample with [`poly_cbd1`].
pub fn poly_sotp_encode<P: NtruPlusParams>(r: &mut Poly, msg: &[u8], buf: &[u8]) {
    let n = P::N;
    let mut tmp = vec![0u8; n / 4];
    for i in 0..n / 8 {
        tmp[i] = buf[i] ^ msg[i];
    }
    tmp[n / 8..n / 4].copy_from_slice(&buf[n / 8..n / 4]);
    poly_cbd1::<P>(r, &tmp);
}

/// SOTP decode: recover the N/8-byte message from a ternary polynomial and
/// the tape. Returns 0 when every coefficient was in {-1, 0, 1}; otherwise
/// returns 1 and zeroes `msg`, as the reference does.
pub fn poly_sotp_decode<P: NtruPlusParams>(msg: &mut [u8], a: &Poly, buf: &[u8]) -> i32 {
    let n = P::N;
    let mut r: u32 = 0;
    for i in 0..n / 8 {
        let mut t1 = buf[i];
        let mut t2 = buf[i + n / 8];
        let mut t3: u8 = 0;
        for j in 0..8 {
            let mut t4 = (t2 & 1) as u16;
            t4 = t4.wrapping_add(a.coeffs[8 * i + j] as u16);
            r |= t4 as u32;
            t4 = (t4 ^ (t1 as u16)) & 1;
            t3 ^= (t4 << j) as u8;
            t1 >>= 1;
            t2 >>= 1;
        }
        msg[i] = t3;
    }
    r >>= 1;
    let r = r.wrapping_neg() >> 31;
    let mask = (r as u8).wrapping_sub(1);
    for m in msg.iter_mut().take(n / 8) {
        *m &= mask;
    }
    r as i32
}

/// Byte comparison by OR-accumulation, no data-dependent branch. Returns 0 if equal, 1 if different.
pub fn verify(a: &[u8], b: &[u8]) -> i32 {
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    ((acc as u64).wrapping_neg() >> 63) as i32
}
