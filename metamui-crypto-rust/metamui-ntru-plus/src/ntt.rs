//! Number Theoretic Transform for NTRU+.
//!
//! A line-for-line port of `ntt.c` from the ntruplus.org reference
//! implementation (commit 621c667, spec dated 2026-02-02), vendored under
//! `metamui-crypto-reference/c/ntruplus-ref/Reference_Implementation/`.
//!
//! NTRU+ works in R_q = Z_q[X]/(X^N - X^{N/2} + 1), q = 3457, and uses a
//! mixed-radix NTT: one radix-2 split at N/2, a radix-3 cascade, then a
//! radix-2 cascade down to base polynomials of degree d:
//! - N=768/1152: N/8 copies of Z_q[X]/(X^4 - zeta), degree-4 base ring
//! - N=864:      N/6 copies of Z_q[X]/(X^3 - zeta), degree-3 base ring
//!
//! Every transform below is in place and mirrors the reference's reduction
//! schedule exactly (which butterflies Barrett-reduce, and where the final
//! Montgomery scalings sit), because the serialized key/ciphertext bytes are
//! taken straight from NTT-domain coefficients: a transform that is only
//! congruent mod q, but reduces at different points, can still serialize to
//! different bytes. Integer arithmetic uses wrapping ops so that the i16
//! behaviour matches the C `int16_t` code on every target.

const Q: i32 = 3457;
const QINV: i16 = 12929u16 as i16;

/// R = 2^16 mod q.
pub const R: i16 = -147;
/// R^{-1} mod q.
const RINV: i16 = -682;
/// R^2 mod q.
const RSQ: i16 = 867;
/// (omega * R) mod q, omega the cube root of unity used by the radix-3 butterflies.
const OMEGA: i16 = -886;
/// (z - z^5)^{-1} * R mod q, where z = zeta^((n/d)/6).
const ZMINUSZ5INV: i16 = -1665;

/// (n/d)^{-1} * R mod q and 2 * (n/d)^{-1} * R mod q, per parameter set.
const NINV_768: i16 = -811;
const TWO_NINV_768: i16 = -1622;
const NINV_864: i16 = -1693;
const TWO_NINV_864: i16 = 71;
const NINV_1152: i16 = -1693;
const TWO_NINV_1152: i16 = 71;

#[inline(always)]
fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV);
    ((a - (t as i32) * Q) >> 16) as i16
}

#[inline(always)]
fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = ((1 << 26) + Q / 2) / Q;
    let t = ((V * (a as i32) + (1 << 25)) >> 26) as i16;
    a.wrapping_sub(t.wrapping_mul(Q as i16))
}

#[inline(always)]
fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce((a as i32) * (b as i32))
}

/// Field inversion a^{q-2} via the reference's addition chain, returned in
/// the plain (non-Montgomery) domain: the chain of `fqmul`s leaves an R^{-k}
/// factor that the final multiplication by R^{-1} cancels for these callers.
#[inline(always)]
fn fqinv(a: i16) -> i16 {
    let t1 = fqmul(a, a);   // 10
    let t2 = fqmul(t1, t1); // 100
    let t2 = fqmul(t2, t2); // 1000
    let t3 = fqmul(t2, t2); // 10000
    let t1 = fqmul(t1, t2); // 1010
    let t2 = fqmul(t1, t3); // 11010
    let t2 = fqmul(t2, t2); // 110100
    let t2 = fqmul(t2, a);  // 110101
    let t1 = fqmul(t1, t2); // 111111
    let t2 = fqmul(t2, t2); // 1101010
    let t2 = fqmul(t2, t2); // 11010100
    let t2 = fqmul(t2, t2); // 110101000
    let t2 = fqmul(t2, t2); // 1101010000
    let t2 = fqmul(t2, t2); // 11010100000
    let t2 = fqmul(t2, t2); // 110101000000
    let t2 = fqmul(t2, t1); // 110101111111
    fqmul(RINV, t2)
}

// ── shared butterflies ─────────────────────────────────────────────────

#[inline(always)]
fn fwd_radix2_split(r: &mut [i16], n: usize, zeta1: i16) {
    for i in 0..n / 2 {
        let t1 = fqmul(zeta1, r[i + n / 2]);
        r[i + n / 2] = r[i].wrapping_add(r[i + n / 2]).wrapping_sub(t1);
        r[i] = r[i].wrapping_add(t1);
    }
}

#[inline(always)]
fn fwd_radix3(r: &mut [i16], start: usize, step: usize, zeta1: i16, zeta2: i16) {
    for i in start..start + step {
        let t1 = fqmul(zeta1, r[i + step]);
        let t2 = fqmul(zeta2, r[i + 2 * step]);
        let t3 = fqmul(OMEGA, t1.wrapping_sub(t2));
        r[i + 2 * step] = r[i].wrapping_sub(t1).wrapping_sub(t3);
        r[i + step] = r[i].wrapping_sub(t2).wrapping_add(t3);
        r[i] = r[i].wrapping_add(t1).wrapping_add(t2);
    }
}

#[inline(always)]
fn inv_radix2(r: &mut [i16], start: usize, step: usize, zeta: i16) {
    for i in start..start + step {
        let t1 = r[i + step];
        r[i + step] = fqmul(zeta, t1.wrapping_sub(r[i]));
        r[i] = barrett_reduce(r[i].wrapping_add(t1));
    }
}

#[inline(always)]
fn inv_radix3(r: &mut [i16], start: usize, step: usize, zeta1: i16, zeta2: i16, reduce_sum: bool) {
    for i in start..start + step {
        let t1 = fqmul(OMEGA, r[i + step].wrapping_sub(r[i]));
        let t2 = fqmul(zeta1, r[i + 2 * step].wrapping_sub(r[i]).wrapping_add(t1));
        let t3 = fqmul(zeta2, r[i + 2 * step].wrapping_sub(r[i + step]).wrapping_sub(t1));
        let sum = r[i].wrapping_add(r[i + step]).wrapping_add(r[i + 2 * step]);
        r[i] = if reduce_sum { barrett_reduce(sum) } else { sum };
        r[i + step] = t2;
        r[i + 2 * step] = t3;
    }
}

#[inline(always)]
fn inv_final_scale(r: &mut [i16], n: usize, ninv: i16, two_ninv: i16) {
    for i in 0..n / 2 {
        let t1 = r[i].wrapping_add(r[i + n / 2]);
        let t2 = fqmul(ZMINUSZ5INV, r[i].wrapping_sub(r[i + n / 2]));
        r[i] = fqmul(ninv, t1.wrapping_sub(t2));
        r[i + n / 2] = fqmul(two_ninv, t2);
    }
}

// ── N = 768 ────────────────────────────────────────────────────────────

/// Forward NTT for NTRU+768, in place. Radix-2 at N/2, one radix-3 level
/// (step 128), radix-2 cascade 64→4 without per-butterfly reduction, then a
/// single Barrett pass over every coefficient.
pub fn ntt_768(r: &mut [i16], zetas: &[i16]) {
    let n = 768;
    debug_assert_eq!(r.len(), n);
    let mut k = 1;
    let zeta1 = zetas[k];
    k += 1;
    fwd_radix2_split(r, n, zeta1);

    let mut start = 0;
    while start < n {
        let z1 = zetas[k];
        let z2 = zetas[k + 1];
        k += 2;
        fwd_radix3(r, start, 128, z1, z2);
        start += 384;
    }

    let mut step = 64;
    while step >= 4 {
        let mut start = 0;
        while start < n {
            let z = zetas[k];
            k += 1;
            for i in start..start + step {
                let t1 = fqmul(z, r[i + step]);
                r[i + step] = r[i].wrapping_sub(t1);
                r[i] = r[i].wrapping_add(t1);
            }
            start += step << 1;
        }
        step >>= 1;
    }

    for x in r.iter_mut() {
        *x = barrett_reduce(*x);
    }
}

/// Inverse NTT for NTRU+768, in place.
pub fn invntt_768(r: &mut [i16], zetas: &[i16]) {
    let n = 768;
    debug_assert_eq!(r.len(), n);
    let mut k: usize = 191;

    let mut step = 4;
    while step <= 64 {
        let mut start = 0;
        while start < n {
            let z = zetas[k];
            k = k.wrapping_sub(1);
            inv_radix2(r, start, step, z);
            start += step << 1;
        }
        step <<= 1;
    }

    let mut start = 0;
    while start < n {
        let z2 = zetas[k];
        let z1 = zetas[k - 1];
        k = k.wrapping_sub(2);
        inv_radix3(r, start, 128, z1, z2, false);
        start += 384;
    }

    inv_final_scale(r, n, NINV_768, TWO_NINV_768);
}

// ── N = 864 ────────────────────────────────────────────────────────────

/// Forward NTT for NTRU+864, in place. Radix-3 levels at step 144 and 48,
/// radix-2 cascade 24→3 with per-butterfly Barrett reduction.
pub fn ntt_864(r: &mut [i16], zetas: &[i16]) {
    let n = 864;
    debug_assert_eq!(r.len(), n);
    let mut k = 1;
    let zeta1 = zetas[k];
    k += 1;
    fwd_radix2_split(r, n, zeta1);

    let mut step = n / 6;
    while step >= 48 {
        let mut start = 0;
        while start < n {
            let z1 = zetas[k];
            let z2 = zetas[k + 1];
            k += 2;
            fwd_radix3(r, start, step, z1, z2);
            start += 3 * step;
        }
        step /= 3;
    }

    let mut step = 24;
    while step >= 3 {
        let mut start = 0;
        while start < n {
            let z = zetas[k];
            k += 1;
            for i in start..start + step {
                let t1 = fqmul(z, r[i + step]);
                r[i + step] = barrett_reduce(r[i].wrapping_sub(t1));
                r[i] = barrett_reduce(r[i].wrapping_add(t1));
            }
            start += step << 1;
        }
        step >>= 1;
    }
}

/// Inverse NTT for NTRU+864, in place.
pub fn invntt_864(r: &mut [i16], zetas: &[i16]) {
    let n = 864;
    debug_assert_eq!(r.len(), n);
    let mut k: usize = 287;

    let mut step = 3;
    while step <= 24 {
        let mut start = 0;
        while start < n {
            let z = zetas[k];
            k = k.wrapping_sub(1);
            inv_radix2(r, start, step, z);
            start += step << 1;
        }
        step <<= 1;
    }

    let mut step = 48;
    while step <= n / 6 {
        let mut start = 0;
        while start < n {
            let z2 = zetas[k];
            let z1 = zetas[k - 1];
            k = k.wrapping_sub(2);
            inv_radix3(r, start, step, z1, z2, true);
            start += 3 * step;
        }
        step *= 3;
    }

    inv_final_scale(r, n, NINV_864, TWO_NINV_864);
}

// ── N = 1152 ───────────────────────────────────────────────────────────

/// Forward NTT for NTRU+1152, in place. Radix-3 levels at step 192 and 64,
/// radix-2 cascade 32→4 with per-butterfly Barrett reduction.
pub fn ntt_1152(r: &mut [i16], zetas: &[i16]) {
    let n = 1152;
    debug_assert_eq!(r.len(), n);
    let mut k = 1;
    let zeta1 = zetas[k];
    k += 1;
    fwd_radix2_split(r, n, zeta1);

    let mut step = n / 6;
    while step >= 64 {
        let mut start = 0;
        while start < n {
            let z1 = zetas[k];
            let z2 = zetas[k + 1];
            k += 2;
            fwd_radix3(r, start, step, z1, z2);
            start += 3 * step;
        }
        step /= 3;
    }

    let mut step = 32;
    while step >= 4 {
        let mut start = 0;
        while start < n {
            let z = zetas[k];
            k += 1;
            for i in start..start + step {
                let t1 = fqmul(z, r[i + step]);
                r[i + step] = barrett_reduce(r[i].wrapping_sub(t1));
                r[i] = barrett_reduce(r[i].wrapping_add(t1));
            }
            start += step << 1;
        }
        step >>= 1;
    }
}

/// Inverse NTT for NTRU+1152, in place.
pub fn invntt_1152(r: &mut [i16], zetas: &[i16]) {
    let n = 1152;
    debug_assert_eq!(r.len(), n);
    let mut k: usize = 287;

    let mut step = 4;
    while step <= 32 {
        let mut start = 0;
        while start < n {
            let z = zetas[k];
            k = k.wrapping_sub(1);
            inv_radix2(r, start, step, z);
            start += step << 1;
        }
        step <<= 1;
    }

    let mut step = 64;
    while step <= n / 6 {
        let mut start = 0;
        while start < n {
            let z2 = zetas[k];
            let z1 = zetas[k - 1];
            k = k.wrapping_sub(2);
            inv_radix3(r, start, step, z1, z2, true);
            start += 3 * step;
        }
        step *= 3;
    }

    inv_final_scale(r, n, NINV_1152, TWO_NINV_1152);
}

// ── degree-4 base ring Z_q[X]/(X^4 - zeta): N = 768, 1152 ─────────────

#[inline(always)]
fn m(a: i16, b: i16) -> i32 {
    (a as i32) * (b as i32)
}

/// r = a * b in Z_q[X]/(X^4 - zeta), plain domain (the trailing R^2 factor
/// cancels the R^{-1} left by the Montgomery products).
pub fn basemul4(r: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    r[0] = montgomery_reduce(m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]));
    r[1] = montgomery_reduce(m(a[2], b[3]) + m(a[3], b[2]));
    r[2] = montgomery_reduce(m(a[3], b[3]));
    r[0] = montgomery_reduce(m(r[0], zeta) + m(a[0], b[0]));
    r[1] = montgomery_reduce(m(r[1], zeta) + m(a[0], b[1]) + m(a[1], b[0]));
    r[2] = montgomery_reduce(m(r[2], zeta) + m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]));
    r[3] = montgomery_reduce(m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]));
    for x in r.iter_mut().take(4) {
        *x = montgomery_reduce(m(*x, RSQ));
    }
}

/// r = a * b + c in Z_q[X]/(X^4 - zeta), plain domain.
pub fn basemul_add4(r: &mut [i16], a: &[i16], b: &[i16], c: &[i16], zeta: i16) {
    r[0] = montgomery_reduce(m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]));
    r[1] = montgomery_reduce(m(a[2], b[3]) + m(a[3], b[2]));
    r[2] = montgomery_reduce(m(a[3], b[3]));
    r[0] = montgomery_reduce(m(r[0], zeta) + m(a[0], b[0]));
    r[1] = montgomery_reduce(m(r[1], zeta) + m(a[0], b[1]) + m(a[1], b[0]));
    r[2] = montgomery_reduce(m(r[2], zeta) + m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]));
    r[3] = montgomery_reduce(m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]));
    for i in 0..4 {
        r[i] = montgomery_reduce(m(c[i], R) + m(r[i], RSQ));
    }
}

/// r = a^{-1} in Z_q[X]/(X^4 - zeta). Returns 0 on success, 1 if `a` is not
/// invertible (`r` is then unspecified; the polynomial wrapper zeroes it).
pub fn baseinv4(r: &mut [i16], a: &[i16], zeta: i16) -> i32 {
    let t0 = montgomery_reduce(m(a[2], a[2]) - 2 * m(a[1], a[3]));
    let t1 = montgomery_reduce(m(a[3], a[3]));
    let t0 = montgomery_reduce(m(a[0], a[0]) + m(t0, zeta));
    let t1 = montgomery_reduce(m(a[1], a[1]) + m(t1, zeta) - 2 * m(a[0], a[2]));
    let t2 = montgomery_reduce(m(t1, zeta));
    let t3 = montgomery_reduce(m(t0, t0) - m(t1, t2));
    if t3 == 0 {
        return 1;
    }
    r[0] = montgomery_reduce(m(a[0], t0) + m(a[2], t2));
    r[1] = montgomery_reduce(m(a[3], t2) + m(a[1], t0));
    r[2] = montgomery_reduce(m(a[2], t0) + m(a[0], t1));
    r[3] = montgomery_reduce(m(a[1], t1) + m(a[3], t0));
    let t3 = fqinv(t3);
    r[0] = montgomery_reduce(m(r[0], t3));
    r[1] = montgomery_reduce(m(r[1], t3)).wrapping_neg();
    r[2] = montgomery_reduce(m(r[2], t3));
    r[3] = montgomery_reduce(m(r[3], t3)).wrapping_neg();
    0
}

// ── degree-3 base ring Z_q[X]/(X^3 - zeta): N = 864 ───────────────────

/// r = a * b in Z_q[X]/(X^3 - zeta), plain domain.
pub fn basemul3(r: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    r[0] = montgomery_reduce(m(a[2], b[1]) + m(a[1], b[2]));
    r[1] = montgomery_reduce(m(a[2], b[2]));
    r[0] = montgomery_reduce(m(r[0], zeta) + m(a[0], b[0]));
    r[1] = montgomery_reduce(m(r[1], zeta) + m(a[0], b[1]) + m(a[1], b[0]));
    r[2] = montgomery_reduce(m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]));
    for x in r.iter_mut().take(3) {
        *x = montgomery_reduce(m(*x, RSQ));
    }
}

/// r = a * b + c in Z_q[X]/(X^3 - zeta), plain domain.
pub fn basemul_add3(r: &mut [i16], a: &[i16], b: &[i16], c: &[i16], zeta: i16) {
    r[0] = montgomery_reduce(m(a[2], b[1]) + m(a[1], b[2]));
    r[1] = montgomery_reduce(m(a[2], b[2]));
    r[0] = montgomery_reduce(m(r[0], zeta) + m(a[0], b[0]));
    r[1] = montgomery_reduce(m(r[1], zeta) + m(a[0], b[1]) + m(a[1], b[0]));
    r[2] = montgomery_reduce(m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]));
    for i in 0..3 {
        r[i] = montgomery_reduce(m(c[i], R) + m(r[i], RSQ));
    }
}

/// r = a^{-1} in Z_q[X]/(X^3 - zeta). Returns 0 on success, 1 if not invertible.
pub fn baseinv3(r: &mut [i16], a: &[i16], zeta: i16) -> i32 {
    r[0] = montgomery_reduce(m(a[1], a[2]));
    r[1] = montgomery_reduce(m(a[2], a[2]));
    r[2] = montgomery_reduce(m(a[1], a[1]) - m(a[0], a[2]));
    r[0] = montgomery_reduce(m(a[0], a[0]) - m(r[0], zeta));
    r[1] = montgomery_reduce(m(r[1], zeta) - m(a[0], a[1]));
    let t = montgomery_reduce(m(r[2], a[1]) + m(r[1], a[2]));
    let t = montgomery_reduce(m(t, zeta) + m(r[0], a[0]));
    if t == 0 {
        return 1;
    }
    let t = fqinv(t);
    r[0] = montgomery_reduce(m(r[0], t));
    r[1] = montgomery_reduce(m(r[1], t));
    r[2] = montgomery_reduce(m(r[2], t));
    0
}
