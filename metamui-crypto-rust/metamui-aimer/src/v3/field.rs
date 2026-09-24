//! GF(2^λ) arithmetic for AIMer v3 (`field*.c`, `field_common.c` upstream).
//!
//! Elements are little-endian arrays of 64-bit words; only the first
//! `P::W` words of a [`Gf`] are meaningful. The reduction polynomials are
//! those of the reference: x¹²⁸+x⁷+x²+x+1, x¹⁹²+x⁷+x²+x+1, x²⁵⁶+x¹⁰+x⁵+x²+1.

use super::params::AimerV3Params;

/// A field element (up to 256 bits).
pub type Gf = [u64; 4];

/// Carry-less 64×64 → 128-bit product, constant-time. Returns `(hi, lo)`.
#[inline]
fn clmul64(a: u64, b: u64) -> (u64, u64) {
    let a = a as u128;
    let mut r: u128 = 0;
    for i in 0..64 {
        let m = 0u128.wrapping_sub(((b >> i) & 1) as u128);
        r ^= (a << i) & m;
    }
    ((r >> 64) as u64, r as u64)
}

/// Reduce a `2W`-word polynomial product modulo the field polynomial.
///
/// Exposed, hidden from the documentation, so that a [`super::backend`] crate
/// reduces with the same code; not a stable API.
#[doc(hidden)]
#[inline]
pub fn gf_mod<P: AimerV3Params>(a: &[u64; 8]) -> Gf {
    let mut c: Gf = [0; 4];
    match P::W {
        2 => {
            let t = a[2] ^ (a[3] >> 57) ^ (a[3] >> 62) ^ (a[3] >> 63);
            c[1] = a[1] ^ a[3];
            c[1] ^= (a[3] << 7) | (t >> 57);
            c[1] ^= (a[3] << 2) | (t >> 62);
            c[1] ^= (a[3] << 1) | (t >> 63);
            c[0] = a[0] ^ t ^ (t << 7) ^ (t << 2) ^ (t << 1);
        }
        3 => {
            let t = a[3] ^ (a[5] >> 57) ^ (a[5] >> 62) ^ (a[5] >> 63);
            c[2] = a[2] ^ a[5];
            c[2] ^= (a[5] << 7) | (a[4] >> 57);
            c[2] ^= (a[5] << 2) | (a[4] >> 62);
            c[2] ^= (a[5] << 1) | (a[4] >> 63);
            c[1] = a[1] ^ a[4];
            c[1] ^= (a[4] << 7) | (t >> 57);
            c[1] ^= (a[4] << 2) | (t >> 62);
            c[1] ^= (a[4] << 1) | (t >> 63);
            c[0] = a[0] ^ t ^ (t << 7) ^ (t << 2) ^ (t << 1);
        }
        4 => {
            let t = a[4] ^ (a[7] >> 54) ^ (a[7] >> 59) ^ (a[7] >> 62);
            c[3] = a[3] ^ a[7];
            c[3] ^= (a[7] << 10) | (a[6] >> 54);
            c[3] ^= (a[7] << 5) | (a[6] >> 59);
            c[3] ^= (a[7] << 2) | (a[6] >> 62);
            c[2] = a[2] ^ a[6];
            c[2] ^= (a[6] << 10) | (a[5] >> 54);
            c[2] ^= (a[6] << 5) | (a[5] >> 59);
            c[2] ^= (a[6] << 2) | (a[5] >> 62);
            c[1] = a[1] ^ a[5];
            c[1] ^= (a[5] << 10) | (t >> 54);
            c[1] ^= (a[5] << 5) | (t >> 59);
            c[1] ^= (a[5] << 2) | (t >> 62);
            c[0] = a[0] ^ t ^ (t << 10) ^ (t << 5) ^ (t << 2);
        }
        _ => unreachable!("AIMer field width"),
    }
    c
}

pub fn gf_zero() -> Gf {
    [0; 4]
}

pub fn gf_is0<P: AimerV3Params>(a: &Gf) -> bool {
    let mut r = 0u64;
    for w in a.iter().take(P::W) {
        r |= *w;
    }
    r == 0
}

pub fn gf_add<P: AimerV3Params>(a: &Gf, b: &Gf) -> Gf {
    let mut c = [0; 4];
    for i in 0..P::W {
        c[i] = a[i] ^ b[i];
    }
    c
}

pub fn gf_add_assign<P: AimerV3Params>(a: &mut Gf, b: &Gf) {
    for i in 0..P::W {
        a[i] ^= b[i];
    }
}

pub fn gf_mul<P: AimerV3Params>(a: &Gf, b: &Gf) -> Gf {
    let mut t = [0u64; 8];
    for i in 0..P::W {
        for j in 0..P::W {
            let (hi, lo) = clmul64(a[i], b[j]);
            t[i + j] ^= lo;
            t[i + j + 1] ^= hi;
        }
    }
    gf_mod::<P>(&t)
}

/// `c += a · b`
pub fn gf_mul_add<P: AimerV3Params>(c: &mut Gf, a: &Gf, b: &Gf) {
    let r = gf_mul::<P>(a, b);
    gf_add_assign::<P>(c, &r);
}

pub fn gf_sqr<P: AimerV3Params>(a: &Gf) -> Gf {
    let mut t = [0u64; 8];
    for i in 0..P::W {
        let (hi, lo) = clmul64(a[i], a[i]);
        t[2 * i] = lo;
        t[2 * i + 1] = hi;
    }
    gf_mod::<P>(&t)
}

/// `a^{2^λ − 2}` (Fermat inversion, as `gf_inv` upstream; `0 ↦ 0`).
pub fn gf_inv<P: AimerV3Params>(a: &Gf) -> Gf {
    let mut temp = *a;
    let mut c: Gf = [0; 4];
    c[0] = 1;
    for _ in 1..P::SECURITY_BITS {
        temp = gf_sqr::<P>(&temp);
        c = gf_mul::<P>(&c, &temp);
    }
    c
}

/// `c = Σ_i a_i · b[i]` over the bits `a_i` of `a` (little-endian word, LSB
/// first), constant-time — a binary matrix `b` (λ rows) applied to `a`.
pub fn gf_mat_vec_mul<P: AimerV3Params>(a: &Gf, b: &[Gf]) -> Gf {
    debug_assert_eq!(b.len(), P::SECURITY_BITS);
    let mut c: Gf = [0; 4];
    let mut idx = 0usize;
    for i in 0..P::W {
        let word = a[i];
        for j in 0..64 {
            let m = 0u64.wrapping_sub((word >> j) & 1);
            let row = &b[idx];
            for k in 0..P::W {
                c[k] ^= row[k] & m;
            }
            idx += 1;
        }
    }
    c
}

/// `c += Σ_i a_i · b[i]`
pub fn gf_mat_vec_mul_add<P: AimerV3Params>(c: &mut Gf, a: &Gf, b: &[Gf]) {
    let r = gf_mat_vec_mul::<P>(a, b);
    gf_add_assign::<P>(c, &r);
}

pub fn gf_from_bytes<P: AimerV3Params>(bytes: &[u8]) -> Gf {
    debug_assert_eq!(bytes.len(), P::FB);
    let mut out: Gf = [0; 4];
    for (i, chunk) in bytes.chunks_exact(8).enumerate().take(P::W) {
        out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

pub fn gf_to_bytes<P: AimerV3Params>(a: &Gf, out: &mut [u8]) {
    debug_assert_eq!(out.len(), P::FB);
    for i in 0..P::W {
        out[8 * i..8 * i + 8].copy_from_slice(&a[i].to_le_bytes());
    }
}

pub fn gf_bytes<P: AimerV3Params>(a: &Gf) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0u8; P::FB];
    gf_to_bytes::<P>(a, &mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::params::{Aimer128s, Aimer192s, Aimer256s};

    fn check_inverse<P: AimerV3Params>() {
        let mut a: Gf = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210, 0x1111_2222_3333_4444, 0x5555_6666_7777_8888];
        for w in a.iter_mut().skip(P::W) {
            *w = 0;
        }
        let inv = gf_inv::<P>(&a);
        let one = gf_mul::<P>(&a, &inv);
        let mut expect: Gf = [0; 4];
        expect[0] = 1;
        assert_eq!(one, expect);
        assert_eq!(gf_sqr::<P>(&a), gf_mul::<P>(&a, &a));
    }

    #[test]
    fn inverse_and_square_agree() {
        check_inverse::<Aimer128s>();
        check_inverse::<Aimer192s>();
        check_inverse::<Aimer256s>();
    }
}
