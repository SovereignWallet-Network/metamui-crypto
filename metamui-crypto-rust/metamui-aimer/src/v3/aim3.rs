//! The AIM3 one-way function and its MPC view (`aim3.c` upstream).
//!
//! `AIM3(pt) = pt + S_L( Σ_i A_{L+i}·S_i(A_i·pt + b_i) + b_L )` with
//! `S_e(x) = x^{2^e−1} + x^{−1}` and `2L` invertible binary matrices plus
//! `L+1` vectors squeezed from `SHAKE(iv)`.

use super::field::*;
use super::hash::{Hash, Xof};
use super::params::AimerV3Params;
use alloc::vec;
use alloc::vec::Vec;

/// The affine layers derived from the public IV.
pub struct Linear {
    /// `mat_A[j]`, `j < 2L`: λ rows each.
    pub mat_a: Vec<Vec<Gf>>,
    /// `vec_b[j]`, `j ≤ L`.
    pub vec_b: Vec<Gf>,
}

/// One party's multiplication-check inputs (`mult_chk_t`).
#[derive(Clone)]
pub struct MultChk {
    pub x_shares: Vec<Gf>,
    pub z_shares: Vec<Gf>,
    pub a_shares: Vec<Gf>,
    /// `b_shares[i] = y_shares[i]`, `b_shares[L] = pt_share (+ ct)`.
    pub b_shares: Vec<Gf>,
    pub c_share: Gf,
}

/// One party's random tape (`tape_t`), squeezed after its commitment.
#[derive(Clone)]
pub struct Tape {
    pub pt_share: Gf,
    pub y_shares: Vec<Gf>,
    pub a_shares: Vec<Gf>,
    pub c_share: Gf,
}

impl Tape {
    pub fn zero<P: AimerV3Params>() -> Self {
        Tape {
            pt_share: gf_zero(),
            y_shares: vec![gf_zero(); P::L],
            a_shares: vec![gf_zero(); P::L + 1],
            c_share: gf_zero(),
        }
    }

    /// Parse `TAPE_BYTES` squeezed bytes in `tape_t` memory order.
    pub fn from_bytes<P: AimerV3Params>(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), P::TAPE_BYTES);
        let mut t = Self::zero::<P>();
        let mut off = 0;
        let next = |off: &mut usize| {
            let g = gf_from_bytes::<P>(&bytes[*off..*off + P::FB]);
            *off += P::FB;
            g
        };
        t.pt_share = next(&mut off);
        for i in 0..P::L {
            t.y_shares[i] = next(&mut off);
        }
        for i in 0..=P::L {
            t.a_shares[i] = next(&mut off);
        }
        t.c_share = next(&mut off);
        t
    }
}

/// `A = U · L` with unit diagonals: an invertible matrix from λ squeezed rows.
/// `mul_ul(U, L)` returns the rows of `U · L`; the reference passes
/// [`mul_ul_reference`]; a [`super::backend`] crate may supply its own mat-vec kernel.
fn squeeze_invertible_matrix<P: AimerV3Params>(
    xof: &mut Xof,
    mul_ul: &mut dyn FnMut(&[Gf], &[Gf]) -> Vec<Gf>,
) -> Vec<Gf> {
    let bits = P::SECURITY_BITS;
    let mut matrix_l = vec![gf_zero(); bits];
    let mut matrix_u = vec![gf_zero(); bits];
    let mut buf = vec![0u8; P::FB];
    for row in 0..bits {
        xof.squeeze_into(&mut buf);
        let temp = gf_from_bytes::<P>(&buf);
        let ormask = 1u64 << (row % 64);
        let lmask = u64::MAX << (row % 64);
        let umask = !lmask;
        let inter = row / 64;
        for col_word in 0..inter {
            matrix_l[row][col_word] = 0;
            matrix_u[row][col_word] = temp[col_word];
        }
        matrix_l[row][inter] = (temp[inter] & lmask) | ormask;
        matrix_u[row][inter] = (temp[inter] & umask) | ormask;
        for col_word in inter + 1..P::W {
            matrix_l[row][col_word] = temp[col_word];
            matrix_u[row][col_word] = 0;
        }
    }
    mul_ul(&matrix_u, &matrix_l)
}

/// The rows of `U · L`: row `i` is `U[i]` applied to the rows of `L`.
fn mul_ul_reference<P: AimerV3Params>(u: &[Gf], l: &[Gf]) -> Vec<Gf> {
    u.iter().map(|row| gf_mat_vec_mul::<P>(row, l)).collect()
}

/// `aim3_generate_linear`: the `2L` matrices then the `L+1` vectors from `SHAKE(iv)`.
pub fn generate_linear<P: AimerV3Params>(iv: &[u8]) -> Linear {
    generate_linear_with::<P>(iv, &mut mul_ul_reference::<P>)
}

/// [`generate_linear`] with the `U · L` product supplied by the caller, so a
/// [`super::backend`] crate reuses this squeeze order instead of duplicating
/// it. Hidden from the documentation; not a stable API.
#[doc(hidden)]
pub fn generate_linear_with<P: AimerV3Params>(
    iv: &[u8],
    mul_ul: &mut dyn FnMut(&[Gf], &[Gf]) -> Vec<Gf>,
) -> Linear {
    let mut h = Hash::new::<P>();
    h.update(iv);
    let mut xof = h.finalize();
    let mat_a = (0..2 * P::L).map(|_| squeeze_invertible_matrix::<P>(&mut xof, mul_ul)).collect();
    let mut vec_b = Vec::with_capacity(P::L + 1);
    let mut buf = vec![0u8; P::FB];
    for _ in 0..=P::L {
        xof.squeeze_into(&mut buf);
        vec_b.push(gf_from_bytes::<P>(&buf));
    }
    Linear { mat_a, vec_b }
}

/// `S_e(x) = x^{−1} · (x^{2^e} + 1)`
fn sbox<P: AimerV3Params>(x: &Gf, e: usize) -> Gf {
    let inv = gf_inv::<P>(x);
    let mut s = *x;
    for _ in 0..e {
        s = gf_sqr::<P>(&s);
    }
    s[0] ^= 1;
    gf_mul::<P>(&s, &inv)
}

/// `aim3_nozeroinpsb`: `ct = AIM3_iv(pt)`, or `None` when any S-box input is
/// zero (the caller must retry key generation with fresh randomness).
pub fn aim3<P: AimerV3Params>(lin: &Linear, pt: &Gf) -> Option<Gf> {
    let mut state = vec![gf_zero(); P::L];
    for i in 0..P::L {
        let mut s = gf_mat_vec_mul::<P>(pt, &lin.mat_a[i]);
        gf_add_assign::<P>(&mut s, &lin.vec_b[i]);
        if gf_is0::<P>(&s) {
            return None;
        }
        s = sbox::<P>(&s, P::EXPONENTS[i]);
        state[i] = gf_mat_vec_mul::<P>(&s, &lin.mat_a[i + P::L]);
    }
    let mut s = state[0];
    for st in state.iter().skip(1) {
        gf_add_assign::<P>(&mut s, st);
    }
    gf_add_assign::<P>(&mut s, &lin.vec_b[P::L]);
    if gf_is0::<P>(&s) {
        return None;
    }
    let s = sbox::<P>(&s, P::EXPONENTS[P::L]);
    Some(gf_add::<P>(pt, &s))
}

/// `aim3_sbox_outputs`: the `L` input S-box outputs and `pt + ct`.
pub fn sbox_outputs<P: AimerV3Params>(lin: &Linear, pt: &Gf, ct: &Gf) -> Vec<Gf> {
    let mut out = vec![gf_zero(); P::L + 1];
    for i in 0..P::L {
        let mut s = gf_mat_vec_mul::<P>(pt, &lin.mat_a[i]);
        gf_add_assign::<P>(&mut s, &lin.vec_b[i]);
        out[i] = sbox::<P>(&s, P::EXPONENTS[i]);
    }
    out[P::L] = gf_add::<P>(pt, ct);
    out
}

/// `aim3_mpc`: one party's linear share of the multiplication-check inputs.
pub fn aim3_mpc<P: AimerV3Params>(lin: &Linear, tape: &Tape, ct: &Gf, party: usize) -> MultChk {
    let last = party == P::N - 1;
    let a_shares = tape.a_shares.clone();
    let mut b_shares = vec![gf_zero(); P::L + 1];
    b_shares[..P::L].clone_from_slice(&tape.y_shares);
    b_shares[P::L] = tape.pt_share;
    if last {
        gf_add_assign::<P>(&mut b_shares[P::L], ct);
    }
    let c_share = tape.c_share;

    let mut x_shares = vec![gf_zero(); P::L + 1];
    for i in 0..P::L {
        x_shares[i] = gf_mat_vec_mul::<P>(&tape.pt_share, &lin.mat_a[i]);
        if last {
            gf_add_assign::<P>(&mut x_shares[i], &lin.vec_b[i]);
        }
    }
    for ell in 0..P::L {
        gf_mat_vec_mul_add::<P>(&mut x_shares[P::L], &tape.y_shares[ell], &lin.mat_a[ell + P::L]);
    }
    if last {
        gf_add_assign::<P>(&mut x_shares[P::L], &lin.vec_b[P::L]);
    }

    // z[ℓ] = x[ℓ]^{2^e_ℓ} + 1  (the constant only on the last party)
    let mut z_shares = vec![gf_zero(); P::L + 1];
    for ell in 0..=P::L {
        let mut z = gf_sqr::<P>(&x_shares[ell]);
        for _ in 1..P::EXPONENTS[ell] {
            z = gf_sqr::<P>(&z);
        }
        if last {
            z[0] ^= 1;
        }
        z_shares[ell] = z;
    }
    MultChk { x_shares, z_shares, a_shares, b_shares, c_share }
}
