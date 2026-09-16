// MetaMUI Falcon - AVX-512 Complex FFT Operations (f64)
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AVX-512F-accelerated complex FFT domain operations.
//!
//! Processes 8 × f64 per `__m512d` register (double AVX2 throughput).
//! Uses FMA via `_mm512_fmadd_pd` / `_mm512_fmsub_pd`.
//!
//! Layout: `f[0..n/2-1]` = real parts, `f[n/2..n-1]` = imaginary parts.
//!
//! All operations are constant-time (no data-dependent branches).

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

use core::f64::consts::PI;

// ================================================================
// Precomputed SOA twiddle tables for split/merge
// ================================================================

const MAX_LOGN: usize = 10;
const MAX_QN: usize = 1 << (MAX_LOGN - 2);

struct FftTwiddles512 {
    cos: [f64; MAX_QN],
    sin: [f64; MAX_QN],
    ready: bool,
}

impl FftTwiddles512 {
    const fn zeroed() -> Self {
        Self { cos: [0.0; MAX_QN], sin: [0.0; MAX_QN], ready: false }
    }
}

static mut FFT_TW512: [FftTwiddles512; MAX_LOGN + 1] = [
    FftTwiddles512::zeroed(), FftTwiddles512::zeroed(), FftTwiddles512::zeroed(),
    FftTwiddles512::zeroed(), FftTwiddles512::zeroed(), FftTwiddles512::zeroed(),
    FftTwiddles512::zeroed(), FftTwiddles512::zeroed(), FftTwiddles512::zeroed(),
    FftTwiddles512::zeroed(), FftTwiddles512::zeroed(),
];

fn ensure_twiddles(logn: usize) {
    if logn < 2 || logn > MAX_LOGN { return; }
    unsafe {
        if FFT_TW512[logn].ready { return; }
        let n = 1usize << logn;
        let qn = n >> 2;
        let inv_n = PI / n as f64;
        for k in 0..qn {
            let angle = (2 * k + 1) as f64 * inv_n;
            FFT_TW512[logn].cos[k] = angle.cos();
            FFT_TW512[logn].sin[k] = angle.sin();
        }
        FFT_TW512[logn].ready = true;
    }
}

// ================================================================
// AVX-512 Pointwise Operations (8 × f64)
// ================================================================

/// c = a + b
///
/// # Safety
/// Requires AVX-512F.
#[target_feature(enable = "avx512f")]
pub unsafe fn poly_add_fft_avx512(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let n = 1usize << logn;
    let mut i = 0;
    while i + 8 <= n {
        let va = _mm512_loadu_pd(a.as_ptr().add(i));
        let vb = _mm512_loadu_pd(b.as_ptr().add(i));
        _mm512_storeu_pd(c.as_mut_ptr().add(i), _mm512_add_pd(va, vb));
        i += 8;
    }
    while i < n { c[i] = a[i] + b[i]; i += 1; }
}

/// c = a - b
///
/// # Safety
/// Requires AVX-512F.
#[target_feature(enable = "avx512f")]
pub unsafe fn poly_sub_fft_avx512(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let n = 1usize << logn;
    let mut i = 0;
    while i + 8 <= n {
        let va = _mm512_loadu_pd(a.as_ptr().add(i));
        let vb = _mm512_loadu_pd(b.as_ptr().add(i));
        _mm512_storeu_pd(c.as_mut_ptr().add(i), _mm512_sub_pd(va, vb));
        i += 8;
    }
    while i < n { c[i] = a[i] - b[i]; i += 1; }
}

/// c = a * b (complex multiply with FMA)
///
/// # Safety
/// Requires AVX-512F.
#[target_feature(enable = "avx512f")]
pub unsafe fn poly_mul_fft_avx512(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut i = 0;
    while i + 8 <= hn {
        let a_re = _mm512_loadu_pd(a.as_ptr().add(i));
        let a_im = _mm512_loadu_pd(a.as_ptr().add(i + hn));
        let b_re = _mm512_loadu_pd(b.as_ptr().add(i));
        let b_im = _mm512_loadu_pd(b.as_ptr().add(i + hn));

        // c_re = a_re*b_re - a_im*b_im
        let c_re = _mm512_fmsub_pd(a_re, b_re, _mm512_mul_pd(a_im, b_im));
        // c_im = a_re*b_im + a_im*b_re
        let c_im = _mm512_fmadd_pd(a_re, b_im, _mm512_mul_pd(a_im, b_re));

        _mm512_storeu_pd(c.as_mut_ptr().add(i), c_re);
        _mm512_storeu_pd(c.as_mut_ptr().add(i + hn), c_im);
        i += 8;
    }
    while i < hn {
        let (ar, ai) = (a[i], a[i + hn]);
        let (br, bi) = (b[i], b[i + hn]);
        c[i]      = ar * br - ai * bi;
        c[i + hn] = ar * bi + ai * br;
        i += 1;
    }
}

/// c = a * conj(b)
///
/// # Safety
/// Requires AVX-512F.
#[target_feature(enable = "avx512f")]
pub unsafe fn poly_muladj_fft_avx512(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut i = 0;
    while i + 8 <= hn {
        let a_re = _mm512_loadu_pd(a.as_ptr().add(i));
        let a_im = _mm512_loadu_pd(a.as_ptr().add(i + hn));
        let b_re = _mm512_loadu_pd(b.as_ptr().add(i));
        let b_im = _mm512_loadu_pd(b.as_ptr().add(i + hn));

        // c_re = a_re*b_re + a_im*b_im
        let c_re = _mm512_fmadd_pd(a_re, b_re, _mm512_mul_pd(a_im, b_im));
        // c_im = a_im*b_re - a_re*b_im
        let c_im = _mm512_fmsub_pd(a_im, b_re, _mm512_mul_pd(a_re, b_im));

        _mm512_storeu_pd(c.as_mut_ptr().add(i), c_re);
        _mm512_storeu_pd(c.as_mut_ptr().add(i + hn), c_im);
        i += 8;
    }
    while i < hn {
        let (ar, ai) = (a[i], a[i + hn]);
        let (br, bi) = (b[i], b[i + hn]);
        c[i]      = ar * br + ai * bi;
        c[i + hn] = ai * br - ar * bi;
        i += 1;
    }
}

/// c = acc + a * b (fused multiply-add)
///
/// # Safety
/// Requires AVX-512F.
#[target_feature(enable = "avx512f")]
pub unsafe fn poly_muladd_fft_avx512(c: &mut [f64], a: &[f64], b: &[f64], acc: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut i = 0;
    while i + 8 <= hn {
        let a_re = _mm512_loadu_pd(a.as_ptr().add(i));
        let a_im = _mm512_loadu_pd(a.as_ptr().add(i + hn));
        let b_re = _mm512_loadu_pd(b.as_ptr().add(i));
        let b_im = _mm512_loadu_pd(b.as_ptr().add(i + hn));
        let acc_re = _mm512_loadu_pd(acc.as_ptr().add(i));
        let acc_im = _mm512_loadu_pd(acc.as_ptr().add(i + hn));

        let mul_re = _mm512_fmsub_pd(a_re, b_re, _mm512_mul_pd(a_im, b_im));
        let mul_im = _mm512_fmadd_pd(a_re, b_im, _mm512_mul_pd(a_im, b_re));

        _mm512_storeu_pd(c.as_mut_ptr().add(i), _mm512_add_pd(acc_re, mul_re));
        _mm512_storeu_pd(c.as_mut_ptr().add(i + hn), _mm512_add_pd(acc_im, mul_im));
        i += 8;
    }
    while i < hn {
        let (ar, ai) = (a[i], a[i + hn]);
        let (br, bi) = (b[i], b[i + hn]);
        c[i]      = acc[i]      + (ar * br - ai * bi);
        c[i + hn] = acc[i + hn] + (ar * bi + ai * br);
        i += 1;
    }
}

/// c = acc - a * b (fused multiply-subtract)
///
/// # Safety
/// Requires AVX-512F.
#[target_feature(enable = "avx512f")]
pub unsafe fn poly_mulsub_fft_avx512(c: &mut [f64], a: &[f64], b: &[f64], acc: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut i = 0;
    while i + 8 <= hn {
        let a_re = _mm512_loadu_pd(a.as_ptr().add(i));
        let a_im = _mm512_loadu_pd(a.as_ptr().add(i + hn));
        let b_re = _mm512_loadu_pd(b.as_ptr().add(i));
        let b_im = _mm512_loadu_pd(b.as_ptr().add(i + hn));
        let acc_re = _mm512_loadu_pd(acc.as_ptr().add(i));
        let acc_im = _mm512_loadu_pd(acc.as_ptr().add(i + hn));

        let mul_re = _mm512_fmsub_pd(a_re, b_re, _mm512_mul_pd(a_im, b_im));
        let mul_im = _mm512_fmadd_pd(a_re, b_im, _mm512_mul_pd(a_im, b_re));

        _mm512_storeu_pd(c.as_mut_ptr().add(i), _mm512_sub_pd(acc_re, mul_re));
        _mm512_storeu_pd(c.as_mut_ptr().add(i + hn), _mm512_sub_pd(acc_im, mul_im));
        i += 8;
    }
    while i < hn {
        let (ar, ai) = (a[i], a[i + hn]);
        let (br, bi) = (b[i], b[i + hn]);
        c[i]      = acc[i]      - (ar * br - ai * bi);
        c[i + hn] = acc[i + hn] - (ar * bi + ai * br);
        i += 1;
    }
}

/// c = conj(a)
///
/// # Safety
/// Requires AVX-512F.
#[target_feature(enable = "avx512f")]
pub unsafe fn poly_adj_fft_avx512(c: &mut [f64], a: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    // Negate sign bit of f64 via XOR with -0.0
    let neg = _mm512_set1_pd(-0.0);
    let mut i = 0;

    // Copy real parts
    while i + 8 <= hn {
        _mm512_storeu_pd(c.as_mut_ptr().add(i), _mm512_loadu_pd(a.as_ptr().add(i)));
        i += 8;
    }
    while i < hn { c[i] = a[i]; i += 1; }

    // Negate imaginary parts
    i = 0;
    while i + 8 <= hn {
        let v = _mm512_loadu_pd(a.as_ptr().add(hn + i));
        _mm512_storeu_pd(c.as_mut_ptr().add(hn + i),
            _mm512_castsi512_pd(_mm512_xor_si512(
                _mm512_castpd_si512(v), _mm512_castpd_si512(neg))));
        i += 8;
    }
    while i < hn { c[hn + i] = -a[hn + i]; i += 1; }
}

/// c = 1/a
///
/// # Safety
/// Requires AVX-512F.
#[target_feature(enable = "avx512f")]
pub unsafe fn poly_inv_fft_avx512(c: &mut [f64], a: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let ones = _mm512_set1_pd(1.0);
    let neg = _mm512_set1_pd(-0.0);
    let mut i = 0;
    while i + 8 <= hn {
        let re = _mm512_loadu_pd(a.as_ptr().add(i));
        let im = _mm512_loadu_pd(a.as_ptr().add(i + hn));
        let norm = _mm512_fmadd_pd(im, im, _mm512_mul_pd(re, re));
        let inv_norm = _mm512_div_pd(ones, norm);
        _mm512_storeu_pd(c.as_mut_ptr().add(i), _mm512_mul_pd(re, inv_norm));
        _mm512_storeu_pd(c.as_mut_ptr().add(i + hn),
            _mm512_castsi512_pd(_mm512_xor_si512(
                _mm512_castpd_si512(_mm512_mul_pd(im, inv_norm)),
                _mm512_castpd_si512(neg))));
        i += 8;
    }
    while i < hn {
        let (re, im) = (a[i], a[i + hn]);
        let norm = re * re + im * im;
        let inv_norm = 1.0 / norm;
        c[i]      = re * inv_norm;
        c[i + hn] = -(im * inv_norm);
        i += 1;
    }
}

/// c = |a|²
///
/// # Safety
/// Requires AVX-512F.
#[target_feature(enable = "avx512f")]
pub unsafe fn poly_norm_fft_avx512(c: &mut [f64], a: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let zero = _mm512_setzero_pd();
    let mut i = 0;
    while i + 8 <= hn {
        let re = _mm512_loadu_pd(a.as_ptr().add(i));
        let im = _mm512_loadu_pd(a.as_ptr().add(i + hn));
        let norm = _mm512_fmadd_pd(im, im, _mm512_mul_pd(re, re));
        _mm512_storeu_pd(c.as_mut_ptr().add(i), norm);
        _mm512_storeu_pd(c.as_mut_ptr().add(i + hn), zero);
        i += 8;
    }
    while i < hn {
        let (re, im) = (a[i], a[i + hn]);
        c[i]      = re * re + im * im;
        c[i + hn] = 0.0;
        i += 1;
    }
}

/// Split: decompose FFT(f) → FFT(f₀), FFT(f₁)
///
/// # Safety
/// Requires AVX-512F.
#[target_feature(enable = "avx512f")]
pub unsafe fn poly_split_fft_avx512(
    f0: &mut [f64], f1: &mut [f64], f: &[f64], logn: usize
) {
    if logn == 0 { return; }
    if logn == 1 {
        f0[0] = f[0];
        f1[0] = f[1];
        return;
    }

    let n = 1usize << logn;
    let hn = n >> 1;
    let qn = hn >> 1;
    ensure_twiddles(logn);

    let half = _mm512_set1_pd(0.5);
    let neg = _mm512_set1_pd(-0.0);
    let mut k = 0;

    while k + 8 <= qn {
        let a_re = _mm512_loadu_pd(f.as_ptr().add(k));
        let a_im = _mm512_loadu_pd(f.as_ptr().add(k + hn));

        // Reversed loads: load p_start..p_start+8, then reverse 8 lanes
        let p_start = hn - 8 - k;
        let tmp_re = _mm512_loadu_pd(f.as_ptr().add(p_start));
        let tmp_im = _mm512_loadu_pd(f.as_ptr().add(p_start + hn));

        // Reverse 8 lanes using permutexvar
        let rev_idx = _mm512_setr_epi64(7, 6, 5, 4, 3, 2, 1, 0);
        let b_re = _mm512_permutexvar_pd(rev_idx, tmp_re);
        let b_im_neg = _mm512_permutexvar_pd(rev_idx, tmp_im);
        // Negate for conjugate: b_im = -conj_im
        let b_im = _mm512_castsi512_pd(_mm512_xor_si512(
            _mm512_castpd_si512(b_im_neg), _mm512_castpd_si512(neg)));

        let f0_re = _mm512_mul_pd(_mm512_add_pd(a_re, b_re), half);
        let f0_im = _mm512_mul_pd(_mm512_add_pd(a_im, b_im), half);
        _mm512_storeu_pd(f0.as_mut_ptr().add(k), f0_re);
        _mm512_storeu_pd(f0.as_mut_ptr().add(k + qn), f0_im);

        let d_re = _mm512_mul_pd(_mm512_sub_pd(a_re, b_re), half);
        let d_im = _mm512_mul_pd(_mm512_sub_pd(a_im, b_im), half);

        let z_re = _mm512_loadu_pd(FFT_TW512[logn].cos.as_ptr().add(k));
        let z_im = _mm512_loadu_pd(FFT_TW512[logn].sin.as_ptr().add(k));

        // f1 = d / ω = d * conj(ω) = (d_re*z_re + d_im*z_im, d_im*z_re - d_re*z_im)
        let f1_re = _mm512_fmadd_pd(d_im, z_im, _mm512_mul_pd(d_re, z_re));
        let f1_im = _mm512_fmsub_pd(d_im, z_re, _mm512_mul_pd(d_re, z_im));

        _mm512_storeu_pd(f1.as_mut_ptr().add(k), f1_re);
        _mm512_storeu_pd(f1.as_mut_ptr().add(k + qn), f1_im);
        k += 8;
    }

    // Scalar tail
    while k < qn {
        let p = hn - 1 - k;
        let (a_re, a_im) = (f[k], f[k + hn]);
        let (b_re, b_im) = (f[p], -f[p + hn]);

        f0[k]      = (a_re + b_re) * 0.5;
        f0[k + qn] = (a_im + b_im) * 0.5;

        let d_re = (a_re - b_re) * 0.5;
        let d_im = (a_im - b_im) * 0.5;

        let zr = FFT_TW512[logn].cos[k];
        let zi = FFT_TW512[logn].sin[k];
        f1[k]      = d_re * zr + d_im * zi;
        f1[k + qn] = d_im * zr - d_re * zi;
        k += 1;
    }
}

/// Merge: inverse of split — reconstruct FFT(f) from f₀, f₁
///
/// # Safety
/// Requires AVX-512F.
#[target_feature(enable = "avx512f")]
pub unsafe fn poly_merge_fft_avx512(
    f: &mut [f64], f0: &[f64], f1: &[f64], logn: usize
) {
    if logn == 0 { return; }
    if logn == 1 {
        f[0] = f0[0];
        f[1] = f1[0];
        return;
    }

    let n = 1usize << logn;
    let hn = n >> 1;
    let qn = hn >> 1;
    ensure_twiddles(logn);

    let neg = _mm512_set1_pd(-0.0);
    let rev_idx = _mm512_setr_epi64(7, 6, 5, 4, 3, 2, 1, 0);
    let mut k = 0;

    while k + 8 <= qn {
        let e_re = _mm512_loadu_pd(f0.as_ptr().add(k));
        let e_im = _mm512_loadu_pd(f0.as_ptr().add(k + qn));
        let o_re = _mm512_loadu_pd(f1.as_ptr().add(k));
        let o_im = _mm512_loadu_pd(f1.as_ptr().add(k + qn));

        let z_re = _mm512_loadu_pd(FFT_TW512[logn].cos.as_ptr().add(k));
        let z_im = _mm512_loadu_pd(FFT_TW512[logn].sin.as_ptr().add(k));

        // w = ω * f1 = (o_re*z_re - o_im*z_im, o_re*z_im + o_im*z_re)
        let w_re = _mm512_fmsub_pd(o_re, z_re, _mm512_mul_pd(o_im, z_im));
        let w_im = _mm512_fmadd_pd(o_re, z_im, _mm512_mul_pd(o_im, z_re));

        // f(ω_k) = e + w
        _mm512_storeu_pd(f.as_mut_ptr().add(k), _mm512_add_pd(e_re, w_re));
        _mm512_storeu_pd(f.as_mut_ptr().add(k + hn), _mm512_add_pd(e_im, w_im));

        // f(ω_p) = conj(e - w), reversed for p = hn-1-k..hn-8-k
        let diff_re = _mm512_sub_pd(e_re, w_re);
        let diff_im_neg = _mm512_castsi512_pd(_mm512_xor_si512(
            _mm512_castpd_si512(_mm512_sub_pd(e_im, w_im)),
            _mm512_castpd_si512(neg)));

        let p_start = hn - 8 - k;
        let rev_re = _mm512_permutexvar_pd(rev_idx, diff_re);
        let rev_im = _mm512_permutexvar_pd(rev_idx, diff_im_neg);
        _mm512_storeu_pd(f.as_mut_ptr().add(p_start), rev_re);
        _mm512_storeu_pd(f.as_mut_ptr().add(p_start + hn), rev_im);
        k += 8;
    }

    // Scalar tail
    while k < qn {
        let p = hn - 1 - k;
        let (e_re, e_im) = (f0[k], f0[k + qn]);
        let (o_re, o_im) = (f1[k], f1[k + qn]);

        let zr = FFT_TW512[logn].cos[k];
        let zi = FFT_TW512[logn].sin[k];
        let w_re = o_re * zr - o_im * zi;
        let w_im = o_re * zi + o_im * zr;

        f[k]      = e_re + w_re;
        f[k + hn] = e_im + w_im;
        f[p]      = e_re - w_re;
        f[p + hn] = -(e_im - w_im);
        k += 1;
    }
}
