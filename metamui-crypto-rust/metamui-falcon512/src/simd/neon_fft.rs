// MetaMUI Falcon - ARM NEON Complex FFT Operations (f64)
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! ARM NEON-accelerated complex FFT domain operations.
//!
//! Processes 2 × f64 per `float64x2_t` register.
//! Uses FMA instructions (`vfmaq_f64`, `vfmsq_f64`) for complex multiply.
//!
//! Layout: `f[0..n/2-1]` = real parts, `f[n/2..n-1]` = imaginary parts.
//!
//! NEON is always available on AArch64 — no runtime detection needed.
//! All operations are constant-time (no data-dependent branches).

use core::arch::aarch64::*;
use core::f64::consts::PI;

// ================================================================
// Precomputed SOA twiddle tables for split/merge
// ================================================================

const MAX_LOGN: usize = 10;
const MAX_QN: usize = 1 << (MAX_LOGN - 2); // n/4 for max logn

struct FftTwiddles {
    cos: [f64; MAX_QN],
    sin: [f64; MAX_QN],
    ready: bool,
}

impl FftTwiddles {
    const fn zeroed() -> Self {
        Self { cos: [0.0; MAX_QN], sin: [0.0; MAX_QN], ready: false }
    }
}

static mut FFT_TW: [FftTwiddles; MAX_LOGN + 1] = [
    FftTwiddles::zeroed(), FftTwiddles::zeroed(), FftTwiddles::zeroed(),
    FftTwiddles::zeroed(), FftTwiddles::zeroed(), FftTwiddles::zeroed(),
    FftTwiddles::zeroed(), FftTwiddles::zeroed(), FftTwiddles::zeroed(),
    FftTwiddles::zeroed(), FftTwiddles::zeroed(),
];

fn ensure_twiddles(logn: usize) {
    if logn < 2 || logn > MAX_LOGN { return; }
    unsafe {
        if FFT_TW[logn].ready { return; }
        let n = 1usize << logn;
        let qn = n >> 2;
        let inv_n = PI / n as f64;
        for k in 0..qn {
            let angle = (2 * k + 1) as f64 * inv_n;
            FFT_TW[logn].cos[k] = angle.cos();
            FFT_TW[logn].sin[k] = angle.sin();
        }
        FFT_TW[logn].ready = true;
    }
}

// ================================================================
// NEON Pointwise Operations
// ================================================================

/// c = a + b (n elements, covers both real and imaginary halves)
///
/// # Safety
/// Requires AArch64 NEON.
pub unsafe fn poly_add_fft_neon(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let n = 1usize << logn;
    let mut i = 0;
    while i + 2 <= n {
        let va = vld1q_f64(a.as_ptr().add(i));
        let vb = vld1q_f64(b.as_ptr().add(i));
        vst1q_f64(c.as_mut_ptr().add(i), vaddq_f64(va, vb));
        i += 2;
    }
    while i < n { c[i] = a[i] + b[i]; i += 1; }
}

/// c = a - b
///
/// # Safety
/// Requires AArch64 NEON.
pub unsafe fn poly_sub_fft_neon(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let n = 1usize << logn;
    let mut i = 0;
    while i + 2 <= n {
        let va = vld1q_f64(a.as_ptr().add(i));
        let vb = vld1q_f64(b.as_ptr().add(i));
        vst1q_f64(c.as_mut_ptr().add(i), vsubq_f64(va, vb));
        i += 2;
    }
    while i < n { c[i] = a[i] - b[i]; i += 1; }
}

/// c = a * b (complex multiply with FMA)
///
/// # Safety
/// Requires AArch64 NEON.
pub unsafe fn poly_mul_fft_neon(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut i = 0;
    while i + 2 <= hn {
        let a_re = vld1q_f64(a.as_ptr().add(i));
        let a_im = vld1q_f64(a.as_ptr().add(i + hn));
        let b_re = vld1q_f64(b.as_ptr().add(i));
        let b_im = vld1q_f64(b.as_ptr().add(i + hn));

        // c_re = a_re*b_re - a_im*b_im
        let c_re = vfmsq_f64(vmulq_f64(a_re, b_re), a_im, b_im);
        // c_im = a_re*b_im + a_im*b_re
        let c_im = vfmaq_f64(vmulq_f64(a_re, b_im), a_im, b_re);

        vst1q_f64(c.as_mut_ptr().add(i), c_re);
        vst1q_f64(c.as_mut_ptr().add(i + hn), c_im);
        i += 2;
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
/// Requires AArch64 NEON.
pub unsafe fn poly_muladj_fft_neon(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut i = 0;
    while i + 2 <= hn {
        let a_re = vld1q_f64(a.as_ptr().add(i));
        let a_im = vld1q_f64(a.as_ptr().add(i + hn));
        let b_re = vld1q_f64(b.as_ptr().add(i));
        let b_im = vld1q_f64(b.as_ptr().add(i + hn));

        // c_re = a_re*b_re + a_im*b_im
        let c_re = vfmaq_f64(vmulq_f64(a_re, b_re), a_im, b_im);
        // c_im = a_im*b_re - a_re*b_im
        let c_im = vfmsq_f64(vmulq_f64(a_im, b_re), a_re, b_im);

        vst1q_f64(c.as_mut_ptr().add(i), c_re);
        vst1q_f64(c.as_mut_ptr().add(i + hn), c_im);
        i += 2;
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
/// Requires AArch64 NEON.
pub unsafe fn poly_muladd_fft_neon(c: &mut [f64], a: &[f64], b: &[f64], acc: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut i = 0;
    while i + 2 <= hn {
        let a_re = vld1q_f64(a.as_ptr().add(i));
        let a_im = vld1q_f64(a.as_ptr().add(i + hn));
        let b_re = vld1q_f64(b.as_ptr().add(i));
        let b_im = vld1q_f64(b.as_ptr().add(i + hn));
        let acc_re = vld1q_f64(acc.as_ptr().add(i));
        let acc_im = vld1q_f64(acc.as_ptr().add(i + hn));

        // mul_re = a_re*b_re - a_im*b_im
        let mul_re = vfmsq_f64(vmulq_f64(a_re, b_re), a_im, b_im);
        // mul_im = a_re*b_im + a_im*b_re
        let mul_im = vfmaq_f64(vmulq_f64(a_re, b_im), a_im, b_re);

        vst1q_f64(c.as_mut_ptr().add(i), vaddq_f64(acc_re, mul_re));
        vst1q_f64(c.as_mut_ptr().add(i + hn), vaddq_f64(acc_im, mul_im));
        i += 2;
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
/// Requires AArch64 NEON.
pub unsafe fn poly_mulsub_fft_neon(c: &mut [f64], a: &[f64], b: &[f64], acc: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut i = 0;
    while i + 2 <= hn {
        let a_re = vld1q_f64(a.as_ptr().add(i));
        let a_im = vld1q_f64(a.as_ptr().add(i + hn));
        let b_re = vld1q_f64(b.as_ptr().add(i));
        let b_im = vld1q_f64(b.as_ptr().add(i + hn));
        let acc_re = vld1q_f64(acc.as_ptr().add(i));
        let acc_im = vld1q_f64(acc.as_ptr().add(i + hn));

        let mul_re = vfmsq_f64(vmulq_f64(a_re, b_re), a_im, b_im);
        let mul_im = vfmaq_f64(vmulq_f64(a_re, b_im), a_im, b_re);

        vst1q_f64(c.as_mut_ptr().add(i), vsubq_f64(acc_re, mul_re));
        vst1q_f64(c.as_mut_ptr().add(i + hn), vsubq_f64(acc_im, mul_im));
        i += 2;
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
/// Requires AArch64 NEON.
pub unsafe fn poly_adj_fft_neon(c: &mut [f64], a: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let mut i = 0;
    // Copy real parts
    while i + 2 <= hn {
        vst1q_f64(c.as_mut_ptr().add(i), vld1q_f64(a.as_ptr().add(i)));
        i += 2;
    }
    while i < hn { c[i] = a[i]; i += 1; }
    // Negate imaginary parts
    i = 0;
    while i + 2 <= hn {
        vst1q_f64(c.as_mut_ptr().add(hn + i), vnegq_f64(vld1q_f64(a.as_ptr().add(hn + i))));
        i += 2;
    }
    while i < hn { c[hn + i] = -a[hn + i]; i += 1; }
}

/// c = 1/a (complex inverse)
///
/// # Safety
/// Requires AArch64 NEON.
pub unsafe fn poly_inv_fft_neon(c: &mut [f64], a: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let ones = vdupq_n_f64(1.0);
    let mut i = 0;
    while i + 2 <= hn {
        let re = vld1q_f64(a.as_ptr().add(i));
        let im = vld1q_f64(a.as_ptr().add(i + hn));
        let norm = vfmaq_f64(vmulq_f64(re, re), im, im);
        let inv_norm = vdivq_f64(ones, norm);
        vst1q_f64(c.as_mut_ptr().add(i), vmulq_f64(re, inv_norm));
        vst1q_f64(c.as_mut_ptr().add(i + hn), vnegq_f64(vmulq_f64(im, inv_norm)));
        i += 2;
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

/// c = |a|² (squared norm)
///
/// # Safety
/// Requires AArch64 NEON.
pub unsafe fn poly_norm_fft_neon(c: &mut [f64], a: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let zero = vdupq_n_f64(0.0);
    let mut i = 0;
    while i + 2 <= hn {
        let re = vld1q_f64(a.as_ptr().add(i));
        let im = vld1q_f64(a.as_ptr().add(i + hn));
        let norm = vfmaq_f64(vmulq_f64(re, re), im, im);
        vst1q_f64(c.as_mut_ptr().add(i), norm);
        vst1q_f64(c.as_mut_ptr().add(i + hn), zero);
        i += 2;
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
/// Requires AArch64 NEON.
pub unsafe fn poly_split_fft_neon(
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

    let half = vdupq_n_f64(0.5);
    let mut k = 0;

    while k + 2 <= qn {
        // Forward loads
        let a_re = vld1q_f64(f.as_ptr().add(k));
        let a_im = vld1q_f64(f.as_ptr().add(k + hn));

        // Reversed loads: p = hn-1-k, hn-2-k
        let p1 = hn - 2 - k;
        let tmp_re = vld1q_f64(f.as_ptr().add(p1));
        let tmp_im = vld1q_f64(f.as_ptr().add(p1 + hn));
        // Swap 2 lanes for reversed order
        let b_re = vextq_f64(tmp_re, tmp_re, 1);
        let b_im = vnegq_f64(vextq_f64(tmp_im, tmp_im, 1));

        // f₀ = (A + B) / 2
        let f0_re = vmulq_f64(vaddq_f64(a_re, b_re), half);
        let f0_im = vmulq_f64(vaddq_f64(a_im, b_im), half);
        vst1q_f64(f0.as_mut_ptr().add(k), f0_re);
        vst1q_f64(f0.as_mut_ptr().add(k + qn), f0_im);

        // d = (A - B) / 2
        let d_re = vmulq_f64(vsubq_f64(a_re, b_re), half);
        let d_im = vmulq_f64(vsubq_f64(a_im, b_im), half);

        // f₁ = d · conj(ω_k)
        let z_re = vld1q_f64(FFT_TW[logn].cos.as_ptr().add(k));
        let z_im = vld1q_f64(FFT_TW[logn].sin.as_ptr().add(k));
        let f1_re = vfmaq_f64(vmulq_f64(d_re, z_re), d_im, z_im);
        let f1_im = vfmsq_f64(vmulq_f64(d_im, z_re), d_re, z_im);

        vst1q_f64(f1.as_mut_ptr().add(k), f1_re);
        vst1q_f64(f1.as_mut_ptr().add(k + qn), f1_im);
        k += 2;
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

        let zr = FFT_TW[logn].cos[k];
        let zi = FFT_TW[logn].sin[k];
        f1[k]      = d_re * zr + d_im * zi;
        f1[k + qn] = d_im * zr - d_re * zi;
        k += 1;
    }
}

/// Merge: inverse of split
///
/// # Safety
/// Requires AArch64 NEON.
pub unsafe fn poly_merge_fft_neon(
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

    let mut k = 0;

    while k + 2 <= qn {
        let e_re = vld1q_f64(f0.as_ptr().add(k));
        let e_im = vld1q_f64(f0.as_ptr().add(k + qn));
        let o_re = vld1q_f64(f1.as_ptr().add(k));
        let o_im = vld1q_f64(f1.as_ptr().add(k + qn));

        let z_re = vld1q_f64(FFT_TW[logn].cos.as_ptr().add(k));
        let z_im = vld1q_f64(FFT_TW[logn].sin.as_ptr().add(k));

        // w = ω_k · o
        let w_re = vfmsq_f64(vmulq_f64(o_re, z_re), o_im, z_im);
        let w_im = vfmaq_f64(vmulq_f64(o_re, z_im), o_im, z_re);

        // f(ω_k) = e + w
        vst1q_f64(f.as_mut_ptr().add(k), vaddq_f64(e_re, w_re));
        vst1q_f64(f.as_mut_ptr().add(k + hn), vaddq_f64(e_im, w_im));

        // f(ω_p) = conj(e - w) — reversed stores
        let diff_re = vsubq_f64(e_re, w_re);
        let diff_im = vnegq_f64(vsubq_f64(e_im, w_im));
        let p1 = hn - 2 - k;
        let rev_re = vextq_f64(diff_re, diff_re, 1);
        let rev_im = vextq_f64(diff_im, diff_im, 1);
        vst1q_f64(f.as_mut_ptr().add(p1), rev_re);
        vst1q_f64(f.as_mut_ptr().add(p1 + hn), rev_im);
        k += 2;
    }

    // Scalar tail
    while k < qn {
        let p = hn - 1 - k;
        let (e_re, e_im) = (f0[k], f0[k + qn]);
        let (o_re, o_im) = (f1[k], f1[k + qn]);

        let zr = FFT_TW[logn].cos[k];
        let zi = FFT_TW[logn].sin[k];
        let w_re = o_re * zr - o_im * zi;
        let w_im = o_re * zi + o_im * zr;

        f[k]      = e_re + w_re;
        f[k + hn] = e_im + w_im;
        f[p]      = e_re - w_re;
        f[p + hn] = -(e_im - w_im);
        k += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::portable_fft;

    fn rand_f64(seed: &mut u32) -> f64 {
        *seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        ((*seed >> 8) as f64 / 16777216.0) * 200.0 - 100.0
    }

    fn close(a: f64, b: f64, tol: f64) -> bool {
        let diff = (a - b).abs();
        let denom = a.abs() + b.abs() + 1e-30;
        diff / denom < tol
    }

    fn assert_vecs_close(name: &str, a: &[f64], b: &[f64], tol: f64) {
        for i in 0..a.len() {
            assert!(close(a[i], b[i], tol),
                "{name} mismatch at [{i}]: scalar={}, neon={}", a[i], b[i]);
        }
    }

    #[test]
    fn test_neon_add_sub_vs_scalar() {
        for trial in 0..50u32 {
            let mut seed = 200 + trial;
            let logn = 9;
            let n = 1usize << logn;
            let a: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
            let b: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
            let mut c_ref = vec![0.0; n];
            let mut c_neon = vec![0.0; n];

            portable_fft::poly_add_fft(&mut c_ref, &a, &b, logn);
            unsafe { poly_add_fft_neon(&mut c_neon, &a, &b, logn); }
            assert_vecs_close("add", &c_ref, &c_neon, 1e-14);

            portable_fft::poly_sub_fft(&mut c_ref, &a, &b, logn);
            unsafe { poly_sub_fft_neon(&mut c_neon, &a, &b, logn); }
            assert_vecs_close("sub", &c_ref, &c_neon, 1e-14);
        }
    }

    #[test]
    fn test_neon_mul_vs_scalar() {
        for trial in 0..50u32 {
            let mut seed = 300 + trial;
            let logn = 9;
            let n = 1usize << logn;
            let a: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
            let b: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
            let mut c_ref = vec![0.0; n];
            let mut c_neon = vec![0.0; n];

            portable_fft::poly_mul_fft(&mut c_ref, &a, &b, logn);
            unsafe { poly_mul_fft_neon(&mut c_neon, &a, &b, logn); }
            assert_vecs_close("mul", &c_ref, &c_neon, 1e-12);
        }
    }

    #[test]
    fn test_neon_muladj_vs_scalar() {
        for trial in 0..50u32 {
            let mut seed = 400 + trial;
            let logn = 9;
            let n = 1usize << logn;
            let a: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
            let b: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
            let mut c_ref = vec![0.0; n];
            let mut c_neon = vec![0.0; n];

            portable_fft::poly_muladj_fft(&mut c_ref, &a, &b, logn);
            unsafe { poly_muladj_fft_neon(&mut c_neon, &a, &b, logn); }
            assert_vecs_close("muladj", &c_ref, &c_neon, 1e-12);
        }
    }

    #[test]
    fn test_neon_adj_norm_inv_vs_scalar() {
        for trial in 0..20u32 {
            let mut seed = 500 + trial;
            let logn = 9;
            let n = 1usize << logn;
            let hn = n >> 1;
            let mut a: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
            for i in 0..hn {
                if a[i].abs() < 1.0 { a[i] += 10.0; }
                if a[i + hn].abs() < 1.0 { a[i + hn] += 10.0; }
            }

            let mut c_ref = vec![0.0; n];
            let mut c_neon = vec![0.0; n];

            // adj
            portable_fft::poly_adj_fft(&mut c_ref, &a, logn);
            unsafe { poly_adj_fft_neon(&mut c_neon, &a, logn); }
            assert_vecs_close("adj", &c_ref, &c_neon, 1e-14);

            // norm
            portable_fft::poly_norm_fft(&mut c_ref, &a, logn);
            unsafe { poly_norm_fft_neon(&mut c_neon, &a, logn); }
            assert_vecs_close("norm", &c_ref, &c_neon, 1e-12);

            // inv
            portable_fft::poly_inv_fft(&mut c_ref, &a, logn);
            unsafe { poly_inv_fft_neon(&mut c_neon, &a, logn); }
            assert_vecs_close("inv", &c_ref, &c_neon, 1e-10);
        }
    }

    #[test]
    fn test_neon_split_merge_vs_scalar() {
        for logn in [2, 3, 5, 7, 9, 10] {
            for trial in 0..20u32 {
                let mut seed = 600 + trial + logn as u32 * 100;
                let n = 1usize << logn;
                let hn = n >> 1;
                let f: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();

                let mut f0_ref = vec![0.0; hn];
                let mut f1_ref = vec![0.0; hn];
                let mut f0_neon = vec![0.0; hn];
                let mut f1_neon = vec![0.0; hn];

                portable_fft::poly_split_fft(&mut f0_ref, &mut f1_ref, &f, logn);
                unsafe { poly_split_fft_neon(&mut f0_neon, &mut f1_neon, &f, logn); }

                assert_vecs_close(&format!("split f0 logn={logn}"), &f0_ref, &f0_neon, 1e-12);
                assert_vecs_close(&format!("split f1 logn={logn}"), &f1_ref, &f1_neon, 1e-12);

                // Merge roundtrip
                let mut merged = vec![0.0; n];
                unsafe { poly_merge_fft_neon(&mut merged, &f0_neon, &f1_neon, logn); }
                assert_vecs_close(&format!("merge roundtrip logn={logn}"), &f, &merged, 1e-10);
            }
        }
    }
}
