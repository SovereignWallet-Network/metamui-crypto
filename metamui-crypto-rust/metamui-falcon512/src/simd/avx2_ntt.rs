// MetaMUI Falcon - AVX2 NTT Butterfly
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! AVX2-accelerated NTT operations for Falcon.
//!
//! Processes 16 × u16 coefficients per `__m256i` register using:
//! - Montgomery multiply: `_mm256_mullo_epi16` + `_mm256_mulhi_epu16` (no widening needed)
//! - Cooley-Tukey DIF/DIT butterfly with constant-time modular arithmetic
//! - Branchless addmod/submod via `_mm256_srai_epi16` sign mask
//!
//! ## SIMD Coverage (Falcon-512, logn=9)
//!
//! - Layers 9→5 (half 256→16): AVX2 — 5/9 layers vectorized
//! - Layers 4→1 (half 8→1): scalar fallback — 4/9 layers
//! - Pre/post-twist: fully vectorized (contiguous loads)
//!
//! ## Safety
//!
//! All functions require x86_64 + AVX2. Use `is_x86_feature_detected!("avx2")`
//! before calling. Functions are gated with `#[target_feature(enable = "avx2")]`.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;

use super::montgomery::{MONT_Q, MONT_QINV, mont_mul};
use super::tables;

const Q: u16 = MONT_Q;

// ================================================================
// AVX2 Montgomery Multiply (16 lanes)
// ================================================================

/// AVX2 Montgomery multiply: 16 × (a * b_mont * R^(-1) mod q).
///
/// # Safety
/// Requires AVX2.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn avx2_mont_mul(a: __m256i, b_mont: __m256i) -> __m256i {
    let q_vec = _mm256_set1_epi16(Q as i16);
    let qinv_vec = _mm256_set1_epi16(MONT_QINV as i16);

    // Product split into low and high 16 bits
    let prod_lo = _mm256_mullo_epi16(a, b_mont);
    let prod_hi = _mm256_mulhi_epu16(a, b_mont);

    // Montgomery reduction: m = prod_lo * QINV mod R
    let m = _mm256_mullo_epi16(prod_lo, qinv_vec);
    let mq_hi = _mm256_mulhi_epu16(m, q_vec);

    // result = prod_hi - mq_hi (may be negative)
    let result = _mm256_sub_epi16(prod_hi, mq_hi);

    // Normalize: if negative, add q
    let mask = _mm256_srai_epi16(result, 15);
    let correction = _mm256_and_si256(mask, q_vec);
    _mm256_add_epi16(result, correction)
}

/// (a + b) mod q, 16 lanes.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn avx2_addmod(a: __m256i, b: __m256i) -> __m256i {
    let q_vec = _mm256_set1_epi16(Q as i16);
    let sum = _mm256_add_epi16(a, b);
    let reduced = _mm256_sub_epi16(sum, q_vec);
    let mask = _mm256_srai_epi16(reduced, 15);
    _mm256_blendv_epi8(reduced, sum, mask)
}

/// (a - b) mod q, 16 lanes.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn avx2_submod(a: __m256i, b: __m256i) -> __m256i {
    let q_vec = _mm256_set1_epi16(Q as i16);
    let diff = _mm256_sub_epi16(a, b);
    let mask = _mm256_srai_epi16(diff, 15);
    let correction = _mm256_and_si256(mask, q_vec);
    _mm256_add_epi16(diff, correction)
}

// ================================================================
// Scalar helpers for inner layers
// ================================================================

#[inline(always)]
fn scalar_addmod(a: u16, b: u16) -> u16 {
    let s = a as u32 + b as u32;
    if s >= Q as u32 { (s - Q as u32) as u16 } else { s as u16 }
}

#[inline(always)]
fn scalar_submod(a: u16, b: u16) -> u16 {
    if a >= b { a - b } else { a + Q - b }
}

// ================================================================
// Strided gather for twiddle factors (16 lanes)
// ================================================================

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn avx2_gather_u16(base: *const u16, stride: usize) -> __m256i {
    _mm256_setr_epi16(
        *base as i16,
        *base.add(stride) as i16,
        *base.add(2 * stride) as i16,
        *base.add(3 * stride) as i16,
        *base.add(4 * stride) as i16,
        *base.add(5 * stride) as i16,
        *base.add(6 * stride) as i16,
        *base.add(7 * stride) as i16,
        *base.add(8 * stride) as i16,
        *base.add(9 * stride) as i16,
        *base.add(10 * stride) as i16,
        *base.add(11 * stride) as i16,
        *base.add(12 * stride) as i16,
        *base.add(13 * stride) as i16,
        *base.add(14 * stride) as i16,
        *base.add(15 * stride) as i16,
    )
}

// ================================================================
// AVX2 NTT Forward (Negacyclic, In-Place)
// ================================================================

/// AVX2-accelerated forward negacyclic NTT.
///
/// # Safety
/// Requires AVX2. `f` must have length `2^logn`.
#[target_feature(enable = "avx2")]
pub unsafe fn ntt_forward_avx2(f: &mut [u16], logn: usize) {
    let n = 1usize << logn;
    debug_assert_eq!(f.len(), n);
    tables::ensure_tables(logn);
    let psi_mont = tables::psi_pow_mont(logn);

    // Step 1: Pre-twist (contiguous, 16 lanes at a time)
    let mut i = 0;
    while i + 16 <= n {
        let vf = _mm256_loadu_si256(f.as_ptr().add(i) as *const __m256i);
        let vw = _mm256_loadu_si256(psi_mont.as_ptr().add(i) as *const __m256i);
        _mm256_storeu_si256(
            f.as_mut_ptr().add(i) as *mut __m256i,
            avx2_mont_mul(vf, vw),
        );
        i += 16;
    }
    while i < n {
        f[i] = mont_mul(f[i], psi_mont[i]);
        i += 1;
    }

    // Step 2: DIF butterfly
    let mut layer = logn;
    while layer >= 1 {
        let half = 1usize << (layer - 1);
        let groups = n >> layer;
        let stride = 2 * groups;

        if half >= 16 {
            for g in 0..groups {
                let base = g * (2 * half);
                let mut j = 0;
                while j < half {
                    let vu = _mm256_loadu_si256(
                        f.as_ptr().add(base + j) as *const __m256i);
                    let vv = _mm256_loadu_si256(
                        f.as_ptr().add(base + j + half) as *const __m256i);
                    let vw = avx2_gather_u16(
                        psi_mont.as_ptr().add(j * stride), stride);

                    let sum = avx2_addmod(vu, vv);
                    let diff = avx2_submod(vu, vv);
                    let tw = avx2_mont_mul(diff, vw);

                    _mm256_storeu_si256(
                        f.as_mut_ptr().add(base + j) as *mut __m256i, sum);
                    _mm256_storeu_si256(
                        f.as_mut_ptr().add(base + j + half) as *mut __m256i, tw);
                    j += 16;
                }
            }
        } else {
            for g in 0..groups {
                let base = g * (2 * half);
                for j in 0..half {
                    let w_mont = psi_mont[j * stride];
                    let u = f[base + j];
                    let v = f[base + j + half];
                    f[base + j] = scalar_addmod(u, v);
                    let d = scalar_submod(u, v);
                    f[base + j + half] = mont_mul(d, w_mont);
                }
            }
        }
        layer -= 1;
    }
}

// ================================================================
// AVX2 NTT Inverse (Negacyclic, In-Place)
// ================================================================

/// AVX2-accelerated inverse negacyclic NTT.
///
/// # Safety
/// Requires AVX2. `f` must have length `2^logn`.
#[target_feature(enable = "avx2")]
pub unsafe fn ntt_inverse_avx2(f: &mut [u16], logn: usize) {
    let n = 1usize << logn;
    debug_assert_eq!(f.len(), n);
    tables::ensure_tables(logn);
    let psi_inv_mont = tables::psi_inv_mont(logn);
    let n_inv = tables::n_inv_mont(logn);

    // Step 1: DIT butterfly
    for layer in 1..=logn {
        let half = 1usize << (layer - 1);
        let groups = n >> layer;
        let stride = 2 * groups;

        if half >= 16 {
            for g in 0..groups {
                let base = g * (2 * half);
                let mut j = 0;
                while j < half {
                    let vw = avx2_gather_u16(
                        psi_inv_mont.as_ptr().add(j * stride), stride);
                    let vv = _mm256_loadu_si256(
                        f.as_ptr().add(base + j + half) as *const __m256i);
                    let vt = avx2_mont_mul(vv, vw);
                    let vu = _mm256_loadu_si256(
                        f.as_ptr().add(base + j) as *const __m256i);

                    _mm256_storeu_si256(
                        f.as_mut_ptr().add(base + j) as *mut __m256i,
                        avx2_addmod(vu, vt));
                    _mm256_storeu_si256(
                        f.as_mut_ptr().add(base + j + half) as *mut __m256i,
                        avx2_submod(vu, vt));
                    j += 16;
                }
            }
        } else {
            for g in 0..groups {
                let base = g * (2 * half);
                for j in 0..half {
                    let w_inv = psi_inv_mont[j * stride];
                    let t = mont_mul(f[base + j + half], w_inv);
                    let u = f[base + j];
                    f[base + j] = scalar_addmod(u, t);
                    f[base + j + half] = scalar_submod(u, t);
                }
            }
        }
    }

    // Step 2: Scale + un-twist (fused, 16 lanes at a time)
    let vn_inv = _mm256_set1_epi16(n_inv as i16);
    let mut i = 0;
    while i + 16 <= n {
        let mut vf = _mm256_loadu_si256(f.as_ptr().add(i) as *const __m256i);
        vf = avx2_mont_mul(vf, vn_inv);
        let vw = _mm256_loadu_si256(psi_inv_mont.as_ptr().add(i) as *const __m256i);
        vf = avx2_mont_mul(vf, vw);
        _mm256_storeu_si256(f.as_mut_ptr().add(i) as *mut __m256i, vf);
        i += 16;
    }
    while i < n {
        f[i] = mont_mul(f[i], n_inv);
        f[i] = mont_mul(f[i], psi_inv_mont[i]);
        i += 1;
    }
}

/// AVX2 polynomial addition: c[i] = (a[i] + b[i]) mod q.
///
/// # Safety
/// Requires AVX2.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_add_avx2(c: &mut [u16], a: &[u16], b: &[u16]) {
    let n = a.len();
    let mut i = 0;
    while i + 16 <= n {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
        _mm256_storeu_si256(
            c.as_mut_ptr().add(i) as *mut __m256i,
            avx2_addmod(va, vb));
        i += 16;
    }
    while i < n {
        c[i] = scalar_addmod(a[i], b[i]);
        i += 1;
    }
}

/// AVX2 polynomial subtraction: c[i] = (a[i] - b[i]) mod q.
///
/// # Safety
/// Requires AVX2.
#[target_feature(enable = "avx2")]
pub unsafe fn poly_sub_avx2(c: &mut [u16], a: &[u16], b: &[u16]) {
    let n = a.len();
    let mut i = 0;
    while i + 16 <= n {
        let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
        let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
        _mm256_storeu_si256(
            c.as_mut_ptr().add(i) as *mut __m256i,
            avx2_submod(va, vb));
        i += 16;
    }
    while i < n {
        c[i] = scalar_submod(a[i], b[i]);
        i += 1;
    }
}
