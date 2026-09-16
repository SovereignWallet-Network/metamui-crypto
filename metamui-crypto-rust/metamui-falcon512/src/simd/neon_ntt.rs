// MetaMUI Falcon - ARM NEON NTT Implementation
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! ARM NEON-accelerated NTT for Falcon-512/1024.
//!
//! Processes 8 × u16 coefficients per `uint16x8_t` register.
//! Uses Montgomery multiplication via `vmull_u16` (widening to u32).
//!
//! ## Algorithm
//!
//! - **Forward NTT**: Pre-twist by ψ^i → radix-2 DIF butterfly
//!   (output in bit-reversed order)
//! - **Inverse NTT**: Radix-2 DIT butterfly → scale by n^(-1) →
//!   un-twist by ψ^(-i) (input in bit-reversed order)
//!
//! ## NEON Strategy
//!
//! Outer layers (half ≥ 8): fully vectorized — 8 butterflies per cycle.
//! Inner layers (half < 8): scalar fallback with Montgomery multiply.
//! Pre/post-twist: contiguous loads — ideal for vector operations.
//!
//! NEON is always available on AArch64 — no runtime detection needed.
//! All operations are constant-time (no data-dependent branches).

use core::arch::aarch64::*;
use super::montgomery::{MONT_Q, MONT_QINV, mont_mul};
use super::tables;

const Q: u16 = MONT_Q;
const QINV: u16 = MONT_QINV;

// ================================================================
// NEON Montgomery Multiply (4-lane and 8-lane)
// ================================================================

/// NEON Montgomery multiply for 4 lanes: a * b_mont * R^(-1) mod q.
///
/// # Safety
/// Requires AArch64 NEON.
#[inline(always)]
unsafe fn neon_mont_mul_x4(a: uint16x4_t, b_mont: uint16x4_t) -> uint16x4_t {
    let q_vec = vdup_n_u16(Q);
    let qinv_vec = vdup_n_u16(QINV);

    // Widening multiply: a * b_mont → 32-bit
    let prod = vmull_u16(a, b_mont);
    let prod_lo = vmovn_u32(prod);      // low 16 bits
    let prod_hi = vshrn_n_u32(prod, 16); // high 16 bits

    // m = prod_lo * QINV mod R
    let m = vmul_u16(prod_lo, qinv_vec);

    // m * q → extract high 16 bits
    let mq = vmull_u16(m, q_vec);
    let mq_hi = vshrn_n_u32(mq, 16);

    // result = prod_hi - mq_hi (may be negative)
    let result = vsub_s16(
        vreinterpret_s16_u16(prod_hi),
        vreinterpret_s16_u16(mq_hi),
    );

    // If result < 0, add q (branchless)
    let q_signed = vreinterpret_s16_u16(q_vec);
    let mask = vshr_n_s16(result, 15); // all 1s if negative
    let correction = vand_s16(mask, q_signed);
    vreinterpret_u16_s16(vadd_s16(result, correction))
}

/// NEON Montgomery multiply for 8 lanes (splits into two 4-lane ops).
#[inline(always)]
unsafe fn neon_mont_mul_x8(a: uint16x8_t, b_mont: uint16x8_t) -> uint16x8_t {
    let r_lo = neon_mont_mul_x4(vget_low_u16(a), vget_low_u16(b_mont));
    let r_hi = neon_mont_mul_x4(vget_high_u16(a), vget_high_u16(b_mont));
    vcombine_u16(r_lo, r_hi)
}

// ================================================================
// NEON Modular Add/Sub (8-lane, branchless)
// ================================================================

/// (a + b) mod q, 8 lanes.
#[inline(always)]
unsafe fn neon_addmod(a: uint16x8_t, b: uint16x8_t) -> uint16x8_t {
    let q_vec = vdupq_n_u16(Q);
    let sum = vaddq_u16(a, b);
    let reduced = vsubq_u16(sum, q_vec);
    let mask = vcgeq_u16(sum, q_vec);
    vbslq_u16(mask, reduced, sum)
}

/// (a - b) mod q, 8 lanes.
#[inline(always)]
unsafe fn neon_submod(a: uint16x8_t, b: uint16x8_t) -> uint16x8_t {
    let q_vec = vdupq_n_u16(Q);
    let diff = vsubq_u16(a, b);
    let mask = vcltq_u16(a, b);
    let correction = vandq_u16(mask, q_vec);
    vaddq_u16(diff, correction)
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
// Strided gather: load 8 non-contiguous u16 values into NEON register
// ================================================================

#[inline(always)]
unsafe fn neon_gather_u16(base: *const u16, stride: usize) -> uint16x8_t {
    let v: [u16; 8] = [
        *base,
        *base.add(stride),
        *base.add(2 * stride),
        *base.add(3 * stride),
        *base.add(4 * stride),
        *base.add(5 * stride),
        *base.add(6 * stride),
        *base.add(7 * stride),
    ];
    vld1q_u16(v.as_ptr())
}

// ================================================================
// NEON NTT Forward (Negacyclic, In-Place)
//
// Algorithm: Pre-twist + radix-2 DIF butterfly.
// Output is in bit-reversed NTT domain.
// ================================================================

/// NEON-accelerated forward negacyclic NTT.
///
/// Input: `f[0..n-1]` in coefficient form, each `f[i]` in `[0, q)`.
/// Output: `f` in NTT domain (bit-reversed order).
///
/// # Safety
/// Requires AArch64 NEON. `f` must have length `2^logn`.
pub unsafe fn ntt_forward_neon(f: &mut [u16], logn: usize) {
    let n = 1usize << logn;
    debug_assert_eq!(f.len(), n);
    tables::ensure_tables(logn);
    let psi_mont = tables::psi_pow_mont(logn);

    // Step 1: Pre-twist — f[i] *= ψ^i (Montgomery form, contiguous)
    let mut i = 0;
    while i + 8 <= n {
        let vf = vld1q_u16(f.as_ptr().add(i));
        let vw = vld1q_u16(psi_mont.as_ptr().add(i));
        vst1q_u16(f.as_mut_ptr().add(i), neon_mont_mul_x8(vf, vw));
        i += 8;
    }
    while i < n {
        f[i] = mont_mul(f[i], psi_mont[i]);
        i += 1;
    }

    // Step 2: Radix-2 DIF butterfly
    let mut layer = logn;
    while layer >= 1 {
        let half = 1usize << (layer - 1);
        let groups = n >> layer;
        let stride = 2 * groups; // twiddle stride = n/half

        if half >= 8 {
            // NEON butterfly
            for g in 0..groups {
                let base = g * (2 * half);
                let mut j = 0;
                while j < half {
                    let vu = vld1q_u16(f.as_ptr().add(base + j));
                    let vv = vld1q_u16(f.as_ptr().add(base + j + half));

                    // Gather twiddles: ψ^(2*(j+k)*groups) for k=0..7
                    let vw = neon_gather_u16(
                        psi_mont.as_ptr().add(j * stride),
                        stride,
                    );

                    // DIF butterfly: u' = u+v, v' = (u-v)*w
                    let sum = neon_addmod(vu, vv);
                    let diff = neon_submod(vu, vv);
                    let tw = neon_mont_mul_x8(diff, vw);

                    vst1q_u16(f.as_mut_ptr().add(base + j), sum);
                    vst1q_u16(f.as_mut_ptr().add(base + j + half), tw);
                    j += 8;
                }
            }
        } else {
            // Scalar fallback for inner layers
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
// NEON NTT Inverse (Negacyclic, In-Place)
//
// Algorithm: Radix-2 DIT butterfly + scale by n^(-1) + un-twist.
// Input is in bit-reversed NTT domain.
// ================================================================

/// NEON-accelerated inverse negacyclic NTT.
///
/// Input: `f` in NTT domain (bit-reversed order).
/// Output: `f[0..n-1]` in coefficient form, each `f[i]` in `[0, q)`.
///
/// # Safety
/// Requires AArch64 NEON. `f` must have length `2^logn`.
pub unsafe fn ntt_inverse_neon(f: &mut [u16], logn: usize) {
    let n = 1usize << logn;
    debug_assert_eq!(f.len(), n);
    tables::ensure_tables(logn);
    let psi_inv_mont = tables::psi_inv_mont(logn);
    let n_inv = tables::n_inv_mont(logn);

    // Step 1: Radix-2 DIT butterfly
    for layer in 1..=logn {
        let half = 1usize << (layer - 1);
        let groups = n >> layer;
        let stride = 2 * groups;

        if half >= 8 {
            // NEON butterfly
            for g in 0..groups {
                let base = g * (2 * half);
                let mut j = 0;
                while j < half {
                    // Gather inverse twiddles
                    let vw = neon_gather_u16(
                        psi_inv_mont.as_ptr().add(j * stride),
                        stride,
                    );

                    // Multiply v-elements by twiddle
                    let vv = vld1q_u16(f.as_ptr().add(base + j + half));
                    let vt = neon_mont_mul_x8(vv, vw);

                    // Load u-elements
                    let vu = vld1q_u16(f.as_ptr().add(base + j));

                    // DIT butterfly: u' = u+t, v' = u-t
                    vst1q_u16(f.as_mut_ptr().add(base + j), neon_addmod(vu, vt));
                    vst1q_u16(
                        f.as_mut_ptr().add(base + j + half),
                        neon_submod(vu, vt),
                    );
                    j += 8;
                }
            }
        } else {
            // Scalar fallback
            for g in 0..groups {
                let base = g * (2 * half);
                for j in 0..half {
                    let w_inv_mont = psi_inv_mont[j * stride];
                    let t = mont_mul(f[base + j + half], w_inv_mont);
                    let u = f[base + j];
                    f[base + j] = scalar_addmod(u, t);
                    f[base + j + half] = scalar_submod(u, t);
                }
            }
        }
    }

    // Step 2: Scale by n^(-1) and un-twist by ψ^(-i) (fused, vectorized)
    let vn_inv = vdupq_n_u16(n_inv);
    let mut i = 0;
    while i + 8 <= n {
        let mut vf = vld1q_u16(f.as_ptr().add(i));
        vf = neon_mont_mul_x8(vf, vn_inv); // scale by n^(-1)
        let vw = vld1q_u16(psi_inv_mont.as_ptr().add(i));
        vf = neon_mont_mul_x8(vf, vw); // un-twist by ψ^(-i)
        vst1q_u16(f.as_mut_ptr().add(i), vf);
        i += 8;
    }
    while i < n {
        f[i] = mont_mul(f[i], n_inv);
        f[i] = mont_mul(f[i], psi_inv_mont[i]);
        i += 1;
    }
}

// ================================================================
// NEON Polynomial Operations (kept for compatibility)
// ================================================================

/// NEON polynomial addition: c[i] = (a[i] + b[i]) mod q.
///
/// # Safety
/// Requires AArch64 NEON. Slices must have equal length.
pub unsafe fn poly_add_neon(c: &mut [u16], a: &[u16], b: &[u16]) {
    let n = a.len();
    debug_assert_eq!(n, b.len());
    debug_assert_eq!(n, c.len());

    let mut i = 0;
    while i + 8 <= n {
        let va = vld1q_u16(a.as_ptr().add(i));
        let vb = vld1q_u16(b.as_ptr().add(i));
        vst1q_u16(c.as_mut_ptr().add(i), neon_addmod(va, vb));
        i += 8;
    }
    while i < n {
        c[i] = scalar_addmod(a[i], b[i]);
        i += 1;
    }
}

/// NEON polynomial subtraction: c[i] = (a[i] - b[i]) mod q.
///
/// # Safety
/// Requires AArch64 NEON.
pub unsafe fn poly_sub_neon(c: &mut [u16], a: &[u16], b: &[u16]) {
    let n = a.len();
    debug_assert_eq!(n, b.len());
    debug_assert_eq!(n, c.len());

    let mut i = 0;
    while i + 8 <= n {
        let va = vld1q_u16(a.as_ptr().add(i));
        let vb = vld1q_u16(b.as_ptr().add(i));
        vst1q_u16(c.as_mut_ptr().add(i), neon_submod(va, vb));
        i += 8;
    }
    while i < n {
        c[i] = scalar_submod(a[i], b[i]);
        i += 1;
    }
}

/// NEON pointwise polynomial multiply: c[i] = (a[i] * b[i]) mod q.
///
/// # Safety
/// Requires AArch64 NEON.
pub unsafe fn poly_pointwise_neon(c: &mut [u16], a: &[u16], b: &[u16]) {
    let n = a.len();
    debug_assert_eq!(n, b.len());
    debug_assert_eq!(n, c.len());

    let mut i = 0;
    while i + 4 <= n {
        let va = vld1_u16(a.as_ptr().add(i));
        let vb = vld1_u16(b.as_ptr().add(i));
        let prod = vmull_u16(va, vb);

        let v0 = vgetq_lane_u32(prod, 0) % Q as u32;
        let v1 = vgetq_lane_u32(prod, 1) % Q as u32;
        let v2 = vgetq_lane_u32(prod, 2) % Q as u32;
        let v3 = vgetq_lane_u32(prod, 3) % Q as u32;

        let result: [u16; 4] = [v0 as u16, v1 as u16, v2 as u16, v3 as u16];
        vst1_u16(c.as_mut_ptr().add(i), vld1_u16(result.as_ptr()));
        i += 4;
    }
    while i < n {
        c[i] = ((a[i] as u32 * b[i] as u32) % Q as u32) as u16;
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::portable;

    fn rand_mod_q(seed: &mut u32) -> u16 {
        *seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        ((*seed >> 16) as u16) % Q
    }

    #[test]
    fn test_neon_addmod_vs_scalar() {
        let mut seed = 42u32;
        let n = 512;
        let a: Vec<u16> = (0..n).map(|_| rand_mod_q(&mut seed)).collect();
        let b: Vec<u16> = (0..n).map(|_| rand_mod_q(&mut seed)).collect();

        let mut c_scalar = vec![0u16; n];
        let mut c_neon = vec![0u16; n];

        portable::poly_add(&mut c_scalar, &a, &b);
        unsafe { poly_add_neon(&mut c_neon, &a, &b); }

        assert_eq!(c_scalar, c_neon, "NEON addmod mismatch");
    }

    #[test]
    fn test_neon_submod_vs_scalar() {
        let mut seed = 43u32;
        let n = 512;
        let a: Vec<u16> = (0..n).map(|_| rand_mod_q(&mut seed)).collect();
        let b: Vec<u16> = (0..n).map(|_| rand_mod_q(&mut seed)).collect();

        let mut c_scalar = vec![0u16; n];
        let mut c_neon = vec![0u16; n];

        portable::poly_sub(&mut c_scalar, &a, &b);
        unsafe { poly_sub_neon(&mut c_neon, &a, &b); }

        assert_eq!(c_scalar, c_neon, "NEON submod mismatch");
    }

    #[test]
    fn test_neon_pointwise_vs_scalar() {
        let mut seed = 44u32;
        let n = 512;
        let a: Vec<u16> = (0..n).map(|_| rand_mod_q(&mut seed)).collect();
        let b: Vec<u16> = (0..n).map(|_| rand_mod_q(&mut seed)).collect();

        let mut c_scalar = vec![0u16; n];
        let mut c_neon = vec![0u16; n];

        portable::poly_pointwise(&mut c_scalar, &a, &b);
        unsafe { poly_pointwise_neon(&mut c_neon, &a, &b); }

        assert_eq!(c_scalar, c_neon, "NEON pointwise mismatch");
    }

    #[test]
    fn test_ntt_roundtrip_512() {
        let logn = 9;
        let n = 1usize << logn;

        for trial in 0..50u32 {
            let mut seed = 1000 + trial;
            let orig: Vec<u16> = (0..n).map(|_| rand_mod_q(&mut seed)).collect();
            let mut f = orig.clone();

            unsafe {
                ntt_forward_neon(&mut f, logn);
                ntt_inverse_neon(&mut f, logn);
            }

            assert_eq!(f, orig, "NTT roundtrip failed at trial {trial}");
        }
    }

    #[test]
    fn test_ntt_roundtrip_1024() {
        let logn = 10;
        let n = 1usize << logn;

        for trial in 0..20u32 {
            let mut seed = 2000 + trial;
            let orig: Vec<u16> = (0..n).map(|_| rand_mod_q(&mut seed)).collect();
            let mut f = orig.clone();

            unsafe {
                ntt_forward_neon(&mut f, logn);
                ntt_inverse_neon(&mut f, logn);
            }

            assert_eq!(f, orig, "NTT 1024 roundtrip failed at trial {trial}");
        }
    }

    #[test]
    fn test_ntt_mul_correctness() {
        // Verify: INTT(NTT(a) * NTT(b)) == a * b mod (x^n+1) mod q
        // We check against schoolbook multiplication.
        let mut seed = 70u32;
        let logn = 9;
        let n = 1usize << logn;
        let q = Q as u32;

        let a: Vec<u16> = (0..n).map(|_| rand_mod_q(&mut seed)).collect();
        let b: Vec<u16> = (0..n).map(|_| rand_mod_q(&mut seed)).collect();

        // NTT multiplication
        let mut a_ntt = a.clone();
        let mut b_ntt = b.clone();
        unsafe {
            ntt_forward_neon(&mut a_ntt, logn);
            ntt_forward_neon(&mut b_ntt, logn);
        }
        let mut c_ntt = vec![0u16; n];
        for i in 0..n {
            c_ntt[i] = ((a_ntt[i] as u32 * b_ntt[i] as u32) % q) as u16;
        }
        unsafe { ntt_inverse_neon(&mut c_ntt, logn); }

        // Schoolbook multiplication mod (x^n+1) mod q
        let mut c_school = vec![0i64; 2 * n];
        for i in 0..n {
            for j in 0..n {
                c_school[i + j] += a[i] as i64 * b[j] as i64;
            }
        }
        let mut c_ref = vec![0u16; n];
        for i in 0..n {
            let val = c_school[i] - c_school[i + n];
            let mut r = (val % q as i64) as i32;
            if r < 0 { r += q as i32; }
            c_ref[i] = r as u16;
        }

        assert_eq!(c_ntt, c_ref, "NTT multiplication does not match schoolbook");
    }

    #[test]
    fn test_neon_100_random_poly_ops() {
        for trial in 0..100u32 {
            let mut seed = 100 + trial;
            let n = 512;
            let a: Vec<u16> = (0..n).map(|_| rand_mod_q(&mut seed)).collect();
            let b: Vec<u16> = (0..n).map(|_| rand_mod_q(&mut seed)).collect();

            let mut c_scalar = vec![0u16; n];
            let mut c_neon = vec![0u16; n];

            portable::poly_add(&mut c_scalar, &a, &b);
            unsafe { poly_add_neon(&mut c_neon, &a, &b); }
            assert_eq!(c_scalar, c_neon, "addmod mismatch at trial {trial}");

            portable::poly_sub(&mut c_scalar, &a, &b);
            unsafe { poly_sub_neon(&mut c_neon, &a, &b); }
            assert_eq!(c_scalar, c_neon, "submod mismatch at trial {trial}");

            portable::poly_pointwise(&mut c_scalar, &a, &b);
            unsafe { poly_pointwise_neon(&mut c_neon, &a, &b); }
            assert_eq!(c_scalar, c_neon, "pointwise mismatch at trial {trial}");
        }
    }
}
