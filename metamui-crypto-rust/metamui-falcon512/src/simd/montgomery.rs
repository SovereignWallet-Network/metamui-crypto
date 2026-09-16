// MetaMUI Falcon - Montgomery Modular Arithmetic (Rust)
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Montgomery modular arithmetic for q=12289, R=2^16.
//!
//! Replaces expensive `% q` division with multiply + shift. These functions
//! are the building blocks for both scalar and SIMD NTT implementations.
//!
//! # Constants
//!
//! For q = 12289, R = 2^16 = 65536:
//! - `QINV = q^(-1) mod R = 53249` (or -12287 as i16)
//! - `R mod q = 4091`
//! - `R^2 mod q = 10952`
//! - `R^(-1) mod q = 2304`
//!
//! # SIMD Mapping
//!
//! Montgomery reduction maps perfectly to SIMD intrinsics:
//! - AVX2: `_mm256_mullo_epi16` + `_mm256_mulhi_epu16` + `_mm256_sub_epi16`
//! - NEON: `vmull_u16` (widening) + `vshrn_n_u32` (narrowing shift)

/// Falcon's NTT prime modulus.
pub const MONT_Q: u16 = 12289;

/// q^(-1) mod 2^16 = 53249 (unsigned) = -12287 (signed i16).
/// Used in the low-bits step of Montgomery reduction.
pub const MONT_QINV: u16 = 53249;

/// R^2 mod q = 10952. Used by `to_mont()` to convert to Montgomery form.
pub const MONT_R2_MOD_Q: u16 = 10952;

/// R mod q = 4091.
pub const MONT_R_MOD_Q: u16 = 4091;

/// R^(-1) mod q = 2304. Used conceptually; `from_mont()` uses `mont_reduce`.
pub const MONT_RINV_MOD_Q: u16 = 2304;

/// Montgomery reduction: computes `a * R^(-1) mod q`.
///
/// Input: `a` is a 32-bit product (e.g., from multiplying two 16-bit values).
/// Output: result in `(-q, q)` range before normalization.
///
/// Algorithm:
/// 1. `t = (a mod R) * QINV mod R`  — low 16 bits only
/// 2. `result = (a - t * q) / R`    — exact division (shift by 16)
///
/// Constant-time: no branches, no data-dependent operations.
#[inline(always)]
pub fn mont_reduce(a: i32) -> i16 {
    // Step 1: low 16 bits of a, times QINV, mod R
    let t = (a as u16).wrapping_mul(MONT_QINV) as i16;
    // Step 2: (a - t*q) is divisible by R; shift right by 16
    ((a - (t as i32) * (MONT_Q as i32)) >> 16) as i16
}

/// Montgomery multiply: `a * b_mont * R^(-1) mod q`.
///
/// If `b_mont = b * R mod q` (Montgomery form), then
/// `mont_mul(a, b_mont) = a * b mod q`.
///
/// Both inputs in `[0, q)`, output in `[0, q)`.
#[inline(always)]
pub fn mont_mul(a: u16, b_mont: u16) -> u16 {
    let prod = (a as u32 * b_mont as u32) as i32;
    let r = mont_reduce(prod);
    if r < 0 { (r + MONT_Q as i16) as u16 } else { r as u16 }
}

/// Convert normal form → Montgomery form: `a * R mod q`.
#[inline(always)]
pub fn to_mont(a: u16) -> u16 {
    mont_mul(a, MONT_R2_MOD_Q)
}

/// Convert Montgomery form → normal form: `a_mont * R^(-1) mod q`.
#[inline(always)]
pub fn from_mont(a_mont: u16) -> u16 {
    let r = mont_reduce(a_mont as i32);
    if r < 0 { (r + MONT_Q as i16) as u16 } else { r as u16 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_constants() {
        // Verify: q * QINV ≡ 1 (mod 2^16)
        let product = (MONT_Q as u32).wrapping_mul(MONT_QINV as u32) & 0xFFFF;
        assert_eq!(product, 1, "q * QINV should be 1 mod R");

        // Verify R^2 mod q = (R mod q)^2 mod q = 4091^2 mod 12289
        let r_mod_q: u64 = 4091;
        assert_eq!((r_mod_q * r_mod_q % MONT_Q as u64) as u16, MONT_R2_MOD_Q);

        // Verify R mod q
        assert_eq!((65536u64 % MONT_Q as u64) as u16, MONT_R_MOD_Q);
    }

    #[test]
    fn test_to_from_mont_roundtrip() {
        for a in [0u16, 1, 100, 6144, 12288] {
            let m = to_mont(a);
            let back = from_mont(m);
            assert_eq!(back, a, "to_mont/from_mont roundtrip failed for {a}");
        }
    }

    #[test]
    fn test_mont_mul_correctness() {
        let q = MONT_Q as u32;
        // Test: mont_mul(a, to_mont(b)) should equal (a * b) % q
        for &a in &[0u16, 1, 49, 1945, 6144, 12288] {
            for &b in &[0u16, 1, 49, 1945, 6144, 12288] {
                let expected = ((a as u32 * b as u32) % q) as u16;
                let b_mont = to_mont(b);
                let result = mont_mul(a, b_mont);
                assert_eq!(result, expected,
                    "mont_mul({a}, to_mont({b})) = {result}, expected {expected}");
            }
        }
    }

    #[test]
    fn test_mont_mul_exhaustive_sample() {
        // Test a sample of all possible multiplications
        let q = MONT_Q as u32;
        for a in (0..12289u16).step_by(127) {
            let b: u16 = (a.wrapping_mul(37).wrapping_add(11)) % MONT_Q;
            let expected = ((a as u32 * b as u32) % q) as u16;
            let result = mont_mul(a, to_mont(b));
            assert_eq!(result, expected, "Failed for a={a}, b={b}");
        }
    }
}
