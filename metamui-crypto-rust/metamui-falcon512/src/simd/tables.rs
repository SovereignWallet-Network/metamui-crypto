// MetaMUI Falcon - NTT Twiddle Factor Tables (u16 Montgomery form)
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Precomputed NTT twiddle factor tables in u16 Montgomery form.
//!
//! These tables are shared across all SIMD implementations (portable,
//! NEON, AVX2, AVX-512). Each table entry is `ψ^i * R mod q` where
//! R = 2^16 (Montgomery radix).
//!
//! Supported degrees:
//! - logn=9  (n=512):  ψ = 49  (primitive 1024th root of unity mod 12289)
//! - logn=10 (n=1024): ψ = 1945 (primitive 2048th root of unity mod 12289)
//!
//! The PSI values match the C implementation for cross-language compatibility.

use super::montgomery::{MONT_Q, to_mont};

const MAX_LOGN: usize = 10;
const MAX_N: usize = 1 << MAX_LOGN;

/// Per-logn twiddle factor tables.
struct NttTableSet {
    psi_pow_mont: [u16; MAX_N],  // ψ^i * R mod q
    psi_inv_mont: [u16; MAX_N],  // ψ^(-i) * R mod q
    n_inv_mont: u16,             // n^(-1) * R mod q
    ready: bool,
}

impl NttTableSet {
    const fn zeroed() -> Self {
        Self {
            psi_pow_mont: [0u16; MAX_N],
            psi_inv_mont: [0u16; MAX_N],
            n_inv_mont: 0,
            ready: false,
        }
    }
}

static mut TABLES: [NttTableSet; MAX_LOGN + 1] = [
    NttTableSet::zeroed(), NttTableSet::zeroed(), NttTableSet::zeroed(),
    NttTableSet::zeroed(), NttTableSet::zeroed(), NttTableSet::zeroed(),
    NttTableSet::zeroed(), NttTableSet::zeroed(), NttTableSet::zeroed(),
    NttTableSet::zeroed(), NttTableSet::zeroed(),
];

/// Modular exponentiation: base^exp mod q.
fn powmod_q(mut base: u32, mut exp: u32) -> u16 {
    let q = MONT_Q as u32;
    let mut result = 1u32;
    base %= q;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % q;
        }
        base = base * base % q;
        exp >>= 1;
    }
    result as u16
}

/// Modular multiply: (a * b) mod q.
fn mulmod_q(a: u16, b: u16) -> u16 {
    ((a as u32 * b as u32) % MONT_Q as u32) as u16
}

/// Get primitive 2n-th root of unity for each logn.
/// Matches the C implementation's values for cross-language consistency.
fn get_psi(logn: usize) -> u16 {
    match logn {
        9 => 49,     // ψ^1024 = 1, ψ^512 = -1 mod 12289
        10 => 1945,  // ψ^2048 = 1, ψ^1024 = -1 mod 12289
        _ => 49,     // fallback
    }
}

/// Initialize twiddle tables for a given logn.
///
/// # Safety
/// Uses static mutable state. Not thread-safe (matches C implementation).
/// Call from a single thread during initialization.
pub fn ensure_tables(logn: usize) {
    if logn > MAX_LOGN { return; }
    unsafe {
        if TABLES[logn].ready { return; }

        let n = 1usize << logn;
        let psi = get_psi(logn);
        let q = MONT_Q as u32;

        // Compute ψ^i and ψ^(-i) for i = 0..n-1
        let psi_inv = powmod_q(psi as u32, q - 2);

        let tab = &mut TABLES[logn];
        tab.psi_pow_mont[0] = to_mont(1);
        tab.psi_inv_mont[0] = to_mont(1);

        let mut psi_pow = 1u16;
        let mut psi_inv_pow = 1u16;
        for i in 1..n {
            psi_pow = mulmod_q(psi_pow, psi);
            psi_inv_pow = mulmod_q(psi_inv_pow, psi_inv);
            tab.psi_pow_mont[i] = to_mont(psi_pow);
            tab.psi_inv_mont[i] = to_mont(psi_inv_pow);
        }

        // n^(-1) mod q in Montgomery form
        let n_inv = powmod_q(n as u32, q - 2);
        tab.n_inv_mont = to_mont(n_inv);

        tab.ready = true;
    }
}

/// Get ψ^i * R mod q table for the given logn.
///
/// # Safety
/// Must call `ensure_tables(logn)` first.
pub fn psi_pow_mont(logn: usize) -> &'static [u16] {
    unsafe {
        let n = 1usize << logn;
        &TABLES[logn].psi_pow_mont[..n]
    }
}

/// Get ψ^(-i) * R mod q table for the given logn.
///
/// # Safety
/// Must call `ensure_tables(logn)` first.
pub fn psi_inv_mont(logn: usize) -> &'static [u16] {
    unsafe {
        let n = 1usize << logn;
        &TABLES[logn].psi_inv_mont[..n]
    }
}

/// Get n^(-1) * R mod q for the given logn.
///
/// # Safety
/// Must call `ensure_tables(logn)` first.
pub fn n_inv_mont(logn: usize) -> u16 {
    unsafe { TABLES[logn].n_inv_mont }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simd::montgomery::from_mont;

    #[test]
    fn test_tables_512() {
        ensure_tables(9);
        let tab = psi_pow_mont(9);
        assert_eq!(tab.len(), 512);
        // ψ^0 in Montgomery form, converted back should be 1
        assert_eq!(from_mont(tab[0]), 1);
        // ψ^1 in Montgomery form, converted back should be 49
        assert_eq!(from_mont(tab[1]), 49);
    }

    #[test]
    fn test_tables_1024() {
        ensure_tables(10);
        let tab = psi_pow_mont(10);
        assert_eq!(tab.len(), 1024);
        assert_eq!(from_mont(tab[0]), 1);
        assert_eq!(from_mont(tab[1]), 1945);
    }

    #[test]
    fn test_psi_pow_512_is_minus_one() {
        ensure_tables(9);
        let tab = psi_pow_mont(9);
        // ψ^512 should be q-1 (= -1 mod q)
        // tab[512] doesn't exist, so compute ψ^512 = ψ^511 * ψ
        let psi_511 = from_mont(tab[511]);
        let psi_512 = mulmod_q(psi_511, 49);
        assert_eq!(psi_512, 12288, "ψ^512 should be -1 mod q");
    }

    #[test]
    fn test_psi_inv_roundtrip() {
        ensure_tables(9);
        let fwd = psi_pow_mont(9);
        let inv = psi_inv_mont(9);
        // ψ^i * ψ^(-i) should be 1 for all i
        for i in 0..512 {
            let prod = mulmod_q(from_mont(fwd[i]), from_mont(inv[i]));
            assert_eq!(prod, 1, "ψ^{i} * ψ^(-{i}) != 1 at i={i}");
        }
    }

    #[test]
    fn test_n_inv_512() {
        ensure_tables(9);
        let n_inv = from_mont(n_inv_mont(9));
        // n * n_inv ≡ 1 (mod q)
        let prod = mulmod_q(512, n_inv);
        assert_eq!(prod, 1, "512 * 512^(-1) should be 1 mod q");
    }
}
