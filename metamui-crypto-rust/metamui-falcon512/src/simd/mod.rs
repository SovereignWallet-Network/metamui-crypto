// MetaMUI Falcon - SIMD Module
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! SIMD-accelerated kernels for Falcon NTT, FFT, and polynomial operations.
//!
//! Each sub-module implements the same trait interface, compiled with
//! architecture-specific flags. The [`dispatch`](crate::dispatch) module
//! selects the fastest available at runtime.
//!
//! # Module Layout
//!
//! ## NTT (integer mod q=12289)
//! - `portable` — scalar reference (always available)
//! - `montgomery` — shared Montgomery reduction utilities
//! - `avx2_ntt` — AVX2 NTT butterfly (Phase 1)
//! - `neon_ntt` — ARM NEON NTT butterfly (Phase 1)
//! - `avx512_ntt` — AVX-512BW NTT butterfly (Phase 3)
//!
//! ## Complex FFT (f64, for signing pipeline)
//! - `portable_fft` — scalar reference FFT operations
//! - `neon_fft` — ARM NEON complex FFT (Phase 2)
//! - `avx2_fft` — AVX2 complex FFT (Phase 2)
//! - `avx512_fft` — AVX-512F complex FFT (Phase 3)

pub mod portable;
pub mod portable_fft;
pub mod montgomery;
pub mod tables;

// Phase 1: AVX2 NTT kernels (x86/x86_64 only)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod avx2_ntt;

// Phase 1: ARM NEON NTT kernels (AArch64 only)
#[cfg(target_arch = "aarch64")]
pub mod neon_ntt;

// Phase 2: Complex FFT SIMD kernels
#[cfg(target_arch = "aarch64")]
pub mod neon_fft;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod avx2_fft;

// Phase 3: AVX-512 kernels (x86_64 only, opt-in)
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    feature = "avx512"
))]
pub mod avx512_ntt;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    feature = "avx512"
))]
pub mod avx512_fft;

/// Montgomery constants for q=12289, R=2^16.
/// Shared across all SIMD implementations.
pub use montgomery::{
    MONT_Q, MONT_QINV, MONT_R2_MOD_Q,
    mont_reduce, mont_mul, to_mont, from_mont,
};
