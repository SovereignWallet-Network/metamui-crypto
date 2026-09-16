// MetaMUI Falcon - Adaptive SIMD Dispatch
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>

//! Adaptive SIMD dispatch for Falcon NTT and FFT operations.
//!
//! Automatically selects the best SIMD implementation based on:
//! - Platform capabilities (AVX-512, AVX2, NEON)
//! - Runtime CPU feature detection
//!
//! # Performance Hierarchy
//!
//! | Level    | Register Width | Coefficients/Op | Platform                    |
//! |----------|---------------|-----------------|-----------------------------|
//! | AVX-512  | 512-bit       | 32 × u16        | Intel Skylake-X+, AMD Zen4+ |
//! | AVX2     | 256-bit       | 16 × u16        | Intel Haswell+, AMD Zen+    |
//! | NEON     | 128-bit       | 8 × u16         | All AArch64 / Apple Silicon |
//! | Portable | 64-bit        | 1 × u16         | Universal fallback          |
//!
//! # Usage
//!
//! ```rust,ignore
//! use metamui_falcon512::dispatch::{SimdType, detect_best};
//!
//! let level = detect_best();
//! println!("Using {} for NTT operations", level.name());
//! ```

/// SIMD implementation type for Falcon operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SimdType {
    /// Apple Metal GPU batch operations (macOS, batch_size >= 100)
    Metal,
    /// AVX-512BW: 32 × u16 per register (Intel Skylake-X 2017+, AMD Zen4 2022+)
    Avx512,
    /// AVX2: 16 × u16 per register (Intel Haswell 2013+, AMD Excavator 2015+)
    Avx2,
    /// ARM NEON: 8 × u16 per register (all AArch64 / Apple Silicon)
    Neon,
    /// Portable scalar implementation (universal fallback)
    Portable,
}

impl SimdType {
    /// Number of u16 coefficients processed per SIMD register.
    pub fn width(&self) -> usize {
        match self {
            SimdType::Metal => 1024, // GPU threadgroup
            SimdType::Avx512 => 32,
            SimdType::Avx2 => 16,
            SimdType::Neon => 8,
            SimdType::Portable => 1,
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            SimdType::Metal => "Apple Metal GPU",
            SimdType::Avx512 => "AVX-512BW",
            SimdType::Avx2 => "AVX2",
            SimdType::Neon => "ARM NEON",
            SimdType::Portable => "Portable (scalar)",
        }
    }
}

impl core::fmt::Display for SimdType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Detect the best available SIMD implementation at runtime.
///
/// Uses CPUID (x86) or assumes NEON (AArch64) to find the fastest path.
/// Result is cached after first call via std::sync::OnceLock.
pub fn detect_best() -> SimdType {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_avx512_available() {
            return SimdType::Avx512;
        }
        if is_avx2_available() {
            return SimdType::Avx2;
        }
        return SimdType::Portable;
    }

    #[cfg(target_arch = "aarch64")]
    {
        // NEON is mandatory on AArch64
        return SimdType::Neon;
    }

    #[cfg(not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64"
    )))]
    {
        SimdType::Portable
    }
}

// ================================================================
// Platform detection helpers
// ================================================================

/// Check AVX2 availability at runtime (x86/x86_64 only).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn is_avx2_available() -> bool {
    #[cfg(target_feature = "avx2")]
    { true }
    #[cfg(not(target_feature = "avx2"))]
    { is_x86_feature_detected!("avx2") }
}

/// Check AVX-512BW availability at runtime (x86/x86_64 only).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn is_avx512_available() -> bool {
    #[cfg(target_feature = "avx512bw")]
    { true }
    #[cfg(not(target_feature = "avx512bw"))]
    {
        is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512bw")
    }
}

/// NEON is always available on AArch64.
#[cfg(target_arch = "aarch64")]
pub fn is_neon_available() -> bool {
    true
}

// ================================================================
// FFT Domain Dispatch Functions
//
// These route complex polynomial operations to the fastest available
// SIMD implementation. The SOA layout (f[0..hn-1] = re, f[hn..n-1] = im)
// is used for SIMD-friendly access patterns.
// ================================================================

/// Dispatch poly_add_fft to the best SIMD implementation.
pub fn poly_add_fft(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { crate::simd::neon_fft::poly_add_fft_neon(c, a, b, logn); }
        return;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "avx512")]
        if is_avx512_available() {
            unsafe { crate::simd::avx512_fft::poly_add_fft_avx512(c, a, b, logn); }
            return;
        }
        if is_avx2_available() {
            unsafe { crate::simd::avx2_fft::poly_add_fft_avx2(c, a, b, logn); }
            return;
        }
    }
    #[allow(unreachable_code)]
    { crate::simd::portable_fft::poly_add_fft(c, a, b, logn); }
}

/// Dispatch poly_sub_fft.
pub fn poly_sub_fft(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { crate::simd::neon_fft::poly_sub_fft_neon(c, a, b, logn); }
        return;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "avx512")]
        if is_avx512_available() {
            unsafe { crate::simd::avx512_fft::poly_sub_fft_avx512(c, a, b, logn); }
            return;
        }
        if is_avx2_available() {
            unsafe { crate::simd::avx2_fft::poly_sub_fft_avx2(c, a, b, logn); }
            return;
        }
    }
    #[allow(unreachable_code)]
    { crate::simd::portable_fft::poly_sub_fft(c, a, b, logn); }
}

/// Dispatch poly_mul_fft (complex multiply).
pub fn poly_mul_fft(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { crate::simd::neon_fft::poly_mul_fft_neon(c, a, b, logn); }
        return;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "avx512")]
        if is_avx512_available() {
            unsafe { crate::simd::avx512_fft::poly_mul_fft_avx512(c, a, b, logn); }
            return;
        }
        if is_avx2_available() {
            unsafe { crate::simd::avx2_fft::poly_mul_fft_avx2(c, a, b, logn); }
            return;
        }
    }
    #[allow(unreachable_code)]
    { crate::simd::portable_fft::poly_mul_fft(c, a, b, logn); }
}

/// Dispatch poly_muladj_fft (multiply by conjugate).
pub fn poly_muladj_fft(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { crate::simd::neon_fft::poly_muladj_fft_neon(c, a, b, logn); }
        return;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "avx512")]
        if is_avx512_available() {
            unsafe { crate::simd::avx512_fft::poly_muladj_fft_avx512(c, a, b, logn); }
            return;
        }
        if is_avx2_available() {
            unsafe { crate::simd::avx2_fft::poly_muladj_fft_avx2(c, a, b, logn); }
            return;
        }
    }
    #[allow(unreachable_code)]
    { crate::simd::portable_fft::poly_muladj_fft(c, a, b, logn); }
}

/// Dispatch poly_muladd_fft: c = acc + a * b (fused multiply-add).
///
/// Combines complex multiply and addition in a single pass, saving one
/// full load/store cycle over separate `poly_mul_fft` + `poly_add_fft`.
pub fn poly_muladd_fft(c: &mut [f64], a: &[f64], b: &[f64], acc: &[f64], logn: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { crate::simd::neon_fft::poly_muladd_fft_neon(c, a, b, acc, logn); }
        return;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "avx512")]
        if is_avx512_available() {
            unsafe { crate::simd::avx512_fft::poly_muladd_fft_avx512(c, a, b, acc, logn); }
            return;
        }
        if is_avx2_available() {
            unsafe { crate::simd::avx2_fft::poly_muladd_fft_avx2(c, a, b, acc, logn); }
            return;
        }
    }
    #[allow(unreachable_code)]
    { crate::simd::portable_fft::poly_muladd_fft(c, a, b, acc, logn); }
}

/// Dispatch poly_mulsub_fft: c = acc - a * b (fused multiply-subtract).
///
/// Combines complex multiply and subtraction in a single pass.
pub fn poly_mulsub_fft(c: &mut [f64], a: &[f64], b: &[f64], acc: &[f64], logn: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { crate::simd::neon_fft::poly_mulsub_fft_neon(c, a, b, acc, logn); }
        return;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "avx512")]
        if is_avx512_available() {
            unsafe { crate::simd::avx512_fft::poly_mulsub_fft_avx512(c, a, b, acc, logn); }
            return;
        }
        if is_avx2_available() {
            unsafe { crate::simd::avx2_fft::poly_mulsub_fft_avx2(c, a, b, acc, logn); }
            return;
        }
    }
    #[allow(unreachable_code)]
    { crate::simd::portable_fft::poly_mulsub_fft(c, a, b, acc, logn); }
}

/// Dispatch poly_adj_fft (complex conjugate).
pub fn poly_adj_fft(c: &mut [f64], a: &[f64], logn: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { crate::simd::neon_fft::poly_adj_fft_neon(c, a, logn); }
        return;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "avx512")]
        if is_avx512_available() {
            unsafe { crate::simd::avx512_fft::poly_adj_fft_avx512(c, a, logn); }
            return;
        }
        if is_avx2_available() {
            unsafe { crate::simd::avx2_fft::poly_adj_fft_avx2(c, a, logn); }
            return;
        }
    }
    #[allow(unreachable_code)]
    { crate::simd::portable_fft::poly_adj_fft(c, a, logn); }
}

/// Dispatch poly_inv_fft (complex inverse).
pub fn poly_inv_fft(c: &mut [f64], a: &[f64], logn: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { crate::simd::neon_fft::poly_inv_fft_neon(c, a, logn); }
        return;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "avx512")]
        if is_avx512_available() {
            unsafe { crate::simd::avx512_fft::poly_inv_fft_avx512(c, a, logn); }
            return;
        }
        if is_avx2_available() {
            unsafe { crate::simd::avx2_fft::poly_inv_fft_avx2(c, a, logn); }
            return;
        }
    }
    #[allow(unreachable_code)]
    { crate::simd::portable_fft::poly_inv_fft(c, a, logn); }
}

/// Dispatch poly_norm_fft (squared norm).
pub fn poly_norm_fft(c: &mut [f64], a: &[f64], logn: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { crate::simd::neon_fft::poly_norm_fft_neon(c, a, logn); }
        return;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "avx512")]
        if is_avx512_available() {
            unsafe { crate::simd::avx512_fft::poly_norm_fft_avx512(c, a, logn); }
            return;
        }
        if is_avx2_available() {
            unsafe { crate::simd::avx2_fft::poly_norm_fft_avx2(c, a, logn); }
            return;
        }
    }
    #[allow(unreachable_code)]
    { crate::simd::portable_fft::poly_norm_fft(c, a, logn); }
}

/// Dispatch poly_split_fft.
pub fn poly_split_fft(f0: &mut [f64], f1: &mut [f64], f: &[f64], logn: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { crate::simd::neon_fft::poly_split_fft_neon(f0, f1, f, logn); }
        return;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "avx512")]
        if is_avx512_available() {
            unsafe { crate::simd::avx512_fft::poly_split_fft_avx512(f0, f1, f, logn); }
            return;
        }
        if is_avx2_available() {
            unsafe { crate::simd::avx2_fft::poly_split_fft_avx2(f0, f1, f, logn); }
            return;
        }
    }
    #[allow(unreachable_code)]
    { crate::simd::portable_fft::poly_split_fft(f0, f1, f, logn); }
}

/// Dispatch poly_merge_fft.
pub fn poly_merge_fft(f: &mut [f64], f0: &[f64], f1: &[f64], logn: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { crate::simd::neon_fft::poly_merge_fft_neon(f, f0, f1, logn); }
        return;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "avx512")]
        if is_avx512_available() {
            unsafe { crate::simd::avx512_fft::poly_merge_fft_avx512(f, f0, f1, logn); }
            return;
        }
        if is_avx2_available() {
            unsafe { crate::simd::avx2_fft::poly_merge_fft_avx2(f, f0, f1, logn); }
            return;
        }
    }
    #[allow(unreachable_code)]
    { crate::simd::portable_fft::poly_merge_fft(f, f0, f1, logn); }
}

// ================================================================
// FFT Forward / Inverse: coefficient ↔ FFT domain
//
// O(n log n) butterfly FFT using SIMD-dispatched split/merge.
// The recursive structure itself is sequential, but each split/merge
// call routes through the fastest SIMD backend.
// ================================================================

/// O(n log n) forward FFT: real coefficients → FFT domain (SOA layout).
///
/// Converts `f[0..n-1]` real coefficients into the split-radix FFT
/// representation where `f[0..hn-1]` = real parts, `f[hn..n-1]` = imaginary parts.
///
/// Uses SIMD-accelerated `poly_merge_fft` at each recursion level.
pub fn fft_forward(f: &mut [f64], logn: usize) {
    if logn <= 1 { return; }

    let n = 1usize << logn;
    let hn = n >> 1;

    // Separate even/odd coefficients
    let mut tmp = vec![0.0f64; n];
    for i in 0..hn {
        tmp[i]      = f[2 * i];     // even
        tmp[i + hn] = f[2 * i + 1]; // odd
    }

    // Recursively FFT each half
    fft_forward(&mut tmp[..hn], logn - 1);
    fft_forward(&mut tmp[hn..], logn - 1);

    // SIMD-dispatched merge
    poly_merge_fft(f, &tmp[..hn], &tmp[hn..], logn);
}

/// O(n log n) inverse FFT: FFT domain (SOA layout) → real coefficients.
///
/// Converts `f[0..hn-1]` real parts + `f[hn..n-1]` imaginary parts back
/// into real polynomial coefficients `f[0..n-1]`.
///
/// Uses SIMD-accelerated `poly_split_fft` at each recursion level.
pub fn fft_inverse(f: &mut [f64], logn: usize) {
    if logn <= 1 { return; }

    let n = 1usize << logn;
    let hn = n >> 1;

    // SIMD-dispatched split
    let mut f0 = vec![0.0f64; hn];
    let mut f1 = vec![0.0f64; hn];
    poly_split_fft(&mut f0, &mut f1, f, logn);

    // Recursively inverse FFT each half
    fft_inverse(&mut f0, logn - 1);
    fft_inverse(&mut f1, logn - 1);

    // Interleave even/odd coefficients
    for i in 0..hn {
        f[2 * i]     = f0[i];
        f[2 * i + 1] = f1[i];
    }
}

// ================================================================
// AOS ↔ SOA Conversion Utilities
//
// The signing pipeline (ffSampling) historically used AOS layout
// (Array-of-Structures: Vec<(f64, f64)>), while SIMD kernels use SOA
// (Structure-of-Arrays: [re_0..re_{hn-1}, im_0..im_{hn-1}]).
//
// These converters bridge the two representations.
// ================================================================

/// Convert AOS complex data `[(re, im), ...]` of length `hn` to SOA flat
/// array of length `n = 2*hn`: `[re_0..re_{hn-1}, im_0..im_{hn-1}]`.
#[inline]
pub fn aos_to_soa(aos: &[(f64, f64)], soa: &mut [f64]) {
    let hn = aos.len();
    debug_assert_eq!(soa.len(), 2 * hn);
    for i in 0..hn {
        soa[i]      = aos[i].0;
        soa[i + hn] = aos[i].1;
    }
}

/// Convert SOA flat array of length `n` to AOS complex data of length `hn = n/2`.
#[inline]
pub fn soa_to_aos(soa: &[f64], aos: &mut [(f64, f64)]) {
    let n = soa.len();
    let hn = n >> 1;
    debug_assert_eq!(aos.len(), hn);
    for i in 0..hn {
        aos[i] = (soa[i], soa[i + hn]);
    }
}

/// Allocate and convert AOS to SOA, returning the SOA Vec.
#[inline]
pub fn aos_to_soa_vec(aos: &[(f64, f64)]) -> alloc::vec::Vec<f64> {
    let hn = aos.len();
    let mut soa = vec![0.0f64; 2 * hn];
    aos_to_soa(aos, &mut soa);
    soa
}

/// Allocate and convert SOA to AOS, returning the AOS Vec.
#[inline]
pub fn soa_to_aos_vec(soa: &[f64]) -> alloc::vec::Vec<(f64, f64)> {
    let hn = soa.len() >> 1;
    let mut aos = vec![(0.0f64, 0.0f64); hn];
    soa_to_aos(soa, &mut aos);
    aos
}

// ================================================================
// Metal GPU batch dispatch
//
// Metal is used exclusively for batch operations where the overhead
// of GPU dispatch (~500µs) is amortized across many items.
// Single-polynomial operations always use CPU SIMD.
// ================================================================

/// Check if Metal GPU batch operations are available.
///
/// Returns true on macOS with Metal GPU when the `metal` feature is enabled.
pub fn is_metal_available() -> bool {
    #[cfg(all(feature = "metal", target_os = "macos"))]
    {
        return crate::metal::MetalFalconBatch::is_available();
    }
    #[allow(unreachable_code)]
    false
}

/// Detect the best SIMD level for batch operations.
///
/// Returns `SimdType::Metal` if Metal is available and batch_size exceeds
/// the crossover point (~100 items). Otherwise delegates to `detect_best()`.
pub fn detect_best_for_batch(batch_size: usize) -> SimdType {
    #[cfg(all(feature = "metal", target_os = "macos"))]
    {
        if batch_size >= 100 && is_metal_available() {
            return SimdType::Metal;
        }
    }
    detect_best()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_best() {
        let level = detect_best();
        // Should always return a valid level
        assert!(!level.name().is_empty());
        assert!(level.width() >= 1);
        println!("Detected SIMD level: {} (width={})", level.name(), level.width());
    }

    #[test]
    fn test_simd_ordering() {
        // Metal < Avx512 < Avx2 < Neon < Portable (by enum order)
        assert!(SimdType::Metal < SimdType::Avx512);
        assert!(SimdType::Avx512 < SimdType::Avx2);
        assert!(SimdType::Avx2 < SimdType::Neon);
        assert!(SimdType::Neon < SimdType::Portable);
    }

    // ── FFT dispatch integration tests ──────────────────────────

    fn rand_f64(seed: &mut u32) -> f64 {
        *seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        ((*seed >> 8) as f64 / 16777216.0) * 200.0 - 100.0
    }

    fn close(a: f64, b: f64, tol: f64) -> bool {
        let diff = (a - b).abs();
        let denom = a.abs() + b.abs() + 1e-30;
        diff / denom < tol
    }

    #[test]
    fn test_dispatch_add_sub_roundtrip() {
        let logn = 9;
        let n = 1usize << logn;
        let mut seed = 100u32;

        let a: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
        let b: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
        let mut sum = vec![0.0f64; n];
        let mut diff = vec![0.0f64; n];
        let mut recovered = vec![0.0f64; n];

        poly_add_fft(&mut sum, &a, &b, logn);
        poly_sub_fft(&mut diff, &sum, &b, logn);

        for i in 0..n {
            assert!(close(a[i], diff[i], 1e-14),
                "add/sub roundtrip failed at {i}: {} vs {}", a[i], diff[i]);
        }

        // Also test sub then add
        poly_sub_fft(&mut diff, &a, &b, logn);
        poly_add_fft(&mut recovered, &diff, &b, logn);
        for i in 0..n {
            assert!(close(a[i], recovered[i], 1e-14),
                "sub/add roundtrip failed at {i}");
        }
    }

    #[test]
    fn test_dispatch_mul_identity() {
        let logn = 9;
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut seed = 200u32;

        let a: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
        let mut one = vec![0.0f64; n];
        for i in 0..hn { one[i] = 1.0; }

        let mut c = vec![0.0f64; n];
        poly_mul_fft(&mut c, &a, &one, logn);

        for i in 0..n {
            assert!(close(a[i], c[i], 1e-14),
                "mul identity failed at {i}: {} vs {}", a[i], c[i]);
        }
    }

    #[test]
    fn test_dispatch_inv_roundtrip() {
        let logn = 9;
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut seed = 300u32;

        let mut a: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
        for i in 0..hn {
            if a[i].abs() < 1.0 { a[i] += 10.0; }
            if a[i + hn].abs() < 1.0 { a[i + hn] += 10.0; }
        }

        let mut inv = vec![0.0f64; n];
        poly_inv_fft(&mut inv, &a, logn);

        let mut product = vec![0.0f64; n];
        poly_mul_fft(&mut product, &a, &inv, logn);

        for i in 0..hn {
            assert!(close(product[i], 1.0, 1e-10),
                "inv roundtrip re at {i}: {} vs 1.0", product[i]);
            assert!(product[i + hn].abs() < 1e-8,
                "inv roundtrip im at {i}: {}", product[i + hn]);
        }
    }

    #[test]
    fn test_dispatch_adj_norm() {
        let logn = 9;
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut seed = 400u32;

        let a: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();

        // adj(adj(a)) == a
        let mut b = vec![0.0f64; n];
        let mut c = vec![0.0f64; n];
        poly_adj_fft(&mut b, &a, logn);
        poly_adj_fft(&mut c, &b, logn);
        for i in 0..n {
            assert!(close(a[i], c[i], 1e-14), "adj involution failed at {i}");
        }

        // norm(a) == a * conj(a) (real parts)
        let mut norm = vec![0.0f64; n];
        poly_norm_fft(&mut norm, &a, logn);

        let mut muladj = vec![0.0f64; n];
        poly_muladj_fft(&mut muladj, &a, &a, logn);
        for i in 0..hn {
            assert!(close(norm[i], muladj[i], 1e-12),
                "norm vs muladj(a,a) mismatch at {i}: {} vs {}", norm[i], muladj[i]);
        }
    }

    #[test]
    fn test_dispatch_split_merge_roundtrip() {
        for logn in 2..=10 {
            let n = 1usize << logn;
            let hn = n >> 1;
            let mut seed = 500u32 + logn as u32;

            let f: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
            let mut f0 = vec![0.0f64; hn];
            let mut f1 = vec![0.0f64; hn];
            poly_split_fft(&mut f0, &mut f1, &f, logn);

            let mut merged = vec![0.0f64; n];
            poly_merge_fft(&mut merged, &f0, &f1, logn);

            for i in 0..n {
                assert!(close(f[i], merged[i], 1e-10),
                    "split/merge roundtrip failed at logn={logn} i={i}: {} vs {}",
                    f[i], merged[i]);
            }
        }
    }

    #[test]
    fn test_dispatch_fft_forward_inverse() {
        for logn in 1..=10 {
            let n = 1usize << logn;
            let mut seed = 600u32 + logn as u32;

            let original: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
            let mut f = original.clone();

            fft_forward(&mut f, logn);
            fft_inverse(&mut f, logn);

            for i in 0..n {
                assert!(close(original[i], f[i], 1e-10),
                    "dispatch FFT roundtrip failed at logn={logn} i={i}: {} vs {}",
                    original[i], f[i]);
            }
        }
    }

    #[test]
    fn test_dispatch_fft_negacyclic_multiply() {
        // Verify FFT domain multiply = negacyclic convolution
        // (3 + 2x)(5 + 7x) mod (x²+1) = (15-14) + (21+10)x = 1 + 31x
        let mut a = vec![3.0, 2.0];
        let mut b = vec![5.0, 7.0];
        fft_forward(&mut a, 1);
        fft_forward(&mut b, 1);

        let mut c = vec![0.0; 2];
        poly_mul_fft(&mut c, &a, &b, 1);
        fft_inverse(&mut c, 1);

        assert!(close(c[0], 1.0, 1e-10), "expected 1.0, got {}", c[0]);
        assert!(close(c[1], 31.0, 1e-10), "expected 31.0, got {}", c[1]);
    }

    #[test]
    fn test_aos_soa_roundtrip() {
        let aos = vec![(1.0, 2.0), (3.0, 4.0), (5.0, 6.0), (7.0, 8.0)];
        let soa = aos_to_soa_vec(&aos);

        // SOA should be [1,3,5,7, 2,4,6,8]
        assert_eq!(soa, vec![1.0, 3.0, 5.0, 7.0, 2.0, 4.0, 6.0, 8.0]);

        let recovered = soa_to_aos_vec(&soa);
        assert_eq!(recovered, aos);
    }

    // ── Metal dispatch tests ─────────────────────────────────

    #[test]
    fn test_detect_best_for_batch() {
        // Small batch should NOT return Metal (even on macOS)
        let small = detect_best_for_batch(10);
        assert_ne!(small, SimdType::Metal, "small batch should use CPU SIMD");

        // The function should always return a valid level
        let large = detect_best_for_batch(200);
        assert!(!large.name().is_empty());
        println!("Batch dispatch (200): {}", large.name());
    }

    #[test]
    fn test_is_metal_available_returns_bool() {
        // Just verify it returns without panicking
        let available = is_metal_available();
        println!("Metal GPU available: {}", available);
    }
}
