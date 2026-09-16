// MetaMUI Falcon - Portable Scalar FFT Operations (f64)
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Scalar reference implementations of complex FFT domain operations.
//!
//! These operate on the SOA (Structure-of-Arrays) layout used by Falcon:
//!   `f[0..n/2-1]` = real parts, `f[n/2..n-1]` = imaginary parts.
//!
//! All functions serve as the correctness oracle for SIMD implementations.

use core::f64::consts::PI;

/// c = a + b (pointwise complex addition, n elements)
pub fn poly_add_fft(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let n = 1usize << logn;
    for i in 0..n {
        c[i] = a[i] + b[i];
    }
}

/// c = a - b (pointwise complex subtraction, n elements)
pub fn poly_sub_fft(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let n = 1usize << logn;
    for i in 0..n {
        c[i] = a[i] - b[i];
    }
}

/// c = a * b (pointwise complex multiplication)
///
/// For each complex element i in [0, n/2):
///   c_re = a_re * b_re - a_im * b_im
///   c_im = a_re * b_im + a_im * b_re
pub fn poly_mul_fft(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for i in 0..hn {
        let (ar, ai) = (a[i], a[i + hn]);
        let (br, bi) = (b[i], b[i + hn]);
        c[i]      = ar * br - ai * bi;
        c[i + hn] = ar * bi + ai * br;
    }
}

/// c = a * conj(b) (pointwise multiply by conjugate)
///
///   c_re = a_re * b_re + a_im * b_im
///   c_im = a_im * b_re - a_re * b_im
pub fn poly_muladj_fft(c: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for i in 0..hn {
        let (ar, ai) = (a[i], a[i + hn]);
        let (br, bi) = (b[i], b[i + hn]);
        c[i]      = ar * br + ai * bi;
        c[i + hn] = ai * br - ar * bi;
    }
}

/// c = conj(a) (complex conjugate: negate imaginary parts)
pub fn poly_adj_fft(c: &mut [f64], a: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for i in 0..hn {
        c[i]      = a[i];
        c[i + hn] = -a[i + hn];
    }
}

/// c = 1/a (pointwise complex inverse)
///
///   norm = re² + im²
///   c_re =  re / norm
///   c_im = -im / norm
pub fn poly_inv_fft(c: &mut [f64], a: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for i in 0..hn {
        let (re, im) = (a[i], a[i + hn]);
        let norm = re * re + im * im;
        let inv_norm = 1.0 / norm;
        c[i]      = re * inv_norm;
        c[i + hn] = -(im * inv_norm);
    }
}

/// c = |a|² (squared norm, real-valued result)
///
///   c_re = re² + im²
///   c_im = 0
pub fn poly_norm_fft(c: &mut [f64], a: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for i in 0..hn {
        let (re, im) = (a[i], a[i + hn]);
        c[i]      = re * re + im * im;
        c[i + hn] = 0.0;
    }
}

/// c = acc + a * b (fused multiply-add)
///
/// Combines pointwise complex multiply and add in a single pass,
/// halving memory traffic compared to separate mul + add.
pub fn poly_muladd_fft(c: &mut [f64], a: &[f64], b: &[f64], acc: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for i in 0..hn {
        let (ar, ai) = (a[i], a[i + hn]);
        let (br, bi) = (b[i], b[i + hn]);
        c[i]      = acc[i]      + (ar * br - ai * bi);
        c[i + hn] = acc[i + hn] + (ar * bi + ai * br);
    }
}

/// c = acc - a * b (fused multiply-subtract)
///
/// Combines pointwise complex multiply and subtract in a single pass.
pub fn poly_mulsub_fft(c: &mut [f64], a: &[f64], b: &[f64], acc: &[f64], logn: usize) {
    let n = 1usize << logn;
    let hn = n >> 1;
    for i in 0..hn {
        let (ar, ai) = (a[i], a[i + hn]);
        let (br, bi) = (b[i], b[i + hn]);
        c[i]      = acc[i]      - (ar * br - ai * bi);
        c[i + hn] = acc[i + hn] - (ar * bi + ai * br);
    }
}

/// Split: decompose FFT(f) → FFT(f₀), FFT(f₁)
///
/// For each k in [0, n/4):
///   A = f(ω_k),  B = conj(f(ω_p))  where p = n/2 - 1 - k
///   f₀(η_k) = (A + B) / 2
///   f₁(η_k) = (A - B) / (2·ω_k)
pub fn poly_split_fft(f0: &mut [f64], f1: &mut [f64], f: &[f64], logn: usize) {
    if logn == 0 { return; }
    if logn == 1 {
        f0[0] = f[0];
        f1[0] = f[1];
        return;
    }

    let n = 1usize << logn;
    let hn = n >> 1;
    let qn = hn >> 1;

    for k in 0..qn {
        let p = hn - 1 - k;

        let (a_re, a_im) = (f[k], f[k + hn]);
        let (b_re, b_im) = (f[p], -f[p + hn]);

        f0[k]      = (a_re + b_re) * 0.5;
        f0[k + qn] = (a_im + b_im) * 0.5;

        let d_re = (a_re - b_re) * 0.5;
        let d_im = (a_im - b_im) * 0.5;

        let angle = (2 * k + 1) as f64 * PI / n as f64;
        let (z_re, z_im) = (angle.cos(), angle.sin());
        // Divide by ω_k = multiply by conj(ω_k) = (cos, -sin)
        f1[k]      = d_re * z_re + d_im * z_im;
        f1[k + qn] = d_im * z_re - d_re * z_im;
    }
}

/// Merge: inverse of split — reconstruct FFT(f) from f₀, f₁
///
/// For each k in [0, n/4):
///   w = ω_k · f₁(η_k)
///   f(ω_k) = f₀(η_k) + w
///   f(ω_p) = conj(f₀(η_k) - w)    where p = n/2 - 1 - k
pub fn poly_merge_fft(f: &mut [f64], f0: &[f64], f1: &[f64], logn: usize) {
    if logn == 0 { return; }
    if logn == 1 {
        f[0] = f0[0];
        f[1] = f1[0];
        return;
    }

    let n = 1usize << logn;
    let hn = n >> 1;
    let qn = hn >> 1;

    for k in 0..qn {
        let p = hn - 1 - k;

        let (e_re, e_im) = (f0[k], f0[k + qn]);
        let (o_re, o_im) = (f1[k], f1[k + qn]);

        let angle = (2 * k + 1) as f64 * PI / n as f64;
        let (z_re, z_im) = (angle.cos(), angle.sin());
        let w_re = o_re * z_re - o_im * z_im;
        let w_im = o_re * z_im + o_im * z_re;

        f[k]      = e_re + w_re;
        f[k + hn] = e_im + w_im;
        f[p]      = e_re - w_re;
        f[p + hn] = -(e_im - w_im);
    }
}

// ================================================================
// FFT Forward / Inverse: coefficient ↔ FFT domain conversion
//
// These use the recursive butterfly structure:
//   Forward: coeff → split even/odd → recurse → merge
//   Inverse: FFT → split → recurse → interleave even/odd
//
// Both are O(n log n) and work in-place on SOA layout:
//   f[0..hn-1] = real parts, f[hn..n-1] = imaginary parts
// ================================================================

/// O(n log n) forward FFT: real coefficients → FFT domain (SOA layout).
///
/// Input: `f[0..n-1]` = real polynomial coefficients.
/// Output: `f[0..hn-1]` = real parts, `f[hn..n-1]` = imaginary parts
/// of evaluations at ω^{2k+1} for k=0..hn-1.
pub fn fft_forward(f: &mut [f64], logn: usize) {
    if logn == 0 { return; }

    let n = 1usize << logn;
    let hn = n >> 1;

    // Base case: n=2, f(x) = a + bx evaluated at ω=i → (a, b)
    // The SOA layout [re, im] = [a, b] is already correct.
    if logn == 1 { return; }

    // Separate even/odd coefficients into temporary buffer
    let mut tmp = vec![0.0f64; n];
    for i in 0..hn {
        tmp[i]      = f[2 * i];     // even coefficients
        tmp[i + hn] = f[2 * i + 1]; // odd coefficients
    }

    // Recursively FFT each half
    fft_forward(&mut tmp[..hn], logn - 1);
    fft_forward(&mut tmp[hn..], logn - 1);

    // Merge: combine FFT(f_even) and FFT(f_odd) into FFT(f)
    poly_merge_fft(f, &tmp[..hn], &tmp[hn..], logn);
}

/// O(n log n) inverse FFT: FFT domain (SOA layout) → real coefficients.
///
/// Input: `f[0..hn-1]` = real parts, `f[hn..n-1]` = imaginary parts.
/// Output: `f[0..n-1]` = real polynomial coefficients.
pub fn fft_inverse(f: &mut [f64], logn: usize) {
    if logn == 0 { return; }

    let n = 1usize << logn;
    let hn = n >> 1;

    // Base case: identity (same as forward)
    if logn == 1 { return; }

    // Split FFT(f) into FFT(f_even) and FFT(f_odd)
    let mut f0 = vec![0.0f64; hn];
    let mut f1 = vec![0.0f64; hn];
    poly_split_fft(&mut f0, &mut f1, f, logn);

    // Recursively inverse FFT each half
    fft_inverse(&mut f0, logn - 1);
    fft_inverse(&mut f1, logn - 1);

    // Interleave: reconstruct coefficient ordering
    for i in 0..hn {
        f[2 * i]     = f0[i]; // even coefficients
        f[2 * i + 1] = f1[i]; // odd coefficients
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_mul_identity() {
        // Multiplying by (1+0i) should give the same polynomial
        let logn = 9;
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut seed = 42u32;

        let a: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
        let mut one = vec![0.0f64; n];
        for i in 0..hn { one[i] = 1.0; } // re=1, im=0

        let mut c = vec![0.0f64; n];
        poly_mul_fft(&mut c, &a, &one, logn);

        for i in 0..n {
            assert!(close(a[i], c[i], 1e-14), "mul identity failed at {i}");
        }
    }

    #[test]
    fn test_adj_involution() {
        // conj(conj(a)) == a
        let logn = 9;
        let n = 1usize << logn;
        let mut seed = 43u32;

        let a: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
        let mut b = vec![0.0f64; n];
        let mut c = vec![0.0f64; n];
        poly_adj_fft(&mut b, &a, logn);
        poly_adj_fft(&mut c, &b, logn);

        for i in 0..n {
            assert!(close(a[i], c[i], 1e-14), "adj involution failed at {i}");
        }
    }

    #[test]
    fn test_split_merge_roundtrip() {
        for logn in 2..=10 {
            let n = 1usize << logn;
            let hn = n >> 1;
            let mut seed = 100u32 + logn as u32;

            let f: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
            let mut f0 = vec![0.0f64; hn];
            let mut f1 = vec![0.0f64; hn];
            poly_split_fft(&mut f0, &mut f1, &f, logn);

            let mut merged = vec![0.0f64; n];
            poly_merge_fft(&mut merged, &f0, &f1, logn);

            for i in 0..n {
                assert!(close(f[i], merged[i], 1e-10),
                    "split/merge roundtrip failed at logn={logn} i={i}: {} vs {}", f[i], merged[i]);
            }
        }
    }

    #[test]
    fn test_norm_matches_manual() {
        let logn = 9;
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut seed = 44u32;

        let a: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
        let mut norm_result = vec![0.0f64; n];
        poly_norm_fft(&mut norm_result, &a, logn);

        for i in 0..hn {
            let expected = a[i] * a[i] + a[i + hn] * a[i + hn];
            assert!(close(norm_result[i], expected, 1e-12),
                "norm mismatch at {i}: {} vs {}", norm_result[i], expected);
            assert!(close(norm_result[i + hn], 0.0, 1e-14),
                "norm imaginary not zero at {i}");
        }
    }

    #[test]
    fn test_inv_roundtrip() {
        let logn = 9;
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut seed = 45u32;

        let mut a: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();
        // Ensure no near-zero complex values
        for i in 0..hn {
            if a[i].abs() < 1.0 { a[i] += 10.0; }
            if a[i + hn].abs() < 1.0 { a[i + hn] += 10.0; }
        }

        let mut inv_a = vec![0.0f64; n];
        poly_inv_fft(&mut inv_a, &a, logn);

        let mut product = vec![0.0f64; n];
        poly_mul_fft(&mut product, &a, &inv_a, logn);

        // Product should be (1+0i) for each element
        for i in 0..hn {
            assert!(close(product[i], 1.0, 1e-10),
                "inv roundtrip re at {i}: {} vs 1.0", product[i]);
            assert!(product[i + hn].abs() < 1e-8,
                "inv roundtrip im at {i}: {} vs 0.0", product[i + hn]);
        }
    }

    #[test]
    fn test_fft_forward_inverse_roundtrip() {
        for logn in 1..=10 {
            let n = 1usize << logn;
            let mut seed = 700u32 + logn as u32;

            // Generate random real polynomial coefficients
            let original: Vec<f64> = (0..n).map(|_| rand_f64(&mut seed)).collect();

            // Forward FFT
            let mut f = original.clone();
            fft_forward(&mut f, logn);

            // Inverse FFT
            fft_inverse(&mut f, logn);

            // Should recover the original
            for i in 0..n {
                assert!(close(original[i], f[i], 1e-10),
                    "FFT roundtrip failed at logn={logn} i={i}: {} vs {}",
                    original[i], f[i]);
            }
        }
    }

    #[test]
    fn test_fft_forward_multiplication() {
        // Verify: FFT domain pointwise multiply = negacyclic polynomial product
        // (a0 + a1·x) · (b0 + b1·x) mod (x² + 1) = (a0·b0 - a1·b1) + (a0·b1 + a1·b0)·x
        let a_coeffs = [3.0, 2.0];
        let b_coeffs = [5.0, 7.0];
        // Expected: (15 - 14) + (21 + 10)x = 1 + 31x
        let expected = [1.0, 31.0];

        let mut a_fft = a_coeffs.to_vec();
        let mut b_fft = b_coeffs.to_vec();
        fft_forward(&mut a_fft, 1);
        fft_forward(&mut b_fft, 1);

        // Pointwise complex multiply in FFT domain
        let mut c_fft = vec![0.0; 2];
        poly_mul_fft(&mut c_fft, &a_fft, &b_fft, 1);

        // Inverse FFT to get result
        fft_inverse(&mut c_fft, 1);

        for i in 0..2 {
            assert!(close(expected[i], c_fft[i], 1e-10),
                "FFT mul test failed at {i}: {} vs {}", expected[i], c_fft[i]);
        }
    }
}
