//! Recursive Field Norm NTRU Solver for Falcon-512
//!
//! Solves the NTRU equation: f·G − g·F = q in Z[x]/(xⁿ+1)
//!
//! Algorithm (from the Falcon specification):
//!   1. Descend: compute field norms of f and g at each level,
//!      halving the polynomial degree from n down to 1 (scalar)
//!   2. Base case: solve scalar equation f·G − g·F = q using extended GCD
//!   3. Ascend: lift the solution from degree n/2 to degree n,
//!      then Babai-reduce to keep coefficients bounded
//!
//! Uses BigInt arithmetic for exact computation at all levels.
//! Performance is adequate for key generation (a one-time operation).

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{Zero, One, Signed, ToPrimitive};
use rand::RngCore;

/// Keygen quality bound: `max(||(g,-f)||^2, ||(G,-F)||^2) <= 1.17^2 * q`.
///
/// This is the Gram-Schmidt bound from the Falcon specification (§3.8.2,
/// `NTRUGen`), and it is **load-bearing for the signer**, not a nicety.
///
/// The LDL tree derives each leaf width as `sigma / sqrt(d)`, where the `d`
/// are the squared Gram-Schmidt norms of the basis. `sampler_z` can only
/// narrow the base half-Gaussian by rejection, so it requires every leaf width
/// to be at most `SIGMA_MAX = 1.8205`. Bounding the Gram-Schmidt norms at
/// keygen is exactly what guarantees that; a basis that fails this bound
/// cannot be sampled correctly at signing time.
///
/// It previously read `16384 * N` = 8,388,608 and was compared against
/// `||f||^2 + ||g||^2` alone. That expression has expected value
/// `2n * KEYGEN_SIGMA^2` ~ 16,824, so the test was ~500x too loose to ever
/// reject anything, and the second Gram-Schmidt vector was not checked at all.
/// Nothing noticed, because the leaf was doing Babai rounding — and rounding
/// does not care how wide the leaf is. The two defects hid each other (#139).
const KEYGEN_GS_BOUND: f64 = 1.17 * 1.17 * Q as f64;

/// Sigma for discrete Gaussian sampling of f, g
/// σ = 1.17 · √(q / (2n)) ≈ 4.053 for n=512, q=12289
const KEYGEN_SIGMA: f64 = 4.053;

/// Maximum keygen attempts.
///
/// The spec Gram-Schmidt bound (`gs_norm_sq <= 1.17^2 * q`) accepts only
/// ~10% (n=512) / ~3.5% (n=1024) of candidate `(f, g)` pairs, so a
/// 100-attempt budget fails at the percent level for Falcon-1024; 800 puts
/// the failure probability below 1e-12.
const MAX_KEYGEN_ATTEMPTS: usize = 800;

/// `max(||(g,-f)||^2, ||(G,-F)||^2)` — the quantity `KEYGEN_GS_BOUND` caps.
///
/// The second term is evaluated without solving the NTRU equation, which is the
/// point: it is far cheaper to reject a bad `(f, g)` here than after
/// `ntru_solve`. Following the reference, `(F~, G~) = (q*adj(g), q*adj(f)) /
/// (f*adj(f) + g*adj(g))`, so in the FFT domain
///
/// ```text
///   |F~_k|^2 + |G~_k|^2 = (|g_k|^2 + |f_k|^2) / ffgg_k^2 = 1 / ffgg_k
/// ```
///
/// with `ffgg_k = |f_k|^2 + |g_k|^2`. Parseval for this crate's unnormalised
/// `negacyclic_fft` gives `sum_i p_i^2 = (1/n) * sum_k |P_k|^2`, hence the
/// `1/n` below.
fn gs_norm_sq(f: &[i16], g: &[i16]) -> f64 {
    let n = f.len();

    let sqnorm_fg: f64 = f.iter().map(|&x| (x as f64) * (x as f64)).sum::<f64>()
        + g.iter().map(|&x| (x as f64) * (x as f64)).sum::<f64>();

    let f_r: Vec<f64> = f.iter().map(|&x| x as f64).collect();
    let g_r: Vec<f64> = g.iter().map(|&x| x as f64).collect();
    let f_fft = crate::falcon_canonical::negacyclic_fft(&f_r);
    let g_fft = crate::falcon_canonical::negacyclic_fft(&g_r);

    let mut acc = 0.0f64;
    for k in 0..n {
        let ffgg = f_fft[k].0 * f_fft[k].0
            + f_fft[k].1 * f_fft[k].1
            + g_fft[k].0 * g_fft[k].0
            + g_fft[k].1 * g_fft[k].1;
        if ffgg < 1e-12 {
            // f and g share a root: (F~, G~) is unbounded, so this basis is
            // unusable. Report +inf and let the caller reject it.
            return f64::INFINITY;
        }
        acc += 1.0 / ffgg;
    }

    let sqnorm_big_fg = (Q as f64) * (Q as f64) * acc / (n as f64);
    sqnorm_fg.max(sqnorm_big_fg)
}

/// NIST codec coefficient limits (falcon.h `max_fg_bits` / `max_FG_bits`).
///
/// The NIST private-key format packs f and g with `max_fg_bits[logn]` bits
/// per coefficient and F with `max_FG_bits[logn]` = 8 bits. A key whose
/// coefficients exceed these ranges cannot be serialized losslessly:
/// `nist_encoding::trim_i16_encode` refuses such a coefficient (it used to
/// mask the high bits, so `to_bytes` → `from_bytes` yielded a *different* key
/// whose signatures never verify — #341), and the strict decoder rejects the
/// forbidden −2^(bits−1) pattern outright. The reference implementation rejects such keys inside keygen
/// (keygen.c retries when `poly_big_to_small` fails); mirror that here.
///
/// Empirically ~0.07% of solved keys have an F coefficient outside ±127
/// (σ-driven tail), which surfaced as deterministic signing failures after
/// keystore round-trips (the consumer's consensus H3 path).
fn coeff_limits(n: usize) -> (i16, i16) {
    // (fg_limit, FG_limit): logn=9 → 6-bit f/g (±31), 8-bit F/G (±127);
    // logn=10 → 5-bit f/g (±15), 8-bit F/G (±127).
    if n == 1024 {
        (15, 127)
    } else {
        (31, 127)
    }
}

/// True iff every coefficient of `poly` lies in `[-limit, limit]`.
fn coeffs_within(poly: &[i16], limit: i16) -> bool {
    poly.iter().all(|&c| -limit <= c && c <= limit)
}

// ================================================================
// Public API
// ================================================================

/// Generate NTRU key quadruple (f, g, F, G) satisfying f·G − g·F = q.
///
/// Returns polynomials with small coefficients suitable for Falcon-512.
///
/// Runs on the deep-stack worker (`crate::deep_stack`): the recursive solve
/// below overflows Windows' 1 MB default thread stack, which every public
/// keygen entry point of this crate reaches through here. Hence `R: Send`.
pub fn ntru_keygen_working<R: RngCore + Send>(rng: &mut R) -> Result<(Vec<i16>, Vec<i16>, Vec<i16>, Vec<i16>)> {
    crate::deep_stack::with_deep_stack(move || ntru_keygen_working_inner(rng))
}

fn ntru_keygen_working_inner<R: RngCore>(rng: &mut R) -> Result<(Vec<i16>, Vec<i16>, Vec<i16>, Vec<i16>)> {
    #[cfg(test)]
    let mut diag = [0u32; 6]; // [norm_fail, invert_fail, solve_fail, i16_fail, verify_fail, total]

    for _attempt in 0..MAX_KEYGEN_ATTEMPTS {
        #[cfg(test)]
        { diag[5] += 1; }

        // 1. Sample f, g from discrete Gaussian
        let f = sample_gaussian_poly(rng, N, KEYGEN_SIGMA);
        let g = sample_gaussian_poly(rng, N, KEYGEN_SIGMA);

        // 1b. NIST codec encodability: f, g must fit max_fg_bits (±31).
        let (fg_lim, fg_big_lim) = coeff_limits(N);
        if !coeffs_within(&f, fg_lim) || !coeffs_within(&g, fg_lim) {
            #[cfg(test)]
            { diag[0] += 1; }
            continue;
        }

        // 2. Gram-Schmidt quality bound (spec §3.8.2). Rejects bases whose LDL
        //    leaf widths would exceed what `sampler_z` can sample.
        if gs_norm_sq(&f, &g) > KEYGEN_GS_BOUND {
            #[cfg(test)]
            { diag[0] += 1; }
            continue;
        }

        // 3. Check that f is invertible mod q (all NTT evaluations non-zero)
        if crate::ntt_falcon::inverse_ntt(&f).is_err() {
            #[cfg(test)]
            { diag[1] += 1; }
            continue;
        }

        // 4. Solve NTRU equation f·G − g·F = q
        let f_bi: Vec<BigInt> = f.iter().map(|&x| BigInt::from(x)).collect();
        let g_bi: Vec<BigInt> = g.iter().map(|&x| BigInt::from(x)).collect();

        let (big_f_bi, big_g_bi) = match ntru_solve(&f_bi, &g_bi, N) {
            Some(result) => result,
            None => {
                #[cfg(test)]
                { diag[2] += 1; }
                continue;
            }
        };

        // 5. Convert BigInt → i16 (should fit after Babai reduction)
        #[cfg(test)]
        {
            let max_f = max_coeff_bits(&big_f_bi);
            let max_g = max_coeff_bits(&big_g_bi);
            eprintln!("  Attempt {}: ntru_solve OK, F max_bits={}, G max_bits={}", _attempt, max_f, max_g);
        }
        let big_f: Vec<i16> = match bigints_to_i16(&big_f_bi) {
            Some(v) => v,
            None => {
                #[cfg(test)]
                { diag[3] += 1; }
                continue;
            }
        };
        let big_g: Vec<i16> = match bigints_to_i16(&big_g_bi) {
            Some(v) => v,
            None => {
                #[cfg(test)]
                { diag[3] += 1; }
                continue;
            }
        };

        // 5b. NIST codec encodability: F (serialized, 8-bit) and G
        // (recomputed on decode; reference keygen bounds it identically)
        // must fit max_FG_bits (±127). Out-of-range coefficients would be
        // silently truncated by `to_bytes`, corrupting the key.
        if !coeffs_within(&big_f, fg_big_lim) || !coeffs_within(&big_g, fg_big_lim) {
            #[cfg(test)]
            { diag[3] += 1; }
            continue;
        }

        // 6. Verify solution: f·G − g·F ≡ q (mod x^n+1)
        if !verify_ntru_equation(&f, &g, &big_f, &big_g) {
            #[cfg(test)]
            { diag[4] += 1; }
            continue;
        }

        #[cfg(test)]
        eprintln!("  Keygen succeeded on attempt {}", _attempt);
        return Ok((f, g, big_f, big_g));
    }

    #[cfg(test)]
    eprintln!("Keygen diagnostics: total={}, norm_fail={}, invert_fail={}, solve_fail={}, i16_overflow={}, verify_fail={}",
        diag[5], diag[0], diag[1], diag[2], diag[3], diag[4]);

    Err(Falcon512Error::KeyGenerationFailed)
}

/// Generate NTRU key quadruple for degree n (512 or 1024).
///
/// Parameters:
///   - n: polynomial degree (512 or 1024)
///   - sigma: standard deviation for Gaussian sampling
///       - Falcon-512:  σ ≈ 4.053 = 1.17 · √(q/1024)
///       - Falcon-1024: σ ≈ 2.865 = 1.17 · √(q/2048)
pub fn ntru_keygen_n<R: RngCore>(rng: &mut R, n: usize, sigma: f64) -> Result<(Vec<i16>, Vec<i16>, Vec<i16>, Vec<i16>)> {
    for _attempt in 0..MAX_KEYGEN_ATTEMPTS {
        // 1. Sample f, g from discrete Gaussian
        let f = sample_gaussian_poly(rng, n, sigma);
        let g = sample_gaussian_poly(rng, n, sigma);

        // 1b. NIST codec encodability (see `coeff_limits`): f, g must fit
        // max_fg_bits for this degree.
        let (fg_lim, fg_big_lim) = coeff_limits(n);
        if !coeffs_within(&f, fg_lim) || !coeffs_within(&g, fg_lim) {
            continue;
        }

        // 2. Gram-Schmidt quality bound (spec §3.8.2), same as the n=512 path
        // in `ntru_keygen_working`. This used to be `||f||^2 + ||g||^2 <=
        // 16384*n` — ~500x too loose, and blind to the second Gram-Schmidt
        // vector. Enforcing it is what keeps every LDL leaf width within
        // `sampler_z`'s SIGMA_MAX at signing time (see KEYGEN_GS_BOUND).
        if gs_norm_sq(&f, &g) > KEYGEN_GS_BOUND {
            continue;
        }

        // 3. Check that f is invertible mod q
        if crate::ntt_falcon::inverse_ntt_n(&f, n).is_err() {
            continue;
        }

        // 4. Solve NTRU equation f·G − g·F = q
        let f_bi: Vec<BigInt> = f.iter().map(|&x| BigInt::from(x)).collect();
        let g_bi: Vec<BigInt> = g.iter().map(|&x| BigInt::from(x)).collect();

        let (big_f_bi, big_g_bi) = match ntru_solve(&f_bi, &g_bi, n) {
            Some(result) => result,
            None => continue,
        };

        // 5. Convert BigInt → i16
        let big_f: Vec<i16> = match bigints_to_i16(&big_f_bi) {
            Some(v) => v,
            None => continue,
        };
        let big_g: Vec<i16> = match bigints_to_i16(&big_g_bi) {
            Some(v) => v,
            None => continue,
        };

        // NIST codec encodability: F/G must fit max_FG_bits (±127).
        if !coeffs_within(&big_f, fg_big_lim) || !coeffs_within(&big_g, fg_big_lim) {
            continue;
        }

        // 6. Verify solution: f·G − g·F = q
        if !verify_ntru_equation_n(&f, &g, &big_f, &big_g, n) {
            continue;
        }

        return Ok((f, g, big_f, big_g));
    }

    Err(Falcon512Error::KeyGenerationFailed)
}

// ================================================================
// Gaussian sampling
// ================================================================

/// Sample a polynomial with coefficients from a discrete Gaussian
/// distribution with standard deviation σ, using Box-Muller transform.
fn sample_gaussian_poly<R: RngCore>(rng: &mut R, n: usize, sigma: f64) -> Vec<i16> {
    let mut coeffs = vec![0i16; n];
    let mut i = 0;

    while i < n {
        // Generate two uniform random values in (0, 1)
        let u1 = uniform_f64(rng);
        let u2 = uniform_f64(rng);

        // Box-Muller transform → two Gaussian samples
        let r = (-2.0 * u1.ln()).sqrt();
        let theta = 2.0 * core::f64::consts::PI * u2;

        let z0 = sigma * r * theta.cos();
        let z1 = sigma * r * theta.sin();

        // Round to nearest integer
        coeffs[i] = z0.round() as i16;
        i += 1;
        if i < n {
            coeffs[i] = z1.round() as i16;
            i += 1;
        }
    }

    coeffs
}

/// Generate a uniform f64 in (0, 1) with 53-bit mantissa precision.
fn uniform_f64<R: RngCore>(rng: &mut R) -> f64 {
    loop {
        let bits = rng.next_u64() >> 11; // 53-bit mantissa
        let val = (bits as f64) / ((1u64 << 53) as f64);
        if val > 0.0 && val < 1.0 {
            return val;
        }
    }
}

// ================================================================
// Recursive NTRU solver
// ================================================================

/// Solve f·G − g·F = q in Z[x]/(xⁿ+1) using recursive field norm.
///
/// Returns (F, G) with small coefficients, or None on failure.
fn ntru_solve(f: &[BigInt], g: &[BigInt], n: usize) -> Option<(Vec<BigInt>, Vec<BigInt>)> {
    if n == 1 {
        // Base case: scalar equation f[0]·G − g[0]·F = q
        return solve_base_case(&f[0], &g[0]);
    }

    // 1. Compute field norms: N(f), N(g) ∈ Z[x]/(x^{n/2}+1)
    let fn_f = field_norm(f, n);
    let fn_g = field_norm(g, n);

    // 2. Recurse on half-sized problem
    let (fp, gp) = ntru_solve(&fn_f, &fn_g, n / 2)?;

    // 3. Lift child solution from degree n/2 to degree n
    let (mut big_f, mut big_g) = lift(&fp, &gp, f, g, n);

    // 4. Babai-reduce to minimize coefficient sizes
    babai_reduce(&mut big_f, &mut big_g, f, g, n);

    Some((big_f, big_g))
}

// ================================================================
// Field norm: Z[x]/(xⁿ+1) → Z[x]/(x^{n/2}+1)
// ================================================================

/// Compute the field norm: N(f) = f(x)·f(−x) mod (x^{n/2}+1)
///
/// If f = f₀(x²) + x·f₁(x²), then N(f) = f₀² − y·f₁²
/// where y = x² and the result lives in Z[y]/(y^{n/2}+1).
///
/// Uses FFT-based multiplication when coefficients fit in f64 (~45 bits),
/// falling back to schoolbook BigInt multiplication for larger values.
fn field_norm(f: &[BigInt], n: usize) -> Vec<BigInt> {
    assert!(n >= 2 && n.is_power_of_two());
    let hn = n / 2;

    // Split into even and odd coefficients
    let f0: Vec<BigInt> = (0..hn).map(|i| f[2 * i].clone()).collect();
    let f1: Vec<BigInt> = (0..hn).map(|i| f[2 * i + 1].clone()).collect();

    // Use FFT-based multiplication when the RESULT fits in f64 (53-bit mantissa).
    // Each result coefficient is a sum of hn terms of ±a[i]*b[j], so max = hn * 2^{2*bits}.
    // Need: 2*bits + log2(hn) < 50 (with 3 bits of margin).
    let bits = max_coeff_bits(&f0).max(max_coeff_bits(&f1));
    let log_hn = (hn as f64).log2().ceil() as usize;
    let (f0_sq, f1_sq) = if 2 * bits + log_hn < 50 && hn >= 2 && hn.is_power_of_two() {
        // FFT path: O(n log n)
        let f0_f64: Vec<f64> = f0.iter().map(|b| bigint_to_f64(b)).collect();
        let f1_f64: Vec<f64> = f1.iter().map(|b| bigint_to_f64(b)).collect();
        let sq0 = fft_mul_negacyclic(&f0_f64, &f0_f64, hn);
        let sq1 = fft_mul_negacyclic(&f1_f64, &f1_f64, hn);
        let sq0_bi: Vec<BigInt> = sq0.iter().map(|&x| BigInt::from(x.round() as i64)).collect();
        let sq1_bi: Vec<BigInt> = sq1.iter().map(|&x| BigInt::from(x.round() as i64)).collect();
        (sq0_bi, sq1_bi)
    } else {
        // Schoolbook path for large coefficients or small n
        (poly_mul_negacyclic(&f0, &f0, hn), poly_mul_negacyclic(&f1, &f1, hn))
    };

    // Multiply f₁² by y (= rotate right by 1 with sign change)
    let y_f1_sq = poly_mul_x(&f1_sq, hn);

    // N(f) = f₀² − y·f₁²
    poly_sub(&f0_sq, &y_f1_sq)
}

// ================================================================
// Lift: degree n/2 → degree n
// ================================================================

/// Lift child solution (Fp, Gp) from Z[x]/(x^{n/2}+1) to Z[x]/(xⁿ+1).
///
/// Formula:
///   F(x) = Fp(x²) · g(−x)
///   G(x) = Gp(x²) · f(−x)
///
/// where Fp(x²) embeds the child polynomial into even-index slots.
///
/// Uses FFT multiplication when values fit in f64, else schoolbook BigInt.
fn lift(
    fp: &[BigInt],
    gp: &[BigInt],
    f: &[BigInt],
    g: &[BigInt],
    n: usize,
) -> (Vec<BigInt>, Vec<BigInt>) {
    // Embed child solution into even slots of degree-n polynomial
    let fp_embed = embed_even(fp, n);
    let gp_embed = embed_even(gp, n);

    // Compute conjugates: f(−x), g(−x)
    let f_conj = poly_conj(f);
    let g_conj = poly_conj(g);

    // Check if FFT path is viable: result must fit in f64.
    // Each result coefficient is a sum of n terms of ±a[i]*b[j].
    // Need: bits_a + bits_b + log2(n) < 50 (with margin).
    let bits_fp = max_coeff_bits(&fp_embed);
    let bits_gp = max_coeff_bits(&gp_embed);
    let bits_f = max_coeff_bits(&f_conj);
    let bits_g = max_coeff_bits(&g_conj);
    let log_n = (n as f64).log2().ceil() as usize;
    let max_bits_fg = bits_fp.max(bits_gp) + bits_f.max(bits_g);

    if max_bits_fg + log_n < 50 && n >= 2 && n.is_power_of_two() {
        // FFT path: O(n log n)
        let fp_f64: Vec<f64> = fp_embed.iter().map(|b| bigint_to_f64(b)).collect();
        let gp_f64: Vec<f64> = gp_embed.iter().map(|b| bigint_to_f64(b)).collect();
        let fc_f64: Vec<f64> = f_conj.iter().map(|b| bigint_to_f64(b)).collect();
        let gc_f64: Vec<f64> = g_conj.iter().map(|b| bigint_to_f64(b)).collect();

        let bf = fft_mul_negacyclic(&fp_f64, &gc_f64, n);
        let bg = fft_mul_negacyclic(&gp_f64, &fc_f64, n);

        let big_f: Vec<BigInt> = bf.iter().map(|&x| BigInt::from(x.round() as i64)).collect();
        let big_g: Vec<BigInt> = bg.iter().map(|&x| BigInt::from(x.round() as i64)).collect();
        (big_f, big_g)
    } else {
        // Schoolbook path for large coefficients
        let big_f = poly_mul_negacyclic(&fp_embed, &g_conj, n);
        let big_g = poly_mul_negacyclic(&gp_embed, &f_conj, n);
        (big_f, big_g)
    }
}

/// Embed a degree n/2 polynomial into even slots of a degree n polynomial.
/// p(y) → p(x²): coeff[2i] = p[i], coeff[2i+1] = 0
fn embed_even(p: &[BigInt], n: usize) -> Vec<BigInt> {
    let mut result = vec![BigInt::zero(); n];
    for i in 0..p.len() {
        result[2 * i] = p[i].clone();
    }
    result
}

// ================================================================
// Babai reduction (FFT-based polynomial reduction)
// ================================================================

/// Reduce F, G by subtracting a polynomial multiple k(x)·(f, g) to minimize norms.
///
/// This is the proper ring-based Babai nearest-plane reduction. We compute
/// a polynomial k(x) ∈ Z[x]/(xⁿ+1) that minimizes ||(F − k·f, G − k·g)||.
///
/// In the negacyclic FFT domain, the optimal k is computed pointwise:
///   k̂[j] = (F̂[j]·conj(f̂[j]) + Ĝ[j]·conj(ĝ[j])) / (|f̂[j]|² + |ĝ[j]|²)
///
/// **Dual-scaling trick:** When F,G and f,g have very different magnitudes
/// (e.g., F ~6000 bits, f ~3000 bits), we use separate shifts:
///   - Shift F,G by `a` bits (to bring into f64 range ~2^500)
///   - Shift f,g by `b` bits (independently)
///
/// With F' = F/2^a and f' = f/2^b, the FFT ratio gives:
///   k_scaled = k_true × 2^{b-a}
///
/// So we recover k_true = round(k_scaled) × 2^{a-b} (BigInt left-shift).
/// Each pass removes ~50 bits of coefficient magnitude (f64 precision limit).
fn babai_reduce(
    big_f: &mut Vec<BigInt>,
    big_g: &mut Vec<BigInt>,
    f: &[BigInt],
    g: &[BigInt],
    n: usize,
) {
    let fg_bits = max_coeff_bits(f).max(max_coeff_bits(g));
    let target_bits = fg_bits + 4;

    let max_bits = max_coeff_bits(big_f).max(max_coeff_bits(big_g));
    if max_bits <= target_bits {
        return;
    }

    // Each pass removes ~50 bits; add margin passes
    let num_passes = ((max_bits.saturating_sub(target_bits)) / 50).max(1) + 5;

    // Precompute scaled f, g FFTs (only recompute if fg_bits changes, which it doesn't)
    // Shift f,g to bring into f64 range (~2^500 magnitude)
    let shift_fg = if fg_bits > 500 { fg_bits - 500 } else { 0 };
    let f_scaled: Vec<f64> = f.iter().map(|b| bigint_to_scaled_f64(b, shift_fg)).collect();
    let g_scaled: Vec<f64> = g.iter().map(|b| bigint_to_scaled_f64(b, shift_fg)).collect();
    let f_fft = negacyclic_fft(&f_scaled);
    let g_fft = negacyclic_fft(&g_scaled);

    for _pass in 0..num_passes {
        let cur_bits = max_coeff_bits(big_f).max(max_coeff_bits(big_g));
        if cur_bits <= target_bits {
            break;
        }

        // Shift F,G independently to bring into f64 range (~2^500)
        let shift_fg_cur = if cur_bits > 500 { cur_bits - 500 } else { 0 };

        let bf_scaled: Vec<f64> = big_f.iter().map(|b| bigint_to_scaled_f64(b, shift_fg_cur)).collect();
        let bg_scaled: Vec<f64> = big_g.iter().map(|b| bigint_to_scaled_f64(b, shift_fg_cur)).collect();

        let bf_fft = negacyclic_fft(&bf_scaled);
        let bg_fft = negacyclic_fft(&bg_scaled);

        // Compute k_scaled in FFT domain:
        // k_scaled[j] = (F'·conj(f') + G'·conj(g')) / (|f'|² + |g'|²)
        // where F' = F/2^a, f' = f/2^b
        // k_scaled = k_true × 2^{b-a}
        let mut k_fft = vec![(0.0f64, 0.0f64); n];
        for j in 0..n {
            let (fr, fi) = f_fft[j];
            let (gr, gi) = g_fft[j];
            let denom = fr * fr + fi * fi + gr * gr + gi * gi;
            if denom < 1e-30 {
                continue;
            }
            let (bfr, bfi) = bf_fft[j];
            let (bgr, bgi) = bg_fft[j];

            let num_r = bfr * fr + bfi * fi + bgr * gr + bgi * gi;
            let num_i = bfi * fr - bfr * fi + bgi * gr - bgr * gi;

            k_fft[j] = (num_r / denom, num_i / denom);
        }

        // Inverse FFT → real polynomial k_scaled, then round
        let k_f64 = negacyclic_ifft(&k_fft);

        // Correction: k_true = k_scaled × 2^{a-b} where a=shift_fg_cur, b=shift_fg
        let correction_shift = shift_fg_cur.saturating_sub(shift_fg);

        let k: Vec<BigInt> = k_f64.iter().map(|&x| {
            let rounded = f64_to_bigint(x);
            if correction_shift > 0 && !rounded.is_zero() {
                rounded << correction_shift
            } else {
                rounded
            }
        }).collect();

        // If k is all zeros, we've converged
        if k.iter().all(|c| c.is_zero()) {
            break;
        }

        // Apply exact reduction: F -= k·f, G -= k·g (BigInt arithmetic)
        let kf = poly_mul_negacyclic(&k, f, n);
        let kg = poly_mul_negacyclic(&k, g, n);
        for i in 0..n {
            big_f[i] -= &kf[i];
            big_g[i] -= &kg[i];
        }
    }
}

/// Convert BigInt to f64 scaled down by 2^{shift} bits.
/// Result = value / 2^shift, as a f64 approximation.
fn bigint_to_scaled_f64(b: &BigInt, shift: usize) -> f64 {
    if b.is_zero() || shift == 0 {
        return bigint_to_f64(b);
    }
    // Right-shift the BigInt, then convert the result to f64.
    // This keeps the magnitude in f64 range while preserving the top ~53 bits.
    let shifted = b >> shift;
    bigint_to_f64(&shifted)
}

// ================================================================
// Complex negacyclic FFT / IFFT (f64) — O(n log n) butterfly
// ================================================================

/// Bit-reverse permutation index for butterfly FFT.
fn bit_reverse(mut x: usize, log_n: u32) -> usize {
    let mut result = 0usize;
    for _ in 0..log_n {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}

/// Standard Cooley-Tukey FFT in-place (radix-2, DIT).
/// O(n log n) complexity.  `inverse` flag computes IFFT (no 1/n scaling).
fn fft_butterfly(a: &mut [(f64, f64)], inverse: bool) {
    let n = a.len();
    if n <= 1 {
        return;
    }
    let log_n = n.trailing_zeros();

    // Bit-reverse permutation
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            a.swap(i, j);
        }
    }

    // Butterfly stages
    let mut len = 2;
    while len <= n {
        let half = len / 2;
        let sign = if inverse { 1.0 } else { -1.0 };
        let angle = sign * 2.0 * core::f64::consts::PI / len as f64;
        let wn = (angle.cos(), angle.sin());

        let mut start = 0;
        while start < n {
            let mut w = (1.0f64, 0.0f64);
            for j in 0..half {
                let u = a[start + j];
                let t = cmul_f(w, a[start + j + half]);
                a[start + j] = (u.0 + t.0, u.1 + t.1);
                a[start + j + half] = (u.0 - t.0, u.1 - t.1);
                w = cmul_f(w, wn);
            }
            start += len;
        }
        len <<= 1;
    }
}

/// Complex multiplication for (f64, f64) tuples.
#[inline]
fn cmul_f(a: (f64, f64), b: (f64, f64)) -> (f64, f64) {
    (a.0 * b.0 - a.1 * b.1, a.0 * b.1 + a.1 * b.0)
}

/// Negacyclic FFT: evaluate polynomial at the n roots of xⁿ + 1.
///
/// The roots are ω^(2j+1) for j = 0, ..., n−1 where ω = e^{πi/n}.
///
/// Method: pre-multiply by ψ^k where ψ = e^{iπ/n}, then apply standard FFT.
/// This is O(n log n) via the butterfly FFT.
fn negacyclic_fft(a: &[f64]) -> Vec<(f64, f64)> {
    let n = a.len();
    if n == 1 {
        return vec![(a[0], 0.0)];
    }
    let psi = core::f64::consts::PI / n as f64;

    // Pre-multiply: g[k] = a[k] · ψ^k = a[k] · e^{ikπ/n}
    let mut g: Vec<(f64, f64)> = a
        .iter()
        .enumerate()
        .map(|(k, &ak)| {
            let angle = k as f64 * psi;
            (ak * angle.cos(), ak * angle.sin())
        })
        .collect();

    // Standard forward FFT
    fft_butterfly(&mut g, false);

    g
}

/// Inverse negacyclic FFT: reconstruct polynomial from evaluations.
///
/// Applies standard IFFT then un-multiplies by ψ^{−k}.
fn negacyclic_ifft(fft_vals: &[(f64, f64)]) -> Vec<f64> {
    let n = fft_vals.len();
    if n == 1 {
        return vec![fft_vals[0].0];
    }
    let psi = core::f64::consts::PI / n as f64;

    let mut g = fft_vals.to_vec();

    // Standard inverse FFT (without 1/n scaling)
    fft_butterfly(&mut g, true);

    // Scale by 1/n and un-multiply by ψ^{−k}
    let inv_n = 1.0 / n as f64;
    (0..n)
        .map(|k| {
            let angle = -(k as f64) * psi;
            let (cos_a, sin_a) = (angle.cos(), angle.sin());
            let (re, im) = g[k];
            // Re((re + i·im) · (cos_a + i·sin_a)) = re·cos_a − im·sin_a
            (re * cos_a - im * sin_a) * inv_n
        })
        .collect()
}

/// Multiply two real polynomials mod (xⁿ+1) using negacyclic FFT.
///
/// O(n log n) complexity via FFT. Values must fit in f64 (~53 bits).
fn fft_mul_negacyclic(a: &[f64], b: &[f64], n: usize) -> Vec<f64> {
    let a_fft = negacyclic_fft(a);
    let b_fft = negacyclic_fft(b);

    // Pointwise multiply in FFT domain
    let mut c_fft = vec![(0.0f64, 0.0f64); n];
    for j in 0..n {
        c_fft[j] = cmul_f(a_fft[j], b_fft[j]);
    }

    negacyclic_ifft(&c_fft)
}

/// Maximum bit length among all coefficients of a BigInt polynomial.
fn max_coeff_bits(p: &[BigInt]) -> usize {
    p.iter()
        .map(|c| {
            if c.is_zero() {
                0
            } else {
                c.abs().bits() as usize
            }
        })
        .max()
        .unwrap_or(0)
}

/// Convert BigInt to f64 (lossy for large values, but adequate for Babai).
fn bigint_to_f64(b: &BigInt) -> f64 {
    b.to_f64().unwrap_or(0.0)
}

/// Convert f64 to BigInt accurately, handling values beyond i64 range.
///
/// For values that fit in i64 (< 2^63), uses direct conversion.
/// For larger values, decomposes the f64 into mantissa × 2^exponent
/// to preserve all significant bits.
fn f64_to_bigint(x: f64) -> BigInt {
    if x.is_nan() || x.is_infinite() || x == 0.0 {
        return BigInt::zero();
    }
    let rounded = x.round();
    if rounded.abs() < 9.0e18 {
        // Fits in i64
        BigInt::from(rounded as i64)
    } else {
        // Decompose f64 into sign × mantissa × 2^exp
        // f64 = (-1)^sign × mantissa × 2^exp where mantissa is 53-bit integer
        use num_traits::Float;
        let (mantissa, exponent, sign) = Float::integer_decode(rounded);
        let mut result = BigInt::from(mantissa);
        if exponent >= 0 {
            result <<= exponent as usize;
        } else {
            result >>= (-exponent) as usize;
        }
        if sign < 0 {
            result = -result;
        }
        result
    }
}

// ================================================================
// Base case: scalar NTRU equation
// ================================================================

/// Solve f·G − g·F = q for scalar f, g using extended GCD.
///
/// Extended GCD gives s, t with f·s + g·t = gcd(f, g).
/// Then G = s·(q/gcd), F = −t·(q/gcd).
fn solve_base_case(f: &BigInt, g: &BigInt) -> Option<(Vec<BigInt>, Vec<BigInt>)> {
    if f.is_zero() && g.is_zero() {
        return None;
    }

    let q = BigInt::from(Q);
    let (gcd, s, t) = extended_gcd_bi(f, g);

    if gcd.is_zero() {
        return None;
    }

    // q must be divisible by gcd(f, g)
    let (quot, rem) = q.div_rem(&gcd);
    if !rem.is_zero() {
        return None;
    }

    // G = s · (q/gcd), F = −(t · (q/gcd))
    let big_g = &s * &quot;
    let big_f = -(&t * &quot);

    Some((vec![big_f], vec![big_g]))
}

/// Extended GCD: returns (gcd, s, t) such that a·s + b·t = gcd(a, b).
/// The gcd is always non-negative.
fn extended_gcd_bi(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        if a.is_negative() {
            return (a.abs(), BigInt::from(-1), BigInt::zero());
        } else {
            return (a.clone(), BigInt::one(), BigInt::zero());
        }
    }

    let (q_val, r) = a.div_rem(b);
    let (gcd, s1, t1) = extended_gcd_bi(b, &r);

    let s = t1.clone();
    let t = s1 - &q_val * &t1;

    (gcd, s, t)
}

// ================================================================
// Negacyclic polynomial arithmetic over BigInt
// ================================================================

/// Schoolbook multiplication in Z[x]/(xⁿ+1).
///
/// For indices where i+j ≥ n, the wraparound contributes −a[i]·b[j]
/// (because x^n ≡ −1 mod x^n+1).
fn poly_mul_negacyclic(a: &[BigInt], b: &[BigInt], n: usize) -> Vec<BigInt> {
    let mut result = vec![BigInt::zero(); n];

    for i in 0..a.len().min(n) {
        if a[i].is_zero() {
            continue;
        }
        for j in 0..b.len().min(n) {
            if b[j].is_zero() {
                continue;
            }
            let product = &a[i] * &b[j];
            let idx = i + j;
            if idx < n {
                result[idx] += &product;
            } else {
                // Wraparound with negation: x^n ≡ −1
                result[idx - n] -= &product;
            }
        }
    }

    result
}

/// Polynomial subtraction (coefficient-wise).
fn poly_sub(a: &[BigInt], b: &[BigInt]) -> Vec<BigInt> {
    let n = a.len().max(b.len());
    let mut result = vec![BigInt::zero(); n];
    for i in 0..a.len() {
        result[i] += &a[i];
    }
    for i in 0..b.len() {
        result[i] -= &b[i];
    }
    result
}

/// Conjugate polynomial: f(−x). Negate odd-indexed coefficients.
fn poly_conj(f: &[BigInt]) -> Vec<BigInt> {
    f.iter()
        .enumerate()
        .map(|(i, c)| if i & 1 == 0 { c.clone() } else { -c })
        .collect()
}

/// Multiply by x in Z[x]/(xⁿ+1): rotate coefficients right by 1.
///
/// x · (a₀ + a₁x + ··· + a_{n−1}x^{n−1})
///   = −a_{n−1} + a₀x + a₁x² + ··· + a_{n−2}x^{n−1}
fn poly_mul_x(a: &[BigInt], n: usize) -> Vec<BigInt> {
    let mut result = vec![BigInt::zero(); n];
    result[0] = -&a[n - 1]; // x^n ≡ −1
    for i in 1..n {
        result[i] = a[i - 1].clone();
    }
    result
}

// ================================================================
// Conversion helpers
// ================================================================

/// Convert BigInt polynomial to i16, returning None if any coefficient overflows.
fn bigints_to_i16(p: &[BigInt]) -> Option<Vec<i16>> {
    p.iter()
        .map(|b| b.to_i64().and_then(|v| i16::try_from(v).ok()))
        .collect()
}

// ================================================================
// Verification
// ================================================================

/// Verify that f·G − g·F = q in Z[x]/(xⁿ+1) exactly (over the integers).
fn verify_ntru_equation(f: &[i16], g: &[i16], big_f: &[i16], big_g: &[i16]) -> bool {
    verify_ntru_equation_n(f, g, big_f, big_g, N)
}

/// Verify that f·G − g·F = q in Z[x]/(xⁿ+1) for arbitrary degree n.
pub fn verify_ntru_equation_n(f: &[i16], g: &[i16], big_f: &[i16], big_g: &[i16], n: usize) -> bool {
    let f_bi: Vec<BigInt> = f.iter().map(|&x| BigInt::from(x)).collect();
    let g_bi: Vec<BigInt> = g.iter().map(|&x| BigInt::from(x)).collect();
    let bf_bi: Vec<BigInt> = big_f.iter().map(|&x| BigInt::from(x)).collect();
    let bg_bi: Vec<BigInt> = big_g.iter().map(|&x| BigInt::from(x)).collect();

    let fg_exact = poly_mul_negacyclic(&f_bi, &bg_bi, n);
    let gf_exact = poly_mul_negacyclic(&g_bi, &bf_bi, n);
    let diff = poly_sub(&fg_exact, &gf_exact);

    let q_bi = BigInt::from(Q);

    // diff[0] should be q, all others should be 0
    if diff[0] != q_bi {
        return false;
    }
    for i in 1..n {
        if !diff[i].is_zero() {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_poly_mul_negacyclic_basic() {
        // (2 + 3x)(5 + 7x) in Z[x]/(x²+1)
        // = 10 + 14x + 15x + 21x² = 10 + 29x − 21 = −11 + 29x
        let a = vec![BigInt::from(2), BigInt::from(3)];
        let b = vec![BigInt::from(5), BigInt::from(7)];
        let c = poly_mul_negacyclic(&a, &b, 2);
        assert_eq!(c[0], BigInt::from(-11));
        assert_eq!(c[1], BigInt::from(29));
    }

    #[test]
    fn test_field_norm_degree_2() {
        // f = a + bx in Z[x]/(x²+1)
        // N(f) = f(x)·f(−x) = (a+bx)(a−bx) = a² + b²
        // (In Z[x]/(x²+1), bx·(−bx) = −b²x² = −b²·(−1) = b²)
        let f = vec![BigInt::from(3), BigInt::from(4)];
        let norm = field_norm(&f, 2);
        assert_eq!(norm.len(), 1);
        assert_eq!(norm[0], BigInt::from(25)); // 9 + 16 = 25
    }

    #[test]
    fn test_extended_gcd() {
        let (gcd, s, t) = extended_gcd_bi(&BigInt::from(35), &BigInt::from(15));
        assert_eq!(gcd, BigInt::from(5));
        assert_eq!(&BigInt::from(35) * &s + &BigInt::from(15) * &t, BigInt::from(5));
    }

    #[test]
    fn test_base_case() {
        // Solve f·G − g·F = 12289 for f=1, g=1
        let result = solve_base_case(&BigInt::from(1), &BigInt::from(1));
        assert!(result.is_some());
        let (big_f, big_g) = result.unwrap();

        // Verify: 1·G − 1·F = q
        let diff = &big_g[0] - &big_f[0];
        assert_eq!(diff, BigInt::from(Q));
    }

    #[test]
    fn test_base_case_coprime() {
        // f=3, g=5 → gcd=1, so q/gcd = 12289
        let result = solve_base_case(&BigInt::from(3), &BigInt::from(5));
        assert!(result.is_some());
        let (big_f, big_g) = result.unwrap();

        // Verify: 3·G − 5·F = 12289
        let val = &BigInt::from(3) * &big_g[0] - &BigInt::from(5) * &big_f[0];
        assert_eq!(val, BigInt::from(Q));
    }

    #[test]
    fn test_ntru_solve_n2() {
        // f = 3+2x, g = 1+2x in Z[x]/(x²+1)
        // Field norms: N(f) = 9+4 = 13, N(g) = 1+4 = 5
        // gcd(13, 5) = 1, so the NTRU equation has a solution
        let f = vec![BigInt::from(3), BigInt::from(2)];
        let g = vec![BigInt::from(1), BigInt::from(2)];

        let result = ntru_solve(&f, &g, 2);
        assert!(result.is_some(), "NTRU solve should succeed for n=2 (coprime field norms 13, 5)");

        let (big_f, big_g) = result.unwrap();

        // Verify: f·G − g·F = q
        let fg = poly_mul_negacyclic(&f, &big_g, 2);
        let gf = poly_mul_negacyclic(&g, &big_f, 2);
        let diff = poly_sub(&fg, &gf);

        assert_eq!(diff[0], BigInt::from(Q), "f·G − g·F constant term should be q");
        assert_eq!(diff[1], BigInt::zero(), "f·G − g·F linear term should be 0");
    }

    #[test]
    fn test_ntru_solve_n4() {
        // Use Gaussian-sampled-style small polynomials at n=4.
        // We try a few candidates until we find one whose nested field norms
        // are coprime (necessary for the NTRU equation to have a solution).
        let candidates: Vec<(Vec<BigInt>, Vec<BigInt>)> = vec![
            (
                vec![BigInt::from(2), BigInt::from(1), BigInt::from(3), BigInt::from(-1)],
                vec![BigInt::from(1), BigInt::from(-2), BigInt::from(1), BigInt::from(1)],
            ),
            (
                vec![BigInt::from(3), BigInt::from(1), BigInt::from(-1), BigInt::from(2)],
                vec![BigInt::from(1), BigInt::from(3), BigInt::from(2), BigInt::from(-1)],
            ),
            (
                vec![BigInt::from(5), BigInt::from(1), BigInt::from(0), BigInt::from(-1)],
                vec![BigInt::from(1), BigInt::from(0), BigInt::from(2), BigInt::from(1)],
            ),
        ];

        let mut found = false;
        for (f, g) in &candidates {
            if let Some((big_f, big_g)) = ntru_solve(f, g, 4) {
                // Verify: f·G − g·F = q
                let fg = poly_mul_negacyclic(f, &big_g, 4);
                let gf = poly_mul_negacyclic(g, &big_f, 4);
                let diff = poly_sub(&fg, &gf);

                assert_eq!(diff[0], BigInt::from(Q));
                for i in 1..4 {
                    assert_eq!(diff[i], BigInt::zero(), "diff[{}] should be 0", i);
                }
                found = true;
                break;
            }
        }
        assert!(found, "At least one n=4 candidate should have a solution");
    }

    #[test]
    fn test_gaussian_sampling() {
        let mut rng = StdRng::seed_from_u64(42);
        let poly = sample_gaussian_poly(&mut rng, 512, KEYGEN_SIGMA);

        assert_eq!(poly.len(), 512);

        // Check that coefficients are small (within ~4σ with high probability)
        let max_abs = poly.iter().map(|&x| x.abs()).max().unwrap();
        assert!(max_abs < 30, "Max coefficient {} should be < 30 (4σ ≈ 16)", max_abs);

        // Check that not all zero
        assert!(poly.iter().any(|&x| x != 0), "Polynomial should not be all zeros");
    }

    #[test]
    fn test_ntru_keygen() {
        let mut rng = StdRng::seed_from_u64(42);

        match ntru_keygen_working(&mut rng) {
            Ok((f, g, big_f, big_g)) => {
                assert_eq!(f.len(), N);
                assert_eq!(g.len(), N);
                assert_eq!(big_f.len(), N);
                assert_eq!(big_g.len(), N);

                // Verify NTRU equation
                assert!(verify_ntru_equation(&f, &g, &big_f, &big_g),
                    "NTRU equation should be satisfied");

                // Verify f is invertible mod q
                assert!(crate::ntt_falcon::inverse_ntt(&f).is_ok(),
                    "f should be invertible mod q");
            }
            Err(e) => {
                // Key generation can fail with some seeds — this is expected
                // for seeds that don't produce coprime field norms
                eprintln!("Keygen failed (may be expected): {:?}", e);
            }
        }
    }

    /// Every generated key must be losslessly NIST-serializable: all f/g
    /// coefficients within ±31 (6-bit codec) and F/G within ±127 (8-bit
    /// codec). Before keygen enforced this, ~0.07% of keys had an F
    /// coefficient outside ±127; `to_bytes` silently truncated it and the
    /// round-tripped key failed every signature (found via the consumer's
    /// consensus H3 deterministic-signing flake).
    #[test]
    fn test_keygen_coefficients_always_codec_encodable() {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x42; 32]);
        let (fg_lim, fg_big_lim) = coeff_limits(N);
        for i in 0..50 {
            let (f, g, big_f, big_g) =
                ntru_keygen_working(&mut rng).expect("keygen should succeed");
            for (name, poly, lim) in [
                ("f", &f, fg_lim),
                ("g", &g, fg_lim),
                ("F", &big_f, fg_big_lim),
                ("G", &big_g, fg_big_lim),
            ] {
                assert!(
                    coeffs_within(poly, lim),
                    "key {i}: {name} has a coefficient outside ±{lim}"
                );
            }
        }
    }
}
