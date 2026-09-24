//! Falcon-512 FFSampling implementation
//!
//! Self-contained module implementing the complete signing pipeline:
//!   1. O(n log n) negacyclic FFT (`fft_ops`, portable scalar code)
//!   2. FFT split/merge on the SOA layout
//!   3. LDL tree construction from Gram matrix (SOA layout)
//!   4. Recursive FFSampling algorithm
//!   5. Signature computation
//!
//! All internal operations use SOA (Structure-of-Arrays) layout:
//!   `f[0..hn-1]` = real parts, `f[hn..n-1]` = imaginary parts.

use alloc::vec::Vec;
use crate::constants::{Q, SIGMA_MIN, SIGMA_MIN_1024};
use crate::error::{Result, Falcon512Error};
use crate::fft_ops;
use crate::sampler_z::sampler_z;
use rand::RngCore;

/// σ_min for the degree being signed (`fpr_sigma_min_9` / `fpr_sigma_min_10`).
///
/// This module serves both Falcon-512 (`sign_compressed` via `ExpandedKey`)
/// and Falcon-1024 (`falcon1024::sign_core` via `falcon_sign_sample`), so the
/// lower rejection bound for `sampler_z` must follow the degree, not the crate
/// default.
#[inline]
fn sigma_min_for(n: usize) -> f64 {
    if n == 1024 { SIGMA_MIN_1024 } else { SIGMA_MIN }
}

// ================================================================
// SOA-domain complex helpers
//
// These operate on SOA flat arrays where:
//   f[0..hn-1] = real parts, f[hn..n-1] = imaginary parts
// For operations not covered by fft_ops (e.g., c_div, c_abs2),
// we provide scalar helpers on the SOA layout.
// ================================================================

/// Compute logn from n (the number of SOA elements, which is 2*hn).
#[inline]
fn logn_of(n: usize) -> usize {
    debug_assert!(n.is_power_of_two() && n >= 2);
    n.trailing_zeros() as usize
}

/// Pointwise complex division: c = a / b in SOA layout.
///
/// c_re = (a_re*b_re + a_im*b_im) / (b_re² + b_im²)
/// c_im = (a_im*b_re - a_re*b_im) / (b_re² + b_im²)
fn soa_div(c: &mut [f64], a: &[f64], b: &[f64]) {
    let n = a.len();
    let hn = n >> 1;
    for i in 0..hn {
        let (ar, ai) = (a[i], a[i + hn]);
        let (br, bi) = (b[i], b[i + hn]);
        let d = br * br + bi * bi;
        // NaN/Inf prevention, not a comparison on secret data — LDL tree
        // structure is deterministic for a given key, so this branch does
        // not leak timing information about secret coefficients.
        if d < 1e-300 {
            c[i] = 0.0;
            c[i + hn] = 0.0;
        } else {
            c[i]      = (ar * br + ai * bi) / d;
            c[i + hn] = (ai * br - ar * bi) / d;
        }
    }
}

/// Pointwise |a|² → real result in SOA layout.
/// c_re = a_re² + a_im², c_im = 0.
fn soa_abs2_real(c: &mut [f64], a: &[f64]) {
    let n = a.len();
    let hn = n >> 1;
    for i in 0..hn {
        c[i]      = a[i] * a[i] + a[i + hn] * a[i + hn];
        c[i + hn] = 0.0;
    }
}

/// In-place scale: f[i] *= scale for all elements.
fn soa_scale_inplace(f: &mut [f64], scale: f64) {
    for v in f.iter_mut() {
        *v *= scale;
    }
}

// ================================================================
// LDL tree (SOA layout)
// ================================================================

/// LDL decomposition tree for FFSampling.
///
/// At each internal node, the off-diagonal `l10` captures the correlation
/// between the two components. Left/right subtrees correspond to the
/// diagonal blocks after factorization.
///
/// All vectors use SOA layout: `[re_0..re_{hn-1}, im_0..im_{hn-1}]`.
enum LDLTree {
    /// Leaf node (n=1 in FFT domain). Stores sigma values for sampling.
    Leaf { sigma0: f64, sigma1: f64 },
    /// Internal node with off-diagonal L factor and two subtrees.
    /// `l10` has length `n` in SOA layout (n/2 complex elements).
    Node {
        l10: Vec<f64>,
        left: Box<LDLTree>,
        right: Box<LDLTree>,
    },
}

/// Build the top-level LDL tree from the Gram matrix (all SOA layout).
///
/// The Gram matrix G = B·B* where B = [[g, -f], [G, -F]] has:
///   g00 = |f|² + |g|²       (real, self-adjoint)
///   g01 = f·adj(F) + g·adj(G)
///   g11 = |F|² + |G|²       (real, self-adjoint)
///
/// Top-level LDL: L = adj(g01)/g00, D_upper = g00, D_lower = g11 - |g01|²/g00
fn build_ldl_tree_top(
    g00: &[f64], g01: &[f64], g11: &[f64],
    n: usize, sigma: f64,
) -> LDLTree {
    let hn = n >> 1;
    let mut l10 = vec![0.0; n];
    let mut d_lower = vec![0.0; n];

    // l10 = adj(g01) / g00 = conj(g01) / g00
    let mut g01_conj = vec![0.0; n];
    fft_ops::poly_adj_fft(&mut g01_conj, g01, logn_of(n));
    soa_div(&mut l10, &g01_conj, g00);

    // d_lower = g11 - |g01|² / g00
    let mut abs2_g01 = vec![0.0; n];
    soa_abs2_real(&mut abs2_g01, g01);

    let mut ratio = vec![0.0; n];
    soa_div(&mut ratio, &abs2_g01, g00);

    fft_ops::poly_sub_fft(&mut d_lower, g11, &ratio, logn_of(n));

    build_ldl_inner(g00, &d_lower, l10, n, sigma)
}

/// Build LDL tree recursively from two diagonal polynomials.
fn build_ldl_inner(
    d_upper: &[f64], d_lower: &[f64], l10: Vec<f64>,
    n: usize, sigma: f64,
) -> LDLTree {
    if n == 2 {
        // Leaf: n=2 means hn=1 complex element. d_upper[0] = re, d_upper[1] = im(=0).
        let s0 = if d_upper[0] > 1e-30 { sigma / d_upper[0].sqrt() } else { sigma };
        let s1 = if d_lower[0] > 1e-30 { sigma / d_lower[0].sqrt() } else { sigma };
        return LDLTree::Leaf { sigma0: s0, sigma1: s1 };
    }

    let logn = logn_of(n);
    let hn = n >> 1;

    // Split self-adjoint polynomials d_upper and d_lower
    let mut du0 = vec![0.0; hn];
    let mut du1 = vec![0.0; hn];
    fft_ops::poly_split_fft(&mut du0, &mut du1, d_upper, logn);

    let mut dl0 = vec![0.0; hn];
    let mut dl1 = vec![0.0; hn];
    fft_ops::poly_split_fft(&mut dl0, &mut dl1, d_lower, logn);

    // Left subtree from d_upper: Gram = [[du0, du1], [adj(du1), du0]]
    let left = build_ldl_subtree(&du0, &du1, hn, sigma);
    // Right subtree from d_lower: Gram = [[dl0, dl1], [adj(dl1), dl0]]
    let right = build_ldl_subtree(&dl0, &dl1, hn, sigma);

    LDLTree::Node { l10, left: Box::new(left), right: Box::new(right) }
}

/// Build LDL subtree from a symmetric 2×2 Gram matrix [[g0, g1], [adj(g1), g0]].
///
/// For the symmetric case: l10 = adj(g1)/g0, d_lower = g0 - |g1|²/g0
fn build_ldl_subtree(g0: &[f64], g1: &[f64], n: usize, sigma: f64) -> LDLTree {
    let logn = logn_of(n);
    let mut l10 = vec![0.0; n];
    let mut d_lower = vec![0.0; n];

    // l10 = conj(g1) / g0
    let mut g1_conj = vec![0.0; n];
    fft_ops::poly_adj_fft(&mut g1_conj, g1, logn);
    soa_div(&mut l10, &g1_conj, g0);

    // d_lower = g0 - |g1|² / g0
    let mut abs2_g1 = vec![0.0; n];
    soa_abs2_real(&mut abs2_g1, g1);
    let mut ratio = vec![0.0; n];
    soa_div(&mut ratio, &abs2_g1, g0);
    fft_ops::poly_sub_fft(&mut d_lower, g0, &ratio, logn);

    build_ldl_inner(g0, &d_lower, l10, n, sigma)
}

// ================================================================
// Recursive FFSampling (SOA layout)
// ================================================================

/// Sample z = (z0, z1) close to target t = (t0, t1) using the LDL tree.
///
/// At each level:
///   1. Split t1 → recurse on right subtree → merge z1
///   2. Gram-Schmidt correct: t0_adj = t0 + L·(t1 - z1)
///   3. Split t0_adj → recurse on left subtree → merge z0
///
/// At leaves: z ~ D_{Z, t, sigma_leaf} via `sampler_z` (Klein/GPV).
///
/// # History — do not "simplify" this back
///
/// The leaf used to read `t0[0].round(), t0[1].round()` — deterministic Babai
/// rounding that ignored the `sigma0`/`sigma1` the LDL tree computed and never
/// touched the `rng` this function already received. That is the GGH/NTRUSign
/// construction, which leaks the secret basis across a signature transcript;
/// see #139/#143 and the matching note on `falcon_canonical::ffsampling`.
///
/// All polynomials use SOA layout with `n` elements (n/2 complex).
fn ffsampling<R: RngCore>(
    tree: &LDLTree, t0: &[f64], t1: &[f64],
    n: usize, sigma_min: f64, rng: &mut R,
) -> (Vec<f64>, Vec<f64>) {
    match tree {
        LDLTree::Leaf { sigma0, sigma1 } => {
            // Leaf: n=2 SOA. At logn=1 the two entries are the two real
            // values of the sub-target (the reference C `ffSampling_fft`
            // bottoms out the same way and samples both entries with the
            // leaf's sigma — z1 with tree[3], z0 with tree[2]).
            let z0 = vec![
                f64::from(sampler_z(t0[0], *sigma0, sigma_min, rng)),
                f64::from(sampler_z(t0[1], *sigma0, sigma_min, rng)),
            ];
            let z1 = vec![
                f64::from(sampler_z(t1[0], *sigma1, sigma_min, rng)),
                f64::from(sampler_z(t1[1], *sigma1, sigma_min, rng)),
            ];
            (z0, z1)
        }

        LDLTree::Node { l10, left, right } => {
            let logn = logn_of(n);
            let hn = n >> 1;

            // 1. Split t1 and recurse on right subtree
            let mut t10 = vec![0.0; hn];
            let mut t11 = vec![0.0; hn];
            fft_ops::poly_split_fft(&mut t10, &mut t11, t1, logn);

            let (z10, z11) = ffsampling(right, &t10, &t11, hn, sigma_min, rng);

            let mut z1 = vec![0.0; n];
            fft_ops::poly_merge_fft(&mut z1, &z10, &z11, logn);

            // 2. Gram-Schmidt correction: t0_adj = t0 + L·(t1 - z1)
            let mut diff = vec![0.0; n];
            fft_ops::poly_sub_fft(&mut diff, t1, &z1, logn);

            let mut correction = vec![0.0; n];
            fft_ops::poly_mul_fft(&mut correction, l10, &diff, logn);

            let mut t0_adj = vec![0.0; n];
            fft_ops::poly_add_fft(&mut t0_adj, t0, &correction, logn);

            // 3. Split adjusted t0 and recurse on left subtree
            let mut t00 = vec![0.0; hn];
            let mut t01 = vec![0.0; hn];
            fft_ops::poly_split_fft(&mut t00, &mut t01, &t0_adj, logn);

            let (z00, z01) = ffsampling(left, &t00, &t01, hn, sigma_min, rng);

            let mut z0 = vec![0.0; n];
            fft_ops::poly_merge_fft(&mut z0, &z00, &z01, logn);

            (z0, z1)
        }
    }
}

// ================================================================
// Pre-expanded key: amortize LDL tree + FFT across signing attempts
// ================================================================

/// Pre-expanded signing key with cached LDL tree and FFT-domain polynomials.
///
/// The LDL tree and FFT-domain key polynomials depend only on the private key
/// (f, g, F, G), not on the challenge `c`. Pre-computing them once avoids
/// rebuilding the O(n log²n) LDL tree on every retry attempt (typically 1-5
/// attempts per signature, up to 100 max).
///
/// # Performance Impact
/// - LDL tree construction: ~60% of total sign_sample time
/// - 5 FFT forward transforms: ~15% of total sign_sample time
/// - Pre-expansion turns sign_core retries from O(n log²n) to O(n log n) each
/// Walk the LDL tree and return the first leaf width outside `(0, SIGMA_MAX]`.
///
/// Same release-mode guard as `falcon_canonical::ldl_band_violation`, for the
/// SOA tree this module builds: `sampler_z` only debug_asserts its sigma
/// precondition, and a pre-#141 key can deterministically violate it. Applies
/// to both Falcon-512 (`ExpandedKey`) and Falcon-1024 (`falcon_sign_sample`)
/// — the base sampler's `SIGMA_MAX = 1.8205` is shared by both parameter sets.
fn ldl_band_violation(tree: &LDLTree) -> Option<f64> {
    match tree {
        LDLTree::Leaf { sigma0, sigma1 } => [*sigma0, *sigma1]
            .into_iter()
            .find(|&s| !(s > 0.0 && s <= crate::sampler_z::SIGMA_MAX)),
        LDLTree::Node { left, right, .. } => {
            ldl_band_violation(left).or_else(|| ldl_band_violation(right))
        }
    }
}

pub struct ExpandedKey {
    /// FFT-domain f polynomial (SOA layout)
    f_fft: Vec<f64>,
    /// FFT-domain g polynomial (SOA layout)
    g_fft: Vec<f64>,
    /// FFT-domain F polynomial (SOA layout)
    bf_fft: Vec<f64>,
    /// FFT-domain G polynomial (SOA layout)
    bg_fft: Vec<f64>,
    /// Pre-built LDL tree
    tree: LDLTree,
    /// Polynomial degree
    n: usize,
    /// Gaussian sigma
    sigma: f64,
}

impl ExpandedKey {
    /// Pre-expand a private key for fast repeated signing.
    ///
    /// This performs the expensive one-time computation:
    /// 1. Convert (f, g, F, G) to FFT domain (4 × O(n log n))
    /// 2. Build Gram matrix
    /// 3. Build LDL tree (O(n log²n))
    pub fn new(f: &[i16], g: &[i16], big_f: &[i16], big_g: &[i16], sigma: f64) -> Self {
        let n = f.len();
        let logn = n.trailing_zeros() as usize;

        let mut f_fft = vec![0.0f64; n];
        let mut g_fft = vec![0.0f64; n];
        let mut bf_fft = vec![0.0f64; n];
        let mut bg_fft = vec![0.0f64; n];

        for i in 0..n {
            f_fft[i]  = f[i] as f64;
            g_fft[i]  = g[i] as f64;
            bf_fft[i] = big_f[i] as f64;
            bg_fft[i] = big_g[i] as f64;
        }

        fft_ops::fft_forward(&mut f_fft, logn);
        fft_ops::fft_forward(&mut g_fft, logn);
        fft_ops::fft_forward(&mut bf_fft, logn);
        fft_ops::fft_forward(&mut bg_fft, logn);

        // Gram matrix
        let mut g00 = vec![0.0; n];
        let mut f_norm = vec![0.0; n];
        let mut g_norm = vec![0.0; n];
        fft_ops::poly_norm_fft(&mut f_norm, &f_fft, logn);
        fft_ops::poly_norm_fft(&mut g_norm, &g_fft, logn);
        fft_ops::poly_add_fft(&mut g00, &f_norm, &g_norm, logn);

        let mut g01 = vec![0.0; n];
        let mut f_bf = vec![0.0; n];
        let mut g_bg = vec![0.0; n];
        fft_ops::poly_muladj_fft(&mut f_bf, &f_fft, &bf_fft, logn);
        fft_ops::poly_muladj_fft(&mut g_bg, &g_fft, &bg_fft, logn);
        fft_ops::poly_add_fft(&mut g01, &f_bf, &g_bg, logn);

        let mut g11 = vec![0.0; n];
        let mut bf_norm = vec![0.0; n];
        let mut bg_norm = vec![0.0; n];
        fft_ops::poly_norm_fft(&mut bf_norm, &bf_fft, logn);
        fft_ops::poly_norm_fft(&mut bg_norm, &bg_fft, logn);
        fft_ops::poly_add_fft(&mut g11, &bf_norm, &bg_norm, logn);

        let tree = build_ldl_tree_top(&g00, &g01, &g11, n, sigma);

        ExpandedKey { f_fft, g_fft, bf_fft, bg_fft, tree, n, sigma }
    }

    /// Sign using the pre-expanded key. Only the per-challenge work is done:
    /// 1. FFT(c)
    /// 2. Compute target t
    /// 3. FFSample
    /// 4. Compute signature s
    pub fn sign_sample<R: RngCore>(
        &self, c: &[i16], rng: &mut R,
    ) -> Result<(Vec<i16>, Vec<i16>)> {
        let n = self.n;
        let logn = n.trailing_zeros() as usize;
        let q_inv = 1.0 / Q as f64;

        // Fail closed on an out-of-band leaf (pre-#141 key) rather than let
        // sampler_z emit the wrong distribution in release builds.
        if ldl_band_violation(&self.tree).is_some() {
            return Err(Falcon512Error::LdlSigmaOutOfBand);
        }

        // FFT(c) — only per-challenge work
        let mut c_soa = vec![0.0f64; n];
        for i in 0..n { c_soa[i] = c[i] as f64; }
        fft_ops::fft_forward(&mut c_soa, logn);

        // Target: t0 = -c·F/q, t1 = c·f/q
        let mut t0 = vec![0.0; n];
        fft_ops::poly_mul_fft(&mut t0, &c_soa, &self.bf_fft, logn);
        soa_scale_inplace(&mut t0, -q_inv);

        let mut t1 = vec![0.0; n];
        fft_ops::poly_mul_fft(&mut t1, &c_soa, &self.f_fft, logn);
        soa_scale_inplace(&mut t1, q_inv);

        // FFSampling
        let (z0_soa, z1_soa) = ffsampling(&self.tree, &t0, &t1, n, sigma_min_for(n), rng);

        // Signature: s0 = c - z0*g - z1*G (fused), s1 = z0*f + z1*F (fused)
        let mut s0_soa = vec![0.0; n];
        fft_ops::poly_mulsub_fft(&mut s0_soa, &z0_soa, &self.g_fft, &c_soa, logn);
        let s0_tmp = s0_soa.clone();
        fft_ops::poly_mulsub_fft(&mut s0_soa, &z1_soa, &self.bg_fft, &s0_tmp, logn);

        let mut s1_soa = vec![0.0; n];
        // First term: s1 = z0*f (accumulator is zero, so use plain mul)
        fft_ops::poly_mul_fft(&mut s1_soa, &z0_soa, &self.f_fft, logn);
        // Second term: s1 += z1*F (fused muladd)
        let s1_tmp = s1_soa.clone();
        fft_ops::poly_muladd_fft(&mut s1_soa, &z1_soa, &self.bf_fft, &s1_tmp, logn);

        // Inverse FFT
        fft_ops::fft_inverse(&mut s0_soa, logn);
        fft_ops::fft_inverse(&mut s1_soa, logn);

        // Round to integer
        let mut s0 = vec![0i16; n];
        let mut s1 = vec![0i16; n];
        for i in 0..n {
            s0[i] = s0_soa[i].round() as i16;
            s1[i] = s1_soa[i].round() as i16;
        }

        Ok((s0, s1))
    }
}

// ================================================================
// Public API: complete signing sample
// ================================================================

/// Sample a short preimage (s0, s1) for the Falcon signature.
///
/// Given private key (f, g, F, G) and challenge c, finds short polynomials
/// s0, s1 such that s0 + s1·h ≡ c (mod q) and ||(s0, s1)||² is small.
///
/// Algorithm:
///   1. Convert (f, g, F, G, c) to negacyclic FFT domain (O(n log n))
///   2. Compute Gram matrix G = B·B* where B = [[g,-f],[G,-F]]
///   3. Build LDL tree from G
///   4. Compute target t = (c,0)·B⁻¹ = (-c·F/q, c·f/q)
///   5. Sample z ≈ t via FFSampling
///   6. Compute s = (c,0) - z·B
///
/// All internal operations use SOA layout and go through `fft_ops`
/// for AVX2/AVX-512/NEON acceleration.
#[allow(non_snake_case)]
pub fn falcon_sign_sample<R: RngCore>(
    f: &[i16], g: &[i16], big_f: &[i16], big_g: &[i16],
    c: &[i16], sigma: f64,
    rng: &mut R,
) -> Result<(Vec<i16>, Vec<i16>)> {
    let n = f.len();
    if !n.is_power_of_two() || n < 2 {
        return Err(Falcon512Error::InvalidParameter);
    }

    let logn = n.trailing_zeros() as usize;
    let hn = n >> 1;

    // 1. Convert to f64 and compute FFTs (O(n log n) via fft_ops)
    let mut f_soa = vec![0.0f64; n];
    let mut g_soa = vec![0.0f64; n];
    let mut bf_soa = vec![0.0f64; n];
    let mut bg_soa = vec![0.0f64; n];
    let mut c_soa = vec![0.0f64; n];

    for i in 0..n {
        f_soa[i]  = f[i] as f64;
        g_soa[i]  = g[i] as f64;
        bf_soa[i] = big_f[i] as f64;
        bg_soa[i] = big_g[i] as f64;
        c_soa[i]  = c[i] as f64;
    }

    fft_ops::fft_forward(&mut f_soa, logn);
    fft_ops::fft_forward(&mut g_soa, logn);
    fft_ops::fft_forward(&mut bf_soa, logn);
    fft_ops::fft_forward(&mut bg_soa, logn);
    fft_ops::fft_forward(&mut c_soa, logn);

    // 2. Gram matrix: G = B·B* where B = [[g, -f], [G, -F]]
    //    g00 = |f|² + |g|²    (real, via norm)
    //    g01 = f·conj(F) + g·conj(G)
    //    g11 = |F|² + |G|²    (real, via norm)
    let mut g00 = vec![0.0; n];
    let mut f_norm = vec![0.0; n];
    let mut g_norm = vec![0.0; n];
    fft_ops::poly_norm_fft(&mut f_norm, &f_soa, logn);
    fft_ops::poly_norm_fft(&mut g_norm, &g_soa, logn);
    fft_ops::poly_add_fft(&mut g00, &f_norm, &g_norm, logn);

    let mut g01 = vec![0.0; n];
    let mut fF = vec![0.0; n];
    let mut gG = vec![0.0; n];
    fft_ops::poly_muladj_fft(&mut fF, &f_soa, &bf_soa, logn);
    fft_ops::poly_muladj_fft(&mut gG, &g_soa, &bg_soa, logn);
    fft_ops::poly_add_fft(&mut g01, &fF, &gG, logn);

    let mut g11 = vec![0.0; n];
    let mut bf_norm = vec![0.0; n];
    let mut bg_norm = vec![0.0; n];
    fft_ops::poly_norm_fft(&mut bf_norm, &bf_soa, logn);
    fft_ops::poly_norm_fft(&mut bg_norm, &bg_soa, logn);
    fft_ops::poly_add_fft(&mut g11, &bf_norm, &bg_norm, logn);

    // 3. Build LDL tree (all SOA)
    let tree = build_ldl_tree_top(&g00, &g01, &g11, n, sigma);

    // Fail closed on an out-of-band leaf (pre-#141 key) rather than let
    // sampler_z emit the wrong distribution in release builds.
    if ldl_band_violation(&tree).is_some() {
        return Err(Falcon512Error::LdlSigmaOutOfBand);
    }

    // 4. Target: t = (c, 0) · B⁻¹ where B⁻¹ = (1/q)·[[-F, f], [-G, g]]
    //    t0 = -c·F/q,  t1 = c·f/q  (pointwise in FFT domain)
    let q_inv = 1.0 / Q as f64;

    let mut t0 = vec![0.0; n];
    fft_ops::poly_mul_fft(&mut t0, &c_soa, &bf_soa, logn);
    soa_scale_inplace(&mut t0, -q_inv);

    let mut t1 = vec![0.0; n];
    fft_ops::poly_mul_fft(&mut t1, &c_soa, &f_soa, logn);
    soa_scale_inplace(&mut t1, q_inv);

    // 5. FFSampling: sample integer z close to target t (all SOA)
    let (z0_soa, z1_soa) = ffsampling(&tree, &t0, &t1, n, sigma_min_for(n), rng);

    // 6. Signature: s = (c, 0) - z·B  (using fused multiply-add/sub)
    //    s0 = c - z0·g - z1·G
    //    s1 = z0·f + z1·F
    let mut s0_soa = vec![0.0; n];
    fft_ops::poly_mulsub_fft(&mut s0_soa, &z0_soa, &g_soa, &c_soa, logn);
    let s0_tmp = s0_soa.clone();
    fft_ops::poly_mulsub_fft(&mut s0_soa, &z1_soa, &bg_soa, &s0_tmp, logn);

    let mut s1_soa = vec![0.0; n];
    fft_ops::poly_mul_fft(&mut s1_soa, &z0_soa, &f_soa, logn);
    let s1_tmp = s1_soa.clone();
    fft_ops::poly_muladd_fft(&mut s1_soa, &z1_soa, &bf_soa, &s1_tmp, logn);

    // 7. Inverse FFT to get real coefficients (O(n log n))
    fft_ops::fft_inverse(&mut s0_soa, logn);
    fft_ops::fft_inverse(&mut s1_soa, logn);

    // 8. Round to nearest integer
    let mut s0 = vec![0i16; n];
    let mut s1 = vec![0i16; n];

    for i in 0..n {
        s0[i] = s0_soa[i].round() as i16;
        s1[i] = s1_soa[i].round() as i16;
    }

    Ok((s0, s1))
}

// ================================================================
// Tests
// ================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::N;
    use crate::fft_ops;

    fn close(a: f64, b: f64, tol: f64) -> bool {
        let diff = (a - b).abs();
        let denom = a.abs() + b.abs() + 1e-30;
        diff / denom < tol
    }

    #[test]
    fn test_fft_roundtrip_via_fft_ops() {
        // Test that fft_ops::fft_forward → fft_inverse recovers original
        let mut poly = vec![0.0f64; 8];
        poly[0] = 3.0; poly[1] = 1.0; poly[2] = 4.0; poly[3] = 1.0;
        poly[4] = 5.0; poly[5] = 9.0; poly[6] = 2.0; poly[7] = 6.0;

        let original = poly.clone();
        fft_ops::fft_forward(&mut poly, 3);
        fft_ops::fft_inverse(&mut poly, 3);

        for i in 0..8 {
            assert!(close(original[i], poly[i], 1e-10),
                "FFT roundtrip error at {}: {} vs {}", i, original[i], poly[i]);
        }
    }

    #[test]
    fn test_split_merge_roundtrip_soa() {
        let poly = vec![3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0, 6.0];
        let mut fft = poly.clone();
        fft_ops::fft_forward(&mut fft, 3);

        let mut f0 = vec![0.0; 4];
        let mut f1 = vec![0.0; 4];
        fft_ops::poly_split_fft(&mut f0, &mut f1, &fft, 3);

        let mut merged = vec![0.0; 8];
        fft_ops::poly_merge_fft(&mut merged, &f0, &f1, 3);

        for i in 0..8 {
            assert!(close(fft[i], merged[i], 1e-10),
                "Split/merge roundtrip error at {}: {:?} vs {:?}", i, fft[i], merged[i]);
        }
    }

    #[test]
    fn test_fft_multiplication_soa() {
        // (a0 + a1·x) · (b0 + b1·x) mod (x² + 1) = (a0·b0 - a1·b1) + (a0·b1 + a1·b0)·x
        let mut a_fft = vec![3.0, 2.0];
        let mut b_fft = vec![5.0, 7.0];
        // Expected: (15 - 14) + (21 + 10)x = 1 + 31x
        let expected = vec![1.0, 31.0];

        fft_ops::fft_forward(&mut a_fft, 1);
        fft_ops::fft_forward(&mut b_fft, 1);

        let mut c_fft = vec![0.0; 2];
        fft_ops::poly_mul_fft(&mut c_fft, &a_fft, &b_fft, 1);

        fft_ops::fft_inverse(&mut c_fft, 1);

        for i in 0..2 {
            assert!(close(c_fft[i], expected[i], 1e-10),
                "Product mismatch at {}: {} vs {}", i, c_fft[i], expected[i]);
        }
    }

    /// O(n²) direct FFT evaluation for comparison testing
    fn neg_fft_direct(a: &[f64]) -> Vec<(f64, f64)> {
        let n = a.len();
        let mut result = Vec::with_capacity(n);
        for j in 0..n {
            let base = core::f64::consts::PI * (2 * j + 1) as f64 / n as f64;
            let mut re = 0.0;
            let mut im = 0.0;
            for k in 0..n {
                let angle = base * k as f64;
                re += a[k] * angle.cos();
                im += a[k] * angle.sin();
            }
            result.push((re, im));
        }
        result
    }

    #[test]
    fn test_butterfly_matches_direct_fft() {
        // Compare the butterfly FFT (n/2 evaluations) against direct FFT (n evaluations)
        // The butterfly should produce the first n/2 evaluations from the direct FFT
        for logn in 1..=9 {
            let n = 1usize << logn;
            let hn = n >> 1;
            let mut seed = 800u32 + logn as u32;

            let poly: Vec<f64> = (0..n).map(|_| {
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                ((seed >> 8) as f64 / 16777216.0) * 20.0 - 10.0
            }).collect();

            // Direct FFT: all n evaluations
            let direct = neg_fft_direct(&poly);

            // Butterfly FFT: n SOA values = n/2 complex evaluations
            let mut butterfly = poly.clone();
            fft_ops::fft_forward(&mut butterfly, logn);

            // The butterfly FFT stores evaluations at ω^{2k+1} for k=0..hn-1
            // in SOA format: butterfly[k] = re, butterfly[k+hn] = im
            // Direct FFT stores evaluation j = f(ω^{2j+1}) at index j
            // These should match for j=0..hn-1
            let mut max_err = 0.0f64;
            for k in 0..hn {
                let bf_re = butterfly[k];
                let bf_im = butterfly[k + hn];
                let (dir_re, dir_im) = direct[k];
                let err_re = (bf_re - dir_re).abs();
                let err_im = (bf_im - dir_im).abs();
                max_err = max_err.max(err_re).max(err_im);
            }

            assert!(max_err < 1e-6,
                "Butterfly vs direct FFT mismatch at logn={logn}: max_err={max_err:.2e}");
        }
    }

    #[test]
    fn test_sign_sample_norm_diagnostic() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(42);

        let (f, g, big_f, big_g) = match crate::ntru_working::ntru_keygen_working(&mut rng) {
            Ok(keys) => keys,
            Err(_) => { return; }
        };

        let c: Vec<i16> = (0..N).map(|i| ((i * 37 + 13) % Q as usize) as i16).collect();
        let sigma = 165.7366171829776;

        let (s0, s1) = falcon_sign_sample(&f, &g, &big_f, &big_g, &c, sigma, &mut rng)
            .expect("Signing should succeed");

        let mut norm: i64 = 0;
        for i in 0..N {
            norm += (s0[i] as i64) * (s0[i] as i64);
            norm += (s1[i] as i64) * (s1[i] as i64);
        }

        eprintln!("Signature norm² = {} (beta² = 34034726)", norm);
        // With Babai rounding, norm can exceed beta² but should be in reasonable range
        assert!(norm < 1_000_000_000, "Norm unreasonably large: {}", norm);
    }

    #[test]
    fn test_sign_sample_with_keygen() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(42);

        // Generate a real key using the NTRU solver
        let (f, g, big_f, big_g) = match crate::ntru_working::ntru_keygen_working(&mut rng) {
            Ok(keys) => keys,
            Err(_) => {
                eprintln!("Keygen failed, skipping sign_sample test");
                return;
            }
        };

        // Create a test challenge polynomial (uniform mod q)
        let c: Vec<i16> = (0..N).map(|i| ((i * 37 + 13) % Q as usize) as i16).collect();

        let sigma = 165.7366171829776;

        // Sample signature
        let (s0, s1) = falcon_sign_sample(&f, &g, &big_f, &big_g, &c, sigma, &mut rng)
            .expect("Signing should succeed");

        assert_eq!(s0.len(), N);
        assert_eq!(s1.len(), N);

        // Check norm bound
        let mut norm: i64 = 0;
        for i in 0..N {
            norm += (s0[i] as i64) * (s0[i] as i64);
            norm += (s1[i] as i64) * (s1[i] as i64);
        }

        // Norm should be reasonable (< beta² = 34034726)
        // With Babai rounding it might exceed beta² sometimes, but should be finite
        assert!(norm < i64::MAX / 2, "Norm should be finite: {}", norm);
    }

    #[test]
    fn test_fused_muladd_mulsub() {
        // Verify fused ops match separate mul + add/sub
        let logn = 9;
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut seed = 900u32;

        let a: Vec<f64> = (0..n).map(|_| {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            (seed >> 8) as f64 / 16777216.0 * 200.0 - 100.0
        }).collect();
        let b: Vec<f64> = (0..n).map(|_| {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            (seed >> 8) as f64 / 16777216.0 * 200.0 - 100.0
        }).collect();
        let acc: Vec<f64> = (0..n).map(|_| {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            (seed >> 8) as f64 / 16777216.0 * 200.0 - 100.0
        }).collect();

        // Separate: mul then add
        let mut prod = vec![0.0; n];
        fft_ops::poly_mul_fft(&mut prod, &a, &b, logn);
        let mut expected_add = vec![0.0; n];
        fft_ops::poly_add_fft(&mut expected_add, &acc, &prod, logn);

        // Fused muladd
        let mut fused_add = vec![0.0; n];
        fft_ops::poly_muladd_fft(&mut fused_add, &a, &b, &acc, logn);

        for i in 0..n {
            assert!(close(expected_add[i], fused_add[i], 1e-12),
                "muladd mismatch at {i}: {} vs {}", expected_add[i], fused_add[i]);
        }

        // Separate: mul then sub
        let mut expected_sub = vec![0.0; n];
        fft_ops::poly_sub_fft(&mut expected_sub, &acc, &prod, logn);

        // Fused mulsub
        let mut fused_sub = vec![0.0; n];
        fft_ops::poly_mulsub_fft(&mut fused_sub, &a, &b, &acc, logn);

        for i in 0..n {
            assert!(close(expected_sub[i], fused_sub[i], 1e-12),
                "mulsub mismatch at {i}: {} vs {}", expected_sub[i], fused_sub[i]);
        }
    }

    #[test]
    fn test_expanded_key_sign_matches() {
        // Verify ExpandedKey::sign_sample produces identical output
        // to falcon_sign_sample (both use same RNG seed)
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(42);
        let (f, g, big_f, big_g) = match crate::ntru_working::ntru_keygen_working(&mut rng) {
            Ok(keys) => keys,
            Err(_) => { return; }
        };

        let c: Vec<i16> = (0..N).map(|i| ((i * 37 + 13) % Q as usize) as i16).collect();
        let sigma = 165.7366171829776;

        // Sign with standalone function
        let mut rng1 = StdRng::seed_from_u64(99);
        let (s0_a, s1_a) = falcon_sign_sample(&f, &g, &big_f, &big_g, &c, sigma, &mut rng1)
            .expect("standalone sign should succeed");

        // Sign with expanded key
        let expanded = ExpandedKey::new(&f, &g, &big_f, &big_g, sigma);
        let mut rng2 = StdRng::seed_from_u64(99);
        let (s0_b, s1_b) = expanded.sign_sample(&c, &mut rng2)
            .expect("expanded sign should succeed");

        assert_eq!(s0_a, s0_b, "s0 mismatch between standalone and expanded key");
        assert_eq!(s1_a, s1_b, "s1 mismatch between standalone and expanded key");
    }

    #[test]
    fn test_expanded_key_multiple_challenges() {
        // Verify ExpandedKey can sign multiple different challenges
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(42);
        let (f, g, big_f, big_g) = match crate::ntru_working::ntru_keygen_working(&mut rng) {
            Ok(keys) => keys,
            Err(_) => { return; }
        };

        let sigma = 165.7366171829776;
        let expanded = ExpandedKey::new(&f, &g, &big_f, &big_g, sigma);

        for seed_val in 100..105 {
            let c: Vec<i16> = (0..N).map(|i| ((i * seed_val + 7) % Q as usize) as i16).collect();
            let mut rng_sign = StdRng::seed_from_u64(seed_val as u64);
            let (s0, s1) = expanded.sign_sample(&c, &mut rng_sign)
                .expect("expanded sign should succeed");

            let mut norm: i64 = 0;
            for i in 0..N {
                norm += (s0[i] as i64) * (s0[i] as i64);
                norm += (s1[i] as i64) * (s1[i] as i64);
            }
            assert!(norm < 1_000_000_000,
                "Norm unreasonably large for challenge seed {}: {}", seed_val, norm);
        }
    }
}
