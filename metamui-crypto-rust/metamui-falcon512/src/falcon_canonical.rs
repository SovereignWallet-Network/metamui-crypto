//! Canonical Falcon-512 signing via negacyclic FFT + LDL tree + FFSampling.
//!
//! Ported line-by-line from the Python reference `falcon512_canonical.py` (lines 700-1021).
//! Leaves are sampled from a discrete Gaussian at the LDL tree's per-leaf width
//! (Klein / GPV), which is what makes the emitted signature distribution
//! independent of the secret basis. Before #139 the leaf did deterministic
//! Babai nearest-plane rounding instead — see `ffsampling`.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use crate::constants::{Q, SIGMA_MIN};
use crate::error::{Falcon512Error, Result};
use crate::sampler_z::{sampler_z, SIGMA_MAX};
use rand::RngCore;

/// Complex type alias: (real, imag).
type C64 = (f64, f64);

// ================================================================
// Complex number helpers
// ================================================================

#[inline]
fn cmul(a: C64, b: C64) -> C64 {
    (a.0 * b.0 - a.1 * b.1, a.0 * b.1 + a.1 * b.0)
}

#[inline]
fn cadd(a: C64, b: C64) -> C64 {
    (a.0 + b.0, a.1 + b.1)
}

#[inline]
fn csub(a: C64, b: C64) -> C64 {
    (a.0 - b.0, a.1 - b.1)
}

#[inline]
fn cdiv(a: C64, b: C64) -> C64 {
    let d = b.0 * b.0 + b.1 * b.1;
    if d < 1e-300 {
        return (0.0, 0.0);
    }
    ((a.0 * b.0 + a.1 * b.1) / d, (a.1 * b.0 - a.0 * b.1) / d)
}

#[inline]
fn cabs2(a: C64) -> f64 {
    a.0 * a.0 + a.1 * a.1
}

#[inline]
fn cconj(a: C64) -> C64 {
    (a.0, -a.1)
}

#[inline]
fn cscale(a: C64, s: f64) -> C64 {
    (a.0 * s, a.1 * s)
}

// ================================================================
// Trig helpers
// ================================================================

#[inline]
fn cos_f64(x: f64) -> f64 {
    x.cos()
}

#[inline]
fn sin_f64(x: f64) -> f64 {
    x.sin()
}

#[inline]
fn sqrt_f64(x: f64) -> f64 {
    x.sqrt()
}

// ================================================================
// Bit-reversal permutation helper
// ================================================================

fn bit_reverse(val: usize, logn: usize) -> usize {
    let mut rev = 0usize;
    for b in 0..logn {
        if val & (1 << b) != 0 {
            rev |= 1 << (logn - 1 - b);
        }
    }
    rev
}

// ================================================================
// Negacyclic FFT / IFFT
// ================================================================

/// Negacyclic FFT: real polynomial -> complex FFT domain.
///
/// Pre-twist by psi^k (psi = e^{pi*i/n}) followed by standard DFT.
pub fn negacyclic_fft(a: &[f64]) -> Vec<C64> {
    let n = a.len();
    if n == 1 {
        return vec![(a[0], 0.0)];
    }

    let psi_angle = core::f64::consts::PI / (n as f64);

    // Pre-twist: multiply a[k] by psi^k
    let mut buf: Vec<C64> = Vec::with_capacity(n);
    for k in 0..n {
        let angle = (k as f64) * psi_angle;
        let c = cos_f64(angle);
        let s = sin_f64(angle);
        buf.push((a[k] * c, a[k] * s));
    }

    // Bit-reversal permutation
    let logn = n.trailing_zeros() as usize;
    for i in 0..n {
        let j = bit_reverse(i, logn);
        if j > i {
            buf.swap(i, j);
        }
    }

    // Cooley-Tukey butterfly (positive angle for roots of x^n + 1)
    let mut length = 2;
    while length <= n {
        let half = length / 2;
        let angle_step = 2.0 * core::f64::consts::PI / (length as f64);
        let wn_re = cos_f64(angle_step);
        let wn_im = sin_f64(angle_step);
        let mut start = 0;
        while start < n {
            let mut wr: f64 = 1.0;
            let mut wi: f64 = 0.0;
            for k in 0..half {
                let idx0 = start + k;
                let idx1 = start + k + half;
                let tr = buf[idx1].0 * wr - buf[idx1].1 * wi;
                let ti = buf[idx1].0 * wi + buf[idx1].1 * wr;
                buf[idx1] = (buf[idx0].0 - tr, buf[idx0].1 - ti);
                buf[idx0] = (buf[idx0].0 + tr, buf[idx0].1 + ti);
                let new_wr = wr * wn_re - wi * wn_im;
                let new_wi = wr * wn_im + wi * wn_re;
                wr = new_wr;
                wi = new_wi;
            }
            start += length;
        }
        length *= 2;
    }

    buf
}

/// Inverse negacyclic FFT: complex FFT domain -> real polynomial.
///
/// Inverse DFT followed by post-twist by psi^{-k} and 1/n scaling.
pub fn negacyclic_ifft(f: &[C64]) -> Vec<f64> {
    let n = f.len();
    if n == 1 {
        return vec![f[0].0];
    }

    let inv_n = 1.0 / (n as f64);
    let psi_angle = core::f64::consts::PI / (n as f64);

    let mut buf: Vec<C64> = f.to_vec();

    // Bit-reversal permutation
    let logn = n.trailing_zeros() as usize;
    for i in 0..n {
        let j = bit_reverse(i, logn);
        if j > i {
            buf.swap(i, j);
        }
    }

    // Cooley-Tukey butterfly (negative angle for inverse)
    let mut length = 2;
    while length <= n {
        let half = length / 2;
        let angle_step = -2.0 * core::f64::consts::PI / (length as f64);
        let wn_re = cos_f64(angle_step);
        let wn_im = sin_f64(angle_step);
        let mut start = 0;
        while start < n {
            let mut wr: f64 = 1.0;
            let mut wi: f64 = 0.0;
            for k in 0..half {
                let idx0 = start + k;
                let idx1 = start + k + half;
                let tr = buf[idx1].0 * wr - buf[idx1].1 * wi;
                let ti = buf[idx1].0 * wi + buf[idx1].1 * wr;
                buf[idx1] = (buf[idx0].0 - tr, buf[idx0].1 - ti);
                buf[idx0] = (buf[idx0].0 + tr, buf[idx0].1 + ti);
                let new_wr = wr * wn_re - wi * wn_im;
                let new_wi = wr * wn_im + wi * wn_re;
                wr = new_wr;
                wi = new_wi;
            }
            start += length;
        }
        length *= 2;
    }

    // Post-twist: undo pre-twist (multiply by psi^{-k}) and scale by 1/n
    let mut result = Vec::with_capacity(n);
    for k in 0..n {
        let angle = -((k as f64) * psi_angle);
        let c = cos_f64(angle);
        let s = sin_f64(angle);
        let re = buf[k].0 * c - buf[k].1 * s;
        result.push(re * inv_n);
    }

    result
}

// ================================================================
// FFT split / merge (in FFT domain)
// ================================================================

/// Decompose f(x) = f0(x^2) + x*f1(x^2) in FFT domain.
fn fft_split(f: &[C64]) -> (Vec<C64>, Vec<C64>) {
    let n = f.len();
    let hn = n / 2;
    let mut f0 = vec![(0.0, 0.0); hn];
    let mut f1 = vec![(0.0, 0.0); hn];

    for k in 0..hn {
        let s = cadd(f[k], f[hn + k]);
        let d = csub(f[k], f[hn + k]);
        f0[k] = cscale(s, 0.5);
        let angle = core::f64::consts::PI * (2 * k + 1) as f64 / (n as f64);
        let omega = (cos_f64(angle), sin_f64(angle));
        f1[k] = cdiv(cscale(d, 0.5), omega);
    }

    (f0, f1)
}

/// Recombine f(x) = f0(x^2) + x*f1(x^2) in FFT domain.
fn fft_merge(f0: &[C64], f1: &[C64]) -> Vec<C64> {
    let hn = f0.len();
    let n = hn * 2;
    let mut f = vec![(0.0, 0.0); n];

    for k in 0..hn {
        let angle = core::f64::consts::PI * (2 * k + 1) as f64 / (n as f64);
        let omega = (cos_f64(angle), sin_f64(angle));
        let w = cmul(omega, f1[k]);
        f[k] = cadd(f0[k], w);
        f[hn + k] = csub(f0[k], w);
    }

    f
}

// ================================================================
// LDL tree
// ================================================================

/// LDL decomposition tree for FFSampling.
enum LdlTree {
    /// Leaf node: stores sigma values for Babai rounding.
    Leaf {
        sigma0: f64,
        sigma1: f64,
    },
    /// Internal node: stores l10 and left/right subtrees.
    Node {
        l10: Vec<C64>,
        left: Box<LdlTree>,
        right: Box<LdlTree>,
    },
}

/// Build the top-level LDL tree from the Gram matrix.
fn build_ldl_tree_top(g00: &[C64], g01: &[C64], g11: &[C64], n: usize, sigma: f64) -> LdlTree {
    let mut l10 = vec![(0.0, 0.0); n];
    let mut d_lower = vec![(0.0, 0.0); n];

    for k in 0..n {
        l10[k] = cdiv(cconj(g01[k]), g00[k]);
        d_lower[k] = csub(g11[k], cdiv((cabs2(g01[k]), 0.0), g00[k]));
    }

    build_ldl_inner(g00, &d_lower, l10, n, sigma)
}

/// Build LDL tree recursively.
fn build_ldl_inner(d_upper: &[C64], d_lower: &[C64], l10: Vec<C64>, n: usize, sigma: f64) -> LdlTree {
    if n == 1 {
        let s0 = if d_upper[0].0 > 1e-30 {
            sigma / sqrt_f64(d_upper[0].0)
        } else {
            sigma
        };
        let s1 = if d_lower[0].0 > 1e-30 {
            sigma / sqrt_f64(d_lower[0].0)
        } else {
            sigma
        };
        return LdlTree::Leaf { sigma0: s0, sigma1: s1 };
    }

    let (du0, du1) = fft_split(d_upper);
    let (dl0, dl1) = fft_split(d_lower);
    let hn = n / 2;

    let left = build_ldl_subtree(&du0, &du1, hn, sigma);
    let right = build_ldl_subtree(&dl0, &dl1, hn, sigma);

    LdlTree::Node {
        l10,
        left: Box::new(left),
        right: Box::new(right),
    }
}

/// Build subtree from symmetric 2x2 Gram matrix.
fn build_ldl_subtree(g0: &[C64], g1: &[C64], n: usize, sigma: f64) -> LdlTree {
    let mut l10 = vec![(0.0, 0.0); n];
    let mut d_lower = vec![(0.0, 0.0); n];

    for k in 0..n {
        if cabs2(g0[k]) < 1e-300 {
            l10[k] = (0.0, 0.0);
            d_lower[k] = g0[k];
        } else {
            l10[k] = cdiv(cconj(g1[k]), g0[k]);
            d_lower[k] = csub(g0[k], cdiv((cabs2(g1[k]), 0.0), g0[k]));
        }
    }

    build_ldl_inner(g0, &d_lower, l10, n, sigma)
}

/// Walk the LDL tree and return the first leaf width outside `(0, SIGMA_MAX]`.
///
/// `sampler_z`'s rejection step can only *narrow* the base half-Gaussian
/// (`SIGMA_MAX = 1.8205`), so a leaf wider than the band silently samples the
/// wrong distribution — checked there only by a `debug_assert!`, which
/// compiles out of release builds. Post-#141 keygen's GS bound keeps every
/// leaf in band by construction; keys minted before it can violate this, and
/// the violation is a deterministic property of the key (#4977 downstream).
/// This walk is the release-mode guard: O(n) float comparisons once per tree
/// build, before any sampling happens.
fn ldl_band_violation(tree: &LdlTree) -> Option<f64> {
    match tree {
        LdlTree::Leaf { sigma0, sigma1 } => [*sigma0, *sigma1]
            .into_iter()
            .find(|&s| !(s > 0.0 && s <= SIGMA_MAX)),
        LdlTree::Node { left, right, .. } => {
            ldl_band_violation(left).or_else(|| ldl_band_violation(right))
        }
    }
}

/// Validate that a secret basis produces an LDL tree whose every leaf width
/// lies in `(0, SIGMA_MAX]` — the precondition `sampler_z` needs to emit the
/// requested distribution.
///
/// Intended for key load/import: rejecting a bad key here, with a typed
/// error, beats discovering it at sign time. Cost is one Gram-matrix + LDL
/// tree build (~60% of a single signing attempt), with no sampling.
pub fn validate_ldl_band(
    f: &[i16],
    g: &[i16],
    big_f: &[i16],
    big_g: &[i16],
    sigma: f64,
) -> Result<()> {
    let (tree, _fft) = build_basis_ldl_tree(f, g, big_f, big_g, sigma);
    match ldl_band_violation(&tree) {
        None => Ok(()),
        Some(_) => Err(Falcon512Error::LdlSigmaOutOfBand),
    }
}

/// The basis polynomials in FFT domain, as `falcon_sign_sample` consumes them.
struct BasisFft {
    f: Vec<C64>,
    g: Vec<C64>,
    big_f: Vec<C64>,
    big_g: Vec<C64>,
}

/// FFT the basis, form the Gram matrix `B·B*`, and build the LDL tree.
/// Shared by the signing path and `validate_ldl_band` so the tree the
/// validator checks is byte-for-byte the tree signing samples from.
fn build_basis_ldl_tree(
    f: &[i16],
    g: &[i16],
    big_f: &[i16],
    big_g: &[i16],
    sigma: f64,
) -> (LdlTree, BasisFft) {
    let n = f.len();

    let f_f: Vec<f64> = f.iter().map(|&x| x as f64).collect();
    let g_f: Vec<f64> = g.iter().map(|&x| x as f64).collect();
    let bf_f: Vec<f64> = big_f.iter().map(|&x| x as f64).collect();
    let bg_f: Vec<f64> = big_g.iter().map(|&x| x as f64).collect();

    let f_fft = negacyclic_fft(&f_f);
    let g_fft = negacyclic_fft(&g_f);
    let bf_fft = negacyclic_fft(&bf_f);
    let bg_fft = negacyclic_fft(&bg_f);

    // Gram matrix G = B*B* where B = [[g, -f], [G, -F]]
    let mut g00 = vec![(0.0, 0.0); n];
    let mut g01 = vec![(0.0, 0.0); n];
    let mut g11 = vec![(0.0, 0.0); n];

    for k in 0..n {
        g00[k] = (cabs2(f_fft[k]) + cabs2(g_fft[k]), 0.0);
        g01[k] = cadd(
            cmul(f_fft[k], cconj(bf_fft[k])),
            cmul(g_fft[k], cconj(bg_fft[k])),
        );
        g11[k] = (cabs2(bf_fft[k]) + cabs2(bg_fft[k]), 0.0);
    }

    let tree = build_ldl_tree_top(&g00, &g01, &g11, n, sigma);

    (
        tree,
        BasisFft {
            f: f_fft,
            g: g_fft,
            big_f: bf_fft,
            big_g: bg_fft,
        },
    )
}

// ================================================================
// FFSampling (Klein / GPV, discrete-Gaussian leaves)
// ================================================================

/// Recursive FFSampling: sample z close to target t.
///
/// At leaf level this draws from the discrete Gaussian centred on the target,
/// with the width the LDL tree computed for that leaf.
///
/// # History — do not "simplify" this back
///
/// This function used to read:
///
/// ```text
/// LdlTree::Leaf { .. } => {
///     let z0 = vec![(f64_round(t0[0].0), 0.0)];
///     let z1 = vec![(f64_round(t1[0].0), 0.0)];
/// ```
///
/// which wildcarded away the `sigma0`/`sigma1` the tree had just computed and
/// did deterministic Babai nearest-plane rounding instead of sampling. It
/// verified fine — the norm bound is one-sided, and rounding produces vectors
/// far *shorter* than the specification — but it is the GGH/NTRUSign
/// construction, not Falcon, and it leaks the secret basis across a signature
/// transcript. Measured effect: `E||(s0,s1)||^2 = 2n*q/12 = 1,048,661` against
/// the specified `2n*sigma^2 = 28,127,873`, an effective sigma of 32.0 rather
/// than 165.74. See #139.
///
/// The `rng` must be the caller's: see the note on `sampler_z`.
fn ffsampling<R: RngCore>(
    tree: &LdlTree,
    t0: &[C64],
    t1: &[C64],
    n: usize,
    rng: &mut R,
) -> (Vec<C64>, Vec<C64>) {
    match tree {
        LdlTree::Leaf { sigma0, sigma1 } => {
            // Klein/GPV: sample around the target at the leaf's own width,
            // rather than rounding to the nearest lattice point.
            let z0 = vec![(
                f64::from(sampler_z(t0[0].0, *sigma0, SIGMA_MIN, rng)),
                0.0,
            )];
            let z1 = vec![(
                f64::from(sampler_z(t1[0].0, *sigma1, SIGMA_MIN, rng)),
                0.0,
            )];
            (z0, z1)
        }
        LdlTree::Node { l10, left, right } => {
            let hn = n / 2;

            // Split t1, recurse right
            let (t10, t11) = fft_split(t1);
            let (z10, z11) = ffsampling(right, &t10, &t11, hn, rng);
            let z1 = fft_merge(&z10, &z11);

            // Gram-Schmidt correction
            let mut t0_adj = vec![(0.0, 0.0); n];
            for k in 0..n {
                let diff = csub(t1[k], z1[k]);
                t0_adj[k] = cadd(t0[k], cmul(l10[k], diff));
            }

            // Split adjusted t0, recurse left
            let (t00, t01) = fft_split(&t0_adj);
            let (z00, z01) = ffsampling(left, &t00, &t01, hn, rng);
            let z0 = fft_merge(&z00, &z01);

            (z0, z1)
        }
    }
}

/// Round-half-to-even (Python's `round()` semantics).
#[inline]
fn f64_round(x: f64) -> f64 {
    // Python round() is round-half-to-even (banker's rounding).
    // Rust f64::round() is round-half-away-from-zero.
    // For Falcon signing the difference is negligible, but let's match Python.
    let r = x.round();
    // Check if we're exactly at a .5 boundary
    let frac = x - x.floor();
    if (frac - 0.5).abs() < 1e-15 {
        // Round to even
        let down = x.floor();
        let up = x.ceil();
        if (down as i64) % 2 == 0 { down } else { up }
    } else {
        r
    }
}

// ================================================================
// Main signing function
// ================================================================

/// Sample a short preimage (s0, s1) for the Falcon signature.
///
/// Given the NTRU basis (f, g, F, G) and challenge polynomial c,
/// produces (s0, s1) such that s0 + s1*h = c (mod q) and the
/// norm ||(s0, s1)|| is small.
///
/// Klein/GPV sampling over the LDL tree: the leaves draw from a discrete
/// Gaussian at the tree's per-leaf width, so the output follows the
/// distribution Falcon's security argument is stated over.
///
/// `rng` is consumed by the leaf sampler and must be supplied by the caller —
/// signing stays a pure function of the RNG stream, so a caller that seeds
/// deterministically still gets reproducible signatures.
///
/// Was a deterministic Babai nearest-plane sampler taking no RNG at all, which
/// is the #139 defect; see `ffsampling`.
pub fn falcon_sign_sample<R: RngCore>(
    f: &[i16],
    g: &[i16],
    big_f: &[i16],
    big_g: &[i16],
    c: &[i16],
    sigma: f64,
    rng: &mut R,
) -> Result<(Vec<i16>, Vec<i16>)> {
    let n = f.len();

    let c_f: Vec<f64> = c.iter().map(|&x| x as f64).collect();
    let c_fft = negacyclic_fft(&c_f);

    // Build LDL tree from the basis
    let (tree, basis) = build_basis_ldl_tree(f, g, big_f, big_g, sigma);

    // Release-mode band guard: sampler_z only debug_asserts its sigma
    // precondition, so a pre-#141 key with an out-of-band leaf would
    // otherwise sign from the wrong distribution. Fail closed instead —
    // see `ldl_band_violation`.
    if ldl_band_violation(&tree).is_some() {
        return Err(Falcon512Error::LdlSigmaOutOfBand);
    }

    let (f_fft, bf_fft) = (&basis.f, &basis.big_f);
    let (g_fft, bg_fft) = (&basis.g, &basis.big_g);

    // Target: t = (c, 0) * B^{-1}
    let q_inv = 1.0 / (Q as f64);
    let mut t0 = vec![(0.0, 0.0); n];
    let mut t1 = vec![(0.0, 0.0); n];
    for k in 0..n {
        t0[k] = cscale(cmul(c_fft[k], bf_fft[k]), -q_inv);
        t1[k] = cscale(cmul(c_fft[k], f_fft[k]), q_inv);
    }

    // FFSampling (Babai nearest-plane)
    let (z0_fft, z1_fft) = ffsampling(&tree, &t0, &t1, n, rng);

    // Signature: s = (c, 0) - z*B
    let mut s0_fft = vec![(0.0, 0.0); n];
    let mut s1_fft = vec![(0.0, 0.0); n];

    for k in 0..n {
        let zg = cadd(
            cmul(z0_fft[k], g_fft[k]),
            cmul(z1_fft[k], bg_fft[k]),
        );
        s0_fft[k] = csub(c_fft[k], zg);
        s1_fft[k] = cadd(
            cmul(z0_fft[k], f_fft[k]),
            cmul(z1_fft[k], bf_fft[k]),
        );
    }

    // Inverse FFT and round to integers
    let s0_f = negacyclic_ifft(&s0_fft);
    let s1_f = negacyclic_ifft(&s1_fft);

    let s0: Vec<i16> = s0_f.iter().map(|&x| x.round() as i16).collect();
    let s1: Vec<i16> = s1_f.iter().map(|&x| x.round() as i16).collect();

    Ok((s0, s1))
}

// ================================================================
// Tests
// ================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{BETA_SQUARED, N};

    /// An LDL tree with a leaf outside `(0, SIGMA_MAX]` must be reported.
    /// This is the release-mode guard #4977 asked for: the observed bad keys
    /// produced leaf widths 1.8763... and 1.8382... — the first is out of
    /// band, and only a `debug_assert!` (compiled out in release) noticed.
    #[test]
    fn ldl_band_violation_reports_out_of_band_leaf() {
        let bad = LdlTree::Node {
            l10: vec![(0.0, 0.0)],
            left: Box::new(LdlTree::Leaf {
                sigma0: 1.5,
                sigma1: 1.876396003907199, // observed in #4977, > SIGMA_MAX
            }),
            right: Box::new(LdlTree::Leaf {
                sigma0: 1.4,
                sigma1: 1.6,
            }),
        };
        assert_eq!(ldl_band_violation(&bad), Some(1.876396003907199));

        let good = LdlTree::Node {
            l10: vec![(0.0, 0.0)],
            left: Box::new(LdlTree::Leaf {
                sigma0: SIGMA_MAX, // boundary is inclusive
                sigma1: 1.3,
            }),
            right: Box::new(LdlTree::Leaf {
                sigma0: 1.4,
                sigma1: 1.6,
            }),
        };
        assert_eq!(ldl_band_violation(&good), None);

        // Zero and negative widths are also out of band (degenerate basis).
        let degenerate = LdlTree::Leaf {
            sigma0: 0.0,
            sigma1: 1.0,
        };
        assert_eq!(ldl_band_violation(&degenerate), Some(0.0));
    }

    /// A key from the current (post-GS-bound) keygen must pass the band
    /// validation — the guard must not reject good keys.
    #[test]
    fn post_fix_keygen_output_passes_band_validation() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(4977);
        let keypair = crate::generate_keypair(&mut rng).expect("keygen should succeed");
        validate_ldl_band(
            &keypair.private_key.f.coeffs,
            &keypair.private_key.g.coeffs,
            &keypair.private_key.big_f.coeffs,
            &keypair.private_key.big_g.coeffs,
            165.7366171829776,
        )
        .expect("post-GS-bound key must be inside the sigma band");
    }

    #[test]
    fn test_fft_roundtrip() {
        // Verify that IFFT(FFT(a)) ≈ a
        let a: Vec<f64> = (0..16).map(|i| (i as f64) * 1.5 - 10.0).collect();
        let fft_a = negacyclic_fft(&a);
        let recovered = negacyclic_ifft(&fft_a);
        for i in 0..a.len() {
            assert!(
                (a[i] - recovered[i]).abs() < 1e-10,
                "FFT roundtrip failed at index {}: expected {}, got {}",
                i, a[i], recovered[i]
            );
        }
    }

    #[test]
    fn test_fft_split_merge_roundtrip() {
        let a: Vec<f64> = (0..32).map(|i| (i as f64) * 0.7 - 5.0).collect();
        let fft_a = negacyclic_fft(&a);
        let (f0, f1) = fft_split(&fft_a);
        let merged = fft_merge(&f0, &f1);
        for i in 0..fft_a.len() {
            assert!(
                (fft_a[i].0 - merged[i].0).abs() < 1e-10
                    && (fft_a[i].1 - merged[i].1).abs() < 1e-10,
                "Split/merge roundtrip failed at index {}",
                i
            );
        }
    }

    #[test]
    fn test_sign_sample_produces_short_vector() {
        // Use a real keypair to test that sign_sample produces valid signatures.
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(42);
        let keypair = crate::generate_keypair(&mut rng)
            .expect("Key generation should succeed");

        let message = b"test canonical signing";
        let nonce = [0u8; 40];
        let c = crate::nist_hash::hash_to_point_nist(&nonce, message);

        let sigma = 165.7366171829776;
        let (s0, s1) = falcon_sign_sample(
            &keypair.private_key.f.coeffs,
            &keypair.private_key.g.coeffs,
            &keypair.private_key.big_f.coeffs,
            &keypair.private_key.big_g.coeffs,
            &c,
            sigma,
            &mut rng,
        )
        .expect("post-GS-bound keygen output must be inside the sigma band");

        assert_eq!(s0.len(), N);
        assert_eq!(s1.len(), N);

        // Check norm bound: ||(s0, s1)||^2 < beta^2
        let mut norm_sq: i64 = 0;
        for &x in &s0 {
            norm_sq += (x as i64) * (x as i64);
        }
        for &x in &s1 {
            norm_sq += (x as i64) * (x as i64);
        }

        assert!(
            norm_sq < BETA_SQUARED as i64,
            "Signature norm^2 = {} exceeds beta^2 = {}",
            norm_sq,
            BETA_SQUARED
        );

        // Verify NTRU equation: s0 + s1*h = c (mod q)
        let s1h = crate::ntt_falcon::multiply_ntt(&s1, &keypair.public_key.h.coeffs);
        for i in 0..N {
            let lhs = (s0[i] as i32 + s1h[i] as i32).rem_euclid(Q as i32);
            let rhs = (c[i] as i32).rem_euclid(Q as i32);
            assert_eq!(
                lhs, rhs,
                "NTRU equation failed at index {}: {} != {}",
                i, lhs, rhs
            );
        }
    }
}
