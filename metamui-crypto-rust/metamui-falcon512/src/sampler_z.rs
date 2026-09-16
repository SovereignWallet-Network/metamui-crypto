//! `SamplerZ` — the discrete Gaussian sampler over the integers that Falcon
//! signing is defined in terms of (Falcon Round-3 specification, §3.9,
//! Algorithms 12–15).
//!
//! # Why this module exists
//!
//! Until it did, there was no Gaussian sampling anywhere on the signing path.
//! `falcon_canonical::ffsampling` matched its LDL leaf as
//! `LdlTree::Leaf { .. }` — discarding the `sigma0`/`sigma1` the tree had just
//! computed — and returned `f64_round(t)`, plain Babai nearest-plane rounding.
//! `falcon_sign_sample` took no RNG parameter at all.
//!
//! That is not a Falcon signature distribution. Babai rounding leaves the
//! per-coordinate error uniform on `[-1/2, 1/2]` along the Gram–Schmidt basis,
//! so for an NTRU basis (`det = q^n` over `2n` vectors, geometric mean
//! `||b*_i|| = sqrt(q)`):
//!
//! ```text
//!   E||s||^2  ~  2n*q/12  =  1024 * 12289 / 12  =  1,048,661
//!   sigma_eff =  sqrt(q/12)                     =  32.0013
//! ```
//!
//! against the specified `E||s||^2 = 2n*sigma^2 = 28,127,873` and
//! `sigma = 165.7366171829776` — a factor of `1.17*sigma_min*sqrt(12) = 5.179`
//! too narrow in sigma, 26x in squared norm. That matched the measurement
//! reported downstream to five decimal places.
//!
//! It matters because Falcon's security argument (GPV / Klein sampling)
//! requires the emitted `(s0, s1)` to follow the specified discrete Gaussian
//! **independently of the secret basis**. That independence is precisely what
//! makes a transcript of signatures simulatable without the trapdoor.
//! Deterministic rounding confines the error to the fundamental parallelepiped
//! of the secret basis, which is the GGH/NTRUSign construction that the
//! Nguyen–Regev "Learning a Parallelepiped" attack recovers the basis from.
//!
//! # Constant-time status — read before relying on this
//!
//! **This module is not constant-time, and does not claim to be.** The RCDT
//! scan is branch-free and fixed-length, but the acceptance test computes in
//! `f64` (see `ber_exp`) and the rejection loop runs a data-dependent number of
//! iterations, exactly as the specification's does.
//!
//! The reference implementation avoids `f64` here by way of an emulated
//! fixed-point float (`fpr`) and a polynomial `ApproxExp`. Reproducing that
//! would mean converting the whole surrounding path — `falcon_canonical`'s FFT,
//! the LDL tree, the leaf widths feeding this module — which is `f64`/`C64` end
//! to end. Constant-time discipline in this one file, bolted to an `f64` FFT,
//! would be a claim rather than a property.
//!
//! The two defects are also not comparable in reach. A timing side channel
//! requires an attacker measuring a victim's signer. A wrong output
//! distribution weakens every signature ever produced, passively, with no
//! attacker interaction at all. This module fixes the second. The first is
//! real, unfixed, predates this module, and is tracked separately.

use rand::RngCore;

/// Falcon's `sigma_max`: the fixed width of the half-Gaussian the base sampler
/// draws from, and the scale the `RCDT` table below is built for.
pub const SIGMA_MAX: f64 = 1.8205;

/// Reverse cumulative distribution table for the half-Gaussian with
/// `sigma = SIGMA_MAX`, scaled by `2^72` (Falcon Round-3 spec, Table 3.2).
///
/// Reverse-cumulative, hence monotonically **decreasing**: `RCDT[i]` is
/// `2^72 * P(z > i)`. `base_sampler` returns the number of entries strictly
/// greater than a 72-bit uniform draw.
///
/// Nothing already in this crate could be reused for this, which is worth
/// recording so the next person does not go looking:
///
/// * `gaussian_sampler_proper.rs`'s 19-entry table crosses one half at `z = 3`,
///   impossible for a `sigma = 1.8205` half-Gaussian (median ~1). Every method
///   in that module returns `NotImplemented` regardless.
/// * `gaussian.rs`'s `GAUSSIAN_CDT` is commented as this table but is not one:
///   it *increases*, where a reverse-CDT must decrease, and its first entry is
///   ~1.9e10 against the 3.0e21 that `2^72 * P(z > 0)` requires. Whatever those
///   constants are for, they are not this. That module is also not declared in
///   `lib.rs`, so nothing ever compiled it.
///
/// Verified by `rcdt_is_strictly_decreasing_and_scaled_to_2_pow_72` below, which
/// pins both properties the two tables above violate.
const RCDT: [u128; 18] = [
    3024686241123004913666,
    1564742784480091954050,
    636254429462080897535,
    199560484645026482916,
    47667343854657281903,
    8595902006365044063,
    1163297957344668388,
    117656387352093658,
    8867391802663976,
    496969357462633,
    20680885154299,
    638331848991,
    14602316184,
    247426747,
    3104126,
    28824,
    198,
    1,
];

/// Draw one uniform byte.
#[inline]
fn next_byte<R: RngCore>(rng: &mut R) -> u8 {
    let mut b = [0u8; 1];
    rng.fill_bytes(&mut b);
    b[0]
}

/// Draw a uniform `f64` in `[0, 1)` with 53 bits of precision.
#[inline]
fn next_uniform<R: RngCore>(rng: &mut R) -> f64 {
    // 53 significant bits is the whole f64 mantissa; taking the top bits of a
    // 64-bit draw avoids the modulo bias a `% n` would introduce.
    ((rng.next_u64() >> 11) as f64) * (1.0 / ((1u64 << 53) as f64))
}

/// Sample from the half-Gaussian with `sigma = SIGMA_MAX`, supported on
/// non-negative integers (spec Algorithm 12, `BaseSampler`).
///
/// Consumes 72 uniform bits and scans the whole table — the loop length does
/// not depend on the value drawn.
fn base_sampler<R: RngCore>(rng: &mut R) -> i32 {
    let mut buf = [0u8; 9]; // 72 bits
    rng.fill_bytes(&mut buf);

    let mut u: u128 = 0;
    for &b in buf.iter() {
        u = (u << 8) | u128::from(b);
    }

    let mut z = 0i32;
    for &threshold in RCDT.iter() {
        // Branch-free: no early exit, so the count is what varies, not the work.
        z += i32::from(u < threshold);
    }
    z
}

/// Return `true` with probability `ccs * exp(-x)`, for `x >= 0` and
/// `ccs` in `(0, 1]` (spec Algorithm 14, `BerExp`).
///
/// # Deviation from the reference, stated plainly
///
/// The specification computes this acceptance probability with a fixed-point
/// polynomial (`ApproxExp`, Algorithm 13) rather than a floating-point `exp`.
/// That choice buys exactly one thing: it keeps the rejection step free of
/// `f64`, whose timing can depend on operand values.
///
/// This implementation calls `f64::exp` directly. The reasons:
///
/// * The property the polynomial protects is **already unavailable here.** The
///   whole surrounding path — `falcon_canonical`'s FFT, the LDL tree, the leaf
///   widths this function's `x` is derived from — is `f64`/`C64` end to end.
///   A fixed-point `ber_exp` bolted onto an `f64` FFT does not produce a
///   constant-time signer; it produces a constant-time 20 lines.
/// * `exp` is *more* accurate than the degree-18 approximation, so the emitted
///   distribution is at least as correct.
/// * It is reviewable. The defect being fixed here shipped because nobody could
///   tell by reading that the leaf wasn't sampling; a hand-transcribed
///   fixed-point table that no test can distinguish from a wrong one would be
///   the same category of hazard.
///
/// Converting the signing path to the emulated-float (`fpr`) arithmetic the
/// reference uses is real work and a genuinely separate concern: a timing side
/// channel needs an attacker measuring a victim's signer, whereas the wrong
/// distribution harms every signature passively. Fix the distribution first.
fn ber_exp<R: RngCore>(x: f64, ccs: f64, rng: &mut R) -> bool {
    debug_assert!(x >= 0.0, "ber_exp: x = {x} must be non-negative");
    next_uniform(rng) < ccs * (-x).exp()
}

/// Sample an integer from the discrete Gaussian centred at `mu` with standard
/// deviation `sigma` (spec Algorithm 15, `SamplerZ`).
///
/// # Precondition on `sigma`
///
/// `sigma_min <= sigma <= SIGMA_MAX`. This is not decorative. The base sampler
/// draws from a **wider** half-Gaussian (`SIGMA_MAX = 1.8205`) and `ber_exp`
/// narrows it by rejection, so the rejection exponent
/// `x = (z-r)^2/(2*sigma^2) - z0^2/(2*SIGMA_MAX^2)` is only non-negative while
/// the target is the narrower of the two. Ask for `sigma > SIGMA_MAX` and `x`
/// goes negative, `exp(-x) > 1`, and the acceptance test silently stops
/// shaping the distribution — you get the base sampler's shape, offset by the
/// fold, not what you asked for.
///
/// In Falcon this holds by construction: `sigma` arrives as an LDL leaf width
/// `sigma / sqrt(d)`, and the tree's `d` values keep every leaf inside the
/// band. The `debug_assert!` is there to catch a caller that wires this up to
/// something else.
///
/// **The RNG is supplied by the caller and every draw comes from it.** That is
/// both the spec's construction (`SamplerZ` is defined over a caller-supplied
/// PRNG) and what preserves deterministic signing for callers who seed the
/// stream themselves: reaching for `OsRng` in here would silently break every
/// `(seed, sk, msg) -> signature` reproducibility guarantee downstream.
pub fn sampler_z<R: RngCore>(mu: f64, sigma: f64, sigma_min: f64, rng: &mut R) -> i32 {
    debug_assert!(
        sigma > 0.0 && sigma <= SIGMA_MAX,
        "sampler_z: sigma = {sigma} outside (0, {SIGMA_MAX}]; the rejection step \
         cannot widen the base sampler, so the result would not be the requested \
         distribution"
    );

    let s = mu.floor();
    let r = mu - s;
    let dss = 1.0 / (2.0 * sigma * sigma);
    let ccs = sigma_min / sigma;

    loop {
        let z0 = base_sampler(rng);
        let b = i32::from(next_byte(rng) & 1);
        // Fold the half-Gaussian to a full one: b = 1 -> +z0 + 1, b = 0 -> -z0.
        let z = b + (2 * b - 1) * z0;

        let zf = f64::from(z);
        let x = ((zf - r) * (zf - r)) * dss - f64::from(z0 * z0) / (2.0 * SIGMA_MAX * SIGMA_MAX);

        if ber_exp(x, ccs, rng) {
            return z + s as i32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// The RCDT must be strictly decreasing and start just under 2^72 — the
    /// property that makes `base_sampler`'s "count entries above u" correct.
    /// A table pasted in the forward-cumulative direction (the mistake in
    /// `gaussian_sampler_proper.rs`) fails here.
    #[test]
    fn rcdt_is_strictly_decreasing_and_scaled_to_2_pow_72() {
        for w in RCDT.windows(2) {
            assert!(w[0] > w[1], "RCDT must be strictly decreasing: {:?}", w);
        }
        assert!(RCDT[0] < (1u128 << 72), "RCDT[0] must fit under 2^72");
        // P(z > 0) ~ 0.64 for a half-Gaussian at sigma=1.8205.
        let p0 = RCDT[0] as f64 / (1u128 << 72) as f64;
        assert!(
            (0.60..0.70).contains(&p0),
            "RCDT[0]/2^72 = {p0}, expected ~0.64"
        );
    }

    /// The base sampler must reproduce the moments **the RCDT itself encodes**,
    /// which are computed here from the table rather than from a continuous
    /// half-Gaussian. Those differ: `E[z0]` is 1.16103 from the table against
    /// 1.4526 for a continuous half-Gaussian at the same sigma. The base
    /// distribution is deliberately not the target — it is flatter, with heavier
    /// tails, so that `ber_exp`'s rejection can shape it *down* to the requested
    /// sigma. Asserting against the continuous value would fail a correct
    /// sampler.
    #[test]
    fn base_sampler_reproduces_the_rcdt_moments() {
        // E[z0]   = sum_i P(z0 > i)        = sum(RCDT)/2^72
        // E[z0^2] = sum_i (2i+1) P(z0 > i)
        let two72 = (1u128 << 72) as f64;
        let expected_mean = RCDT.iter().map(|&v| v as f64).sum::<f64>() / two72;
        let expected_m2 = RCDT
            .iter()
            .enumerate()
            .map(|(i, &v)| (2 * i + 1) as f64 * v as f64)
            .sum::<f64>()
            / two72;

        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        const N: usize = 200_000;

        let mut sum = 0f64;
        let mut sum_sq = 0f64;
        for _ in 0..N {
            let z = base_sampler(&mut rng);
            assert!(z >= 0, "half-Gaussian must be non-negative, got {z}");
            sum += f64::from(z);
            sum_sq += f64::from(z * z);
        }

        let mean = sum / N as f64;
        assert!(
            (mean - expected_mean).abs() / expected_mean < 0.02,
            "base sampler mean {mean:.4}, table says {expected_mean:.4}"
        );

        let m2 = sum_sq / N as f64;
        assert!(
            (m2 - expected_m2).abs() / expected_m2 < 0.02,
            "base sampler E[z^2] {m2:.4}, table says {expected_m2:.4}"
        );
    }

    /// `sampler_z` must produce the requested width and centre. This is the
    /// assertion whose absence let the Babai-rounding leaf ship: rounding would
    /// give a standard deviation of ~0.29 (uniform on [-1/2,1/2]) instead of
    /// the sigma asked for.
    ///
    /// Every sigma here is inside `[SIGMA_MIN, SIGMA_MAX]`, which is the band
    /// LDL leaf widths actually land in — see the precondition on `sampler_z`.
    #[test]
    fn sampler_z_matches_requested_mean_and_sigma() {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        const N: usize = 100_000;

        for &(mu, sigma) in &[(0.0f64, 1.8f64), (0.3, 1.5), (-1.7, 1.3)] {
            let mut sum = 0f64;
            let mut sum_sq = 0f64;
            for _ in 0..N {
                let z = f64::from(sampler_z(mu, sigma, 1.2778336969128337, &mut rng));
                sum += z;
                sum_sq += z * z;
            }
            let mean = sum / N as f64;
            let var = sum_sq / N as f64 - mean * mean;
            let sd = var.sqrt();

            assert!(
                (mean - mu).abs() < 0.05 * sigma,
                "mu={mu} sigma={sigma}: sample mean {mean:.4} too far from {mu}"
            );
            assert!(
                (sd - sigma).abs() / sigma < 0.05,
                "mu={mu} sigma={sigma}: sample sd {sd:.4} != requested {sigma}"
            );
        }
    }

    /// Same seed must give the same draws — the property the whole signing
    /// path's determinism rests on. If this ever fails, something in here
    /// reached for entropy that is not the caller's RNG.
    #[test]
    fn sampling_is_a_pure_function_of_the_supplied_rng() {
        let draw = || {
            let mut rng = ChaCha20Rng::from_seed([29u8; 32]);
            (0..64)
                .map(|_| sampler_z(0.25, 1.6, 1.2778336969128337, &mut rng))
                .collect::<Vec<_>>()
        };
        assert_eq!(draw(), draw());
    }

    /// Different seeds must give different draws — guards against a stub that
    /// ignores the RNG entirely, which is the shape of the bug being fixed.
    #[test]
    fn different_seeds_produce_different_draws() {
        let draw = |seed: u8| {
            let mut rng = ChaCha20Rng::from_seed([seed; 32]);
            (0..64)
                .map(|_| sampler_z(0.25, 1.6, 1.2778336969128337, &mut rng))
                .collect::<Vec<_>>()
        };
        assert_ne!(draw(31), draw(37));
    }
}
