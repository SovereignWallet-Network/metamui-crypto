//! Polynomial vector operations for HAETAE
//!
//! This module implements vectors of polynomials used in the HAETAE signature scheme.
//! HAETAE uses three vector types based on security level parameters:
//! - `PolyVecK`: Vector of K polynomials (K=2,3,4)
//! - `PolyVecL`: Vector of L polynomials (L=4,6,7)
//! - `PolyVecM`: Vector of M polynomials (M=L-1=3,5,6)
//!
//! Transcopy from: metamui-haetae/src/polyvec.c
//!
//! Note: This is a subset of the full polyvec API, covering core operations
//! needed for the Phase 4 demonstration. Full transcopy will be completed
//! in subsequent phases.

use crate::params::{K, L, M, N, Q, SEEDBYTES, CRHBYTES, POLY_HIGHBITS_PACKEDBYTES, POLYVECK_HIGHBITS_PACKEDBYTES};
use crate::poly::Poly;
use crate::ntt::{ntt, invntt_tomont};
use zeroize::Zeroize;

/// Vector of K polynomials
///
/// Used for public key and intermediate computations in HAETAE.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct PolyVecK {
    /// Array of K polynomials
    pub vec: [Poly; K],
}

/// Vector of L polynomials
///
/// Used for secret key components and signing operations.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct PolyVecL {
    /// Array of L polynomials
    pub vec: [Poly; L],
}

/// Vector of M polynomials
///
/// Where M = L - 1, used for secret key components.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct PolyVecM {
    /// Array of M polynomials
    pub vec: [Poly; M],
}

// ============================================================================
// PolyVecK Operations
// ============================================================================

impl PolyVecK {
    /// Create new zero vector
    pub fn new() -> Self {
        Self {
            vec: core::array::from_fn(|_| Poly::new()),
        }
    }

    /// Add two vectors: w = u + v
    ///
    /// No modular reduction is performed.
    ///
    /// Transcopy from: void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v)
    pub fn add(&mut self, u: &PolyVecK, v: &PolyVecK) {
        for i in 0..K {
            self.vec[i].add(&u.vec[i], &v.vec[i]);
        }
    }

    /// Subtract two vectors: w = u - v
    ///
    /// No modular reduction is performed.
    ///
    /// Transcopy from: void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v)
    pub fn sub(&mut self, u: &PolyVecK, v: &PolyVecK) {
        for i in 0..K {
            self.vec[i].sub(&u.vec[i], &v.vec[i]);
        }
    }

    /// In-place add: self += v
    pub fn add_assign(&mut self, v: &PolyVecK) {
        for i in 0..K {
            self.vec[i].add_assign(&v.vec[i]);
        }
    }

    /// In-place subtract: self -= v
    pub fn sub_assign(&mut self, v: &PolyVecK) {
        for i in 0..K {
            self.vec[i].sub_assign(&v.vec[i]);
        }
    }

    /// Double vector: b = 2*b
    ///
    /// No modular reduction is performed.
    ///
    /// Transcopy from: void polyveck_double(polyveck *b)
    pub fn double(&mut self) {
        for i in 0..K {
            for j in 0..N {
                self.vec[i].coeffs[j] *= 2;
            }
        }
    }

    /// Reduce all coefficients modulo 2Q
    ///
    /// Transcopy from: void polyveck_reduce2q(polyveck *v)
    pub fn reduce2q(&mut self) {
        for i in 0..K {
            self.vec[i].reduce2q();
        }
    }

    /// Freeze all coefficients to [0, Q)
    ///
    /// Transcopy from: void polyveck_freeze(polyveck *v)
    pub fn freeze(&mut self) {
        for i in 0..K {
            self.vec[i].freeze();
        }
    }

    /// Apply forward NTT to all polynomials
    ///
    /// Transcopy from: void polyveck_ntt(polyveck *x)
    pub fn ntt(&mut self) {
        for i in 0..K {
            ntt(&mut self.vec[i].coeffs);
        }
    }

    /// Apply inverse NTT with Montgomery multiplication to all polynomials
    ///
    /// Transcopy from: void polyveck_invntt_tomont(polyveck *x)
    pub fn invntt_tomont(&mut self) {
        for i in 0..K {
            invntt_tomont(&mut self.vec[i].coeffs);
        }
    }

    /// Compute squared L2 norm
    ///
    /// Returns the sum of squares of all coefficients across all polynomials.
    ///
    /// Transcopy from: uint64_t polyveck_sqnorm2(const polyveck *b)
    pub fn sqnorm2(&self) -> u64 {
        let mut r = 0u64;
        for i in 0..K {
            for j in 0..N {
                let c = self.vec[i].coeffs[j] as i64;
                r += (c * c) as u64;
            }
        }
        r
    }

    /// Sample vector of polynomials with uniformly random coefficients
    ///
    /// Uses SHAKE128(seed||nonce) to expand each polynomial.
    /// Nonces start from (K << 8) + M and increment for each polynomial.
    ///
    /// # Arguments
    /// * `seed` - Seed bytes for polynomial expansion
    ///
    /// Transcopy from: void polyveck_expand(polyveck *v, const uint8_t seed[SEEDBYTES])
    pub fn expand(&mut self, seed: &[u8; SEEDBYTES]) {
        let mut nonce = ((K << 8) + M) as u16;
        for i in 0..K {
            self.vec[i].uniform(seed, nonce);
            nonce += 1;
        }
    }

    /// Freeze all coefficients to [0, 2Q)
    ///
    /// Transcopy from: void polyveck_freeze2q(polyveck *v)
    pub fn freeze2q(&mut self) {
        for i in 0..K {
            self.vec[i].freeze2q();
        }
    }

    /// Double and negate: multiply each coefficient by -2 in Montgomery form
    ///
    /// Transcopy from: void polyveck_double_negate(polyveck *v)
    pub fn double_negate(&mut self) {
        use crate::reduce::{MONT, montgomery_reduce};

        for i in 0..K {
            for j in 0..N {
                self.vec[i].coeffs[j] = montgomery_reduce(
                    self.vec[i].coeffs[j] as i64 * MONT as i64 * -2
                );
            }
        }
    }

    /// Multiply each coefficient by MONT (remove Montgomery form)
    ///
    /// Transcopy from: void polyveck_frommont(polyveck *v)
    pub fn frommont(&mut self) {
        use crate::reduce::{MONTSQ, montgomery_reduce};

        for i in 0..K {
            for j in 0..N {
                self.vec[i].coeffs[j] = montgomery_reduce(
                    self.vec[i].coeffs[j] as i64 * MONTSQ as i64
                );
            }
        }
    }

    /// Conditionally add Q if coefficient is negative
    ///
    /// Transcopy from: void polyveck_caddq(polyveck *v)
    pub fn caddq(&mut self) {
        use crate::reduce::caddq;

        for i in 0..K {
            for j in 0..N {
                self.vec[i].coeffs[j] = caddq(self.vec[i].coeffs[j]);
            }
        }
    }

    /// Decompose for D-bit rounding (HAETAE-2/3, D=1)
    ///
    /// For each coefficient a, compute a0, a1 such that a = a1*2^D + a0
    /// with -2^{D-1} <= a0 < 2^{D-1}. Assumes a is in [0, Q).
    ///
    /// # Arguments
    /// * `v0` - Output vector for low bits a0
    ///
    /// Transcopy from: void polyveck_decompose_vk(polyveck *v0, polyveck *v)
    #[cfg(any(feature = "haetae2", feature = "haetae3"))]
    pub fn decompose_vk(&mut self, v0: &mut PolyVecK) {
        for i in 0..K {
            for j in 0..N {
                let a = self.vec[i].coeffs[j];
                let mut a0 = a & 1;
                a0 -= ((a >> 1) & a0) << 1;
                v0.vec[i].coeffs[j] = a0;
                self.vec[i].coeffs[j] = (a - a0) >> 1;
            }
        }
    }

    /// Conditional negate
    ///
    /// Multiply all coefficients by (1 - 2*b) where b is 0 or 1.
    ///
    /// Transcopy from: void polyveck_cneg(polyveck *v, const uint8_t b)
    pub fn cneg(&mut self, b: u8) {
        for i in 0..K {
            for j in 0..N {
                self.vec[i].coeffs[j] *= 1 - 2 * (b as i32);
            }
        }
    }

    /// Pointwise Montgomery multiplication of vector by polynomial
    ///
    /// Multiplies each polynomial in u by scalar polynomial v.
    /// Inputs must be in NTT domain.
    ///
    /// Transcopy from: void polyveck_poly_pointwise_montgomery(polyveck *w, const polyveck *u, const poly *v)
    pub fn poly_pointwise_montgomery(&mut self, u: &PolyVecK, v: &Poly) {
        for i in 0..K {
            self.vec[i].pointwise_montgomery(&u.vec[i], v);
        }
    }

    /// Conditional add DQ / (2 * ALPHA_HINT)
    ///
    /// Add (DQ - 2) / ALPHA_HINT to negative coefficients.
    ///
    /// Transcopy from: void polyveck_caddDQ2ALPHA(polyveck *h)
    pub fn cadd_dq2alpha(&mut self) {
        use crate::params::{DQ, ALPHA_HINT};
        for i in 0..K {
            for j in 0..N {
                self.vec[i].coeffs[j] += (self.vec[i].coeffs[j] >> 31) & ((DQ - 2) / ALPHA_HINT);
            }
        }
    }

    /// Conditional subtract DQ / (2 * ALPHA_HINT)
    ///
    /// Subtract (DQ - 2) / ALPHA_HINT from coefficients >= (DQ - 2) / ALPHA_HINT.
    ///
    /// Transcopy from: void polyveck_csubDQ2ALPHA(polyveck *v)
    pub fn csub_dq2alpha(&mut self) {
        use crate::params::{DQ, ALPHA_HINT};
        for i in 0..K {
            for j in 0..N {
                let threshold = (DQ - 2) / ALPHA_HINT;
                self.vec[i].coeffs[j] -=
                    !(((self.vec[i].coeffs[j] - threshold) >> 31) as u32) as i32 & threshold;
            }
        }
    }

    /// Multiply vector by ALPHA_HINT
    ///
    /// v = u * ALPHA_HINT
    ///
    /// Transcopy from: void polyveck_mul_alpha(polyveck *v, const polyveck *u)
    pub fn mul_alpha(&mut self, u: &PolyVecK) {
        use crate::params::ALPHA_HINT;
        for i in 0..K {
            for j in 0..N {
                self.vec[i].coeffs[j] = u.vec[i].coeffs[j] * ALPHA_HINT;
            }
        }
    }

    /// Divide vector by 2 (arithmetic right shift)
    ///
    /// Transcopy from: void polyveck_div2(polyveck *v)
    pub fn div2(&mut self) {
        for i in 0..K {
            for j in 0..N {
                self.vec[i].coeffs[j] >>= 1;
            }
        }
    }

    /// Compute high bits for hint
    ///
    /// Transcopy from: void polyveck_highbits_hint(polyveck *w, const polyveck *v)
    pub fn highbits_hint(&mut self, v: &PolyVecK) {
        use crate::reduce::decompose_hint;
        for i in 0..K {
            for j in 0..N {
                self.vec[i].coeffs[j] = decompose_hint(v.vec[i].coeffs[j]);
            }
        }
    }

    /// In-place highbits hint (eliminates clone for self-aliasing)
    pub fn highbits_hint_inplace(&mut self) {
        use crate::reduce::decompose_hint;
        for i in 0..K {
            for j in 0..N {
                self.vec[i].coeffs[j] = decompose_hint(self.vec[i].coeffs[j]);
            }
        }
    }

    /// CRT reconstruction with parity check
    ///
    /// Transcopy from: void polyveck_poly_fromcrt(polyveck *w, const polyveck *u, const poly *v)
    pub fn poly_fromcrt(&mut self, u: &PolyVecK, v: &Poly) {
        self.vec[0].fromcrt(&u.vec[0], v);
        for i in 1..K {
            self.vec[i].fromcrt0(&u.vec[i]);
        }
    }

    /// In-place CRT reconstruction (eliminates clone for self-aliasing)
    pub fn poly_fromcrt_inplace(&mut self, v: &Poly) {
        // vec[0]: fromcrt with self as input
        for j in 0..N {
            let xq = self.vec[0].coeffs[j];
            let x2 = v.coeffs[j];
            self.vec[0].coeffs[j] = xq + (Q & -((xq ^ x2) & 1));
        }
        // vec[1..K]: fromcrt0 with self as input
        for i in 1..K {
            for j in 0..N {
                let xq = self.vec[i].coeffs[j];
                self.vec[i].coeffs[j] = xq + (Q & -(xq & 1));
            }
        }
    }

    /// Pack high bits into bytes
    ///
    /// Transcopy from: void polyveck_pack_highbits(uint8_t *buf, const polyveck *v)
    pub fn pack_highbits(&self, buf: &mut [u8; POLYVECK_HIGHBITS_PACKEDBYTES]) {
        for i in 0..K {
            let start = i * POLY_HIGHBITS_PACKEDBYTES;
            // Explicit &mut binding prevents try_into() from resolving to the
            // copying TryFrom<&[u8]> for [u8; N] impl (which writes to a temporary).
            let sub: &mut [u8; POLY_HIGHBITS_PACKEDBYTES] =
                (&mut buf[start..start + POLY_HIGHBITS_PACKEDBYTES]).try_into().unwrap();
            self.vec[i].pack_highbits(sub);
        }
    }
}

impl Default for PolyVecK {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PolyVecL Operations
// ============================================================================

impl PolyVecL {
    /// Create new zero vector
    pub fn new() -> Self {
        Self {
            vec: core::array::from_fn(|_| Poly::new()),
        }
    }

    /// Apply forward NTT to all polynomials
    ///
    /// Transcopy from: void polyvecl_ntt(polyvecl *x)
    pub fn ntt(&mut self) {
        for i in 0..L {
            ntt(&mut self.vec[i].coeffs);
        }
    }

    /// Extract high bits of all polynomials
    ///
    /// Transcopy from: void polyvecl_highbits(polyvecl *v2, const polyvecl *v)
    pub fn highbits(&mut self, v: &PolyVecL) {
        for i in 0..L {
            self.vec[i].highbits(&v.vec[i]);
        }
    }

    /// Extract low bits of all polynomials
    ///
    /// Transcopy from: void polyvecl_lowbits(polyvecl *v1, const polyvecl *v)
    pub fn lowbits(&mut self, v: &PolyVecL) {
        for i in 0..L {
            self.vec[i].lowbits(&v.vec[i]);
        }
    }

    /// Compute squared L2 norm
    ///
    /// Transcopy from: uint64_t polyvecl_sqnorm2(const polyvecl *a)
    pub fn sqnorm2(&self) -> u64 {
        let mut r = 0u64;
        for i in 0..L {
            for j in 0..N {
                let c = self.vec[i].coeffs[j] as i64;
                r += (c * c) as u64;
            }
        }
        r
    }

    /// Pointwise multiply and accumulate: w = sum(u[i] * v[i])
    ///
    /// Input vectors must be in NTT domain.
    ///
    /// Transcopy from: void polyvecl_pointwise_acc_montgomery(poly *w, ...)
    pub fn pointwise_acc_montgomery(&self, v: &PolyVecL) -> Poly {
        let mut w = Poly::new();
        w.pointwise_montgomery(&self.vec[0], &v.vec[0]);

        let mut t = Poly::new();
        for i in 1..L {
            t.pointwise_montgomery(&self.vec[i], &v.vec[i]);
            w.add_assign(&t);
        }

        w
    }

    /// Conditional negate
    ///
    /// Multiply all coefficients by (1 - 2*b) where b is 0 or 1.
    ///
    /// Transcopy from: void polyvecl_cneg(polyvecl *v, const uint8_t b)
    pub fn cneg(&mut self, b: u8) {
        for i in 0..L {
            for j in 0..N {
                self.vec[i].coeffs[j] *= 1 - 2 * (b as i32);
            }
        }
    }
}

impl Default for PolyVecL {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PolyVecM Operations
// ============================================================================

impl PolyVecM {
    /// Create new zero vector
    pub fn new() -> Self {
        Self {
            vec: core::array::from_fn(|_| Poly::new()),
        }
    }

    /// Apply forward NTT to all polynomials
    ///
    /// Transcopy from: void polyvecm_ntt(polyvecm *x)
    pub fn ntt(&mut self) {
        for i in 0..M {
            ntt(&mut self.vec[i].coeffs);
        }
    }

    /// Pointwise multiply and accumulate: w = sum(u[i] * v[i])
    ///
    /// Input vectors must be in NTT domain.
    ///
    /// Transcopy from: void polyvecm_pointwise_acc_montgomery(poly *w, ...)
    pub fn pointwise_acc_montgomery(&self, v: &PolyVecM) -> Poly {
        let mut w = Poly::new();
        w.pointwise_montgomery(&self.vec[0], &v.vec[0]);

        let mut t = Poly::new();
        for i in 1..M {
            t.pointwise_montgomery(&self.vec[i], &v.vec[i]);
            w.add_assign(&t);
        }

        w
    }
}

/// Sample PolyVecM and PolyVecK with bounded coefficients
///
/// Samples M+K polynomials with coefficients in [-ETA, ETA] using
/// SHAKE256(seed||nonce) for each polynomial.
///
/// # Arguments
/// * `u` - Output PolyVecM (M polynomials)
/// * `v` - Output PolyVecK (K polynomials)
/// * `seed` - Seed bytes for sampling
/// * `nonce` - Starting nonce (increments for each polynomial)
///
/// Transcopy from: void polyvecmk_uniform_eta(polyvecm *u, polyveck *v, ...)
pub fn polyvecmk_uniform_eta(
    u: &mut PolyVecM,
    v: &mut PolyVecK,
    seed: &[u8; CRHBYTES],
    nonce: u16
) {
    let mut n = nonce;

    // Sample M polynomials for u
    for i in 0..M {
        u.vec[i].uniform_eta(seed, n);
        n += 1;
    }

    // Sample K polynomials for v
    for i in 0..K {
        v.vec[i].uniform_eta(seed, n);
        n += 1;
    }
}

/// Compute squared singular value for rejection sampling in key generation
///
/// This function computes the squared maximum singular value of the concatenated
/// secret key matrix [s1 || s2] using FFT-based spectral analysis.
///
/// # Arguments
/// * `s1` - First part of secret key (M polynomials)
/// * `s2` - Second part of secret key (K polynomials)
///
/// # Returns
/// Squared singular value (scaled and rounded)
///
/// Transcopy from: int64_t polyvecmk_sqsing_value(const polyvecm *s1, const polyveck *s2)
pub fn polyvecmk_sqsing_value(s1: &PolyVecM, s2: &PolyVecK) -> i64 {
    use crate::fft::{fft, fft_init_and_bitrev, complex_fp_sqabs, Complex, FFT_N};
    use crate::params::TAU;

    // Helper function for constant-time min/max swap (from djbsort)
    #[inline]
    fn minmax(x: &mut i32, y: &mut i32) {
        let a = *x;
        let b = *y;
        let ab = b ^ a;
        let mut c = b - a;
        c ^= ab & (c ^ b);
        c >>= 31;
        c &= ab;
        *x = a ^ c;
        *y = b ^ c;
    }

    let mut input = [Complex { real: 0, imag: 0 }; FFT_N];
    let mut sum = [0i32; N];
    let mut bestm = [0i32; N / TAU + 1];

    // Compute cumulative sum of squared magnitudes for s1
    for i in 0..M {
        fft_init_and_bitrev(&mut input, &s1.vec[i]);
        fft(&mut input);
        for j in 0..N {
            sum[j] += complex_fp_sqabs(input[j]);
        }
    }

    // Compute cumulative sum of squared magnitudes for s2
    for i in 0..K {
        fft_init_and_bitrev(&mut input, &s2.vec[i]);
        fft(&mut input);
        for j in 0..N {
            sum[j] += complex_fp_sqabs(input[j]);
        }
    }

    // Initialize bestm with first N/TAU+1 elements
    for i in 0..(N / TAU + 1) {
        bestm[i] = sum[i];
    }

    // Compute max using min-max network
    for i in (N / TAU + 1)..N {
        for j in 0..(N / TAU + 1) {
            minmax(&mut sum[i], &mut bestm[j]);
        }
    }

    // Find minimum in bestm
    let mut min = bestm[0];
    for i in 1..(N / TAU + 1) {
        let mut tmp = bestm[i];
        minmax(&mut min, &mut tmp);
    }

    // Multiply all but the minimum by N mod TAU
    let mut res = 0i32;
    for i in 0..(N / TAU + 1) {
        let fac = (min - bestm[i]) >> 31; // all-ones if bestm[i] != min
        let fac = (fac & TAU as i32) ^ ((!fac) & ((N % TAU) as i32));
        let mut val = bestm[i];
        val += 0x10200; // add 1 for the "1 poly" in S, and prepare rounding
        val >>= 10; // round off 10 bits
        val *= fac;
        res += val;
    }

    // Return rounded, squared value
    (res as i64 + (1 << 5)) >> 6
}

impl Default for PolyVecM {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polyveck_new() {
        let v = PolyVecK::new();
        for i in 0..K {
            for j in 0..N {
                assert_eq!(v.vec[i].coeffs[j], 0);
            }
        }
    }

    #[test]
    fn test_polyveck_add() {
        let mut u = PolyVecK::new();
        let mut v = PolyVecK::new();
        let mut w = PolyVecK::new();

        u.vec[0].coeffs[0] = 10;
        v.vec[0].coeffs[0] = 20;

        w.add(&u, &v);
        assert_eq!(w.vec[0].coeffs[0], 30);
    }

    #[test]
    fn test_polyveck_double() {
        let mut v = PolyVecK::new();
        v.vec[0].coeffs[0] = 10;
        v.vec[0].coeffs[1] = 20;

        v.double();
        assert_eq!(v.vec[0].coeffs[0], 20);
        assert_eq!(v.vec[0].coeffs[1], 40);
    }

    #[test]
    fn test_polyveck_sqnorm2() {
        let mut v = PolyVecK::new();
        v.vec[0].coeffs[0] = 3;
        v.vec[0].coeffs[1] = 4;

        let norm = v.sqnorm2();
        assert_eq!(norm, 9 + 16); // 3^2 + 4^2 = 25
    }

    #[test]
    fn test_polyvecl_sqnorm2() {
        let mut v = PolyVecL::new();
        v.vec[0].coeffs[0] = 5;
        v.vec[0].coeffs[1] = 12;

        let norm = v.sqnorm2();
        assert_eq!(norm, 25 + 144); // 5^2 + 12^2 = 169
    }
}
