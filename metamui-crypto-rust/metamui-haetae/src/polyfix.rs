//! Fixed-point polynomials for HAETAE
//!
//! This module provides fixed-point polynomial types used in hyperball sampling
//! for signature generation. Coefficients are stored as i32 with LN scaling factor.
//!
//! Transcopy from: metamui-haetae/src/polyfix.c

use crate::params::{K, L, N, LN, LNBITS, LNHALF, CRHBYTES};
use crate::poly::Poly;
use crate::polyvec::{PolyVecK, PolyVecL};

/// Fixed-point polynomial
///
/// Coefficients stored with LN scaling: actual value = coeffs[i] / LN
///
/// Transcopy from: typedef struct { int32_t coeffs[N]; } polyfix;
#[derive(Clone)]
pub struct PolyFix {
    pub coeffs: [i32; N],
}

impl PolyFix {
    /// Create new zero polynomial
    pub fn new() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Add integer polynomial to fixed-point polynomial
    ///
    /// Result: c = a + b * LN
    ///
    /// Transcopy from: void polyfix_add(polyfix *c, const polyfix *a, const poly *b)
    pub fn add(&mut self, a: &PolyFix, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = a.coeffs[i] + (LN as i32) * b.coeffs[i];
        }
    }

    /// Round fixed-point polynomial to integer polynomial
    ///
    /// Transcopy from: void polyfix_round(poly *a, const polyfix *b)
    pub fn round(&self) -> Poly {
        let mut a = Poly::new();
        for i in 0..N {
            a.coeffs[i] = (self.coeffs[i] + (LNHALF as i32)) >> LNBITS;
        }
        a
    }
}

/// Subtract two fixed-point polynomials
///
/// Transcopy from: void polyfixfix_sub(polyfix *c, const polyfix *a, const polyfix *b)
fn polyfixfix_sub(a: &PolyFix, b: &PolyFix) -> PolyFix {
    let mut c = PolyFix::new();
    for i in 0..N {
        c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
    }
    c
}

/// Fixed-point polynomial vector of length L
///
/// Transcopy from: typedef struct { polyfix vec[L]; } polyfixvecl;
#[derive(Clone)]
pub struct PolyFixVecL {
    pub vec: [PolyFix; L],
}

impl PolyFixVecL {
    /// Create new zero vector
    pub fn new() -> Self {
        Self {
            vec: core::array::from_fn(|_| PolyFix::new()),
        }
    }

    /// Add integer vector to fixed-point vector
    ///
    /// Transcopy from: void polyfixvecl_add(polyfixvecl *w, const polyfixvecl *u, const polyvecl *v)
    pub fn add(&mut self, u: &PolyFixVecL, v: &PolyVecL) {
        for i in 0..L {
            self.vec[i].add(&u.vec[i], &v.vec[i]);
        }
    }

    /// Subtract two fixed-point vectors
    ///
    /// Transcopy from: void polyfixfixvecl_sub(polyfixvecl *w, const polyfixvecl *u, const polyfixvecl *v)
    pub fn sub(&mut self, u: &PolyFixVecL, v: &PolyFixVecL) {
        for i in 0..L {
            self.vec[i] = polyfixfix_sub(&u.vec[i], &v.vec[i]);
        }
    }

    /// Double vector
    ///
    /// Transcopy from: void polyfixvecl_double(polyfixvecl *b, const polyfixvecl *a)
    pub fn double(&mut self, a: &PolyFixVecL) {
        for i in 0..L {
            for j in 0..N {
                self.vec[i].coeffs[j] = 2 * a.vec[i].coeffs[j];
            }
        }
    }

    /// Round to integer vector
    ///
    /// Transcopy from: void polyfixvecl_round(polyvecl *a, const polyfixvecl *b)
    pub fn round(&self) -> PolyVecL {
        let mut a = PolyVecL::new();
        for i in 0..L {
            a.vec[i] = self.vec[i].round();
        }
        a
    }
}

/// Fixed-point polynomial vector of length K
///
/// Transcopy from: typedef struct { polyfix vec[K]; } polyfixveck;
#[derive(Clone)]
pub struct PolyFixVecK {
    pub vec: [PolyFix; K],
}

impl PolyFixVecK {
    /// Create new zero vector
    pub fn new() -> Self {
        Self {
            vec: core::array::from_fn(|_| PolyFix::new()),
        }
    }

    /// Add integer vector to fixed-point vector
    ///
    /// Transcopy from: void polyfixveck_add(polyfixveck *w, const polyfixveck *u, const polyveck *v)
    pub fn add(&mut self, u: &PolyFixVecK, v: &PolyVecK) {
        for i in 0..K {
            self.vec[i].add(&u.vec[i], &v.vec[i]);
        }
    }

    /// Subtract two fixed-point vectors
    ///
    /// Transcopy from: void polyfixfixveck_sub(polyfixveck *w, const polyfixveck *u, const polyfixveck *v)
    pub fn sub(&mut self, u: &PolyFixVecK, v: &PolyFixVecK) {
        for i in 0..K {
            self.vec[i] = polyfixfix_sub(&u.vec[i], &v.vec[i]);
        }
    }

    /// Double vector
    ///
    /// Transcopy from: void polyfixveck_double(polyfixveck *b, const polyfixveck *a)
    pub fn double(&mut self, a: &PolyFixVecK) {
        for i in 0..K {
            for j in 0..N {
                self.vec[i].coeffs[j] = 2 * a.vec[i].coeffs[j];
            }
        }
    }

    /// Round to integer vector
    ///
    /// Transcopy from: void polyfixveck_round(polyveck *a, const polyfixveck *b)
    pub fn round(&self) -> PolyVecK {
        let mut a = PolyVecK::new();
        for i in 0..K {
            a.vec[i] = self.vec[i].round();
        }
        a
    }
}

/// Compute squared L2 norm of concatenated fixed-point vectors
///
/// Returns ||[a || b]||² in fixed-point representation
///
/// Transcopy from: uint64_t polyfixveclk_sqnorm2(const polyfixvecl *a, const polyfixveck *b)
pub fn polyfixveclk_sqnorm2(a: &PolyFixVecL, b: &PolyFixVecK) -> u64 {
    let mut ret = 0u64;

    for i in 0..L {
        for j in 0..N {
            ret = ret.wrapping_add((a.vec[i].coeffs[j] as i64 * a.vec[i].coeffs[j] as i64) as u64);
        }
    }

    for i in 0..K {
        for j in 0..N {
            ret = ret.wrapping_add((b.vec[i].coeffs[j] as i64 * b.vec[i].coeffs[j] as i64) as u64);
        }
    }

    ret
}

/// Sample from hyperball of radius B₀
///
/// Samples uniformly from hyperball using Gaussian rejection sampling,
/// then normalizes to exact radius B₀ using inverse square root.
///
/// # Arguments
/// * `y1` - Output fixed-point vector of length L
/// * `y2` - Output fixed-point vector of length K
/// * `b` - Output sign bit
/// * `seed` - SHAKE256 seed
/// * `nonce` - Starting nonce
///
/// # Returns
/// Updated nonce value
///
/// Transcopy from: uint16_t polyfixveclk_sample_hyperball(...)
pub fn polyfixveclk_sample_hyperball(
    y1: &mut PolyFixVecL,
    y2: &mut PolyFixVecK,
    b: &mut u8,
    seed: &[u8; CRHBYTES],
    nonce: u16,
) -> u16 {
    use crate::fixpoint::{fixpoint_newton_invsqrt, fixpoint_mul_high, fixpoint_mul_rnd13, Fp96_76};
    use crate::params::{B0, B0SQ, CRHBYTES, SQNM};
    use crate::sampling::sample_gauss_n;

    let mut ni = nonce;
    let mut samples = vec![0u64; N * (L + K)];
    let mut signs = vec![0u8; N * (L + K) / 8];

    loop {
        let mut sqsum = Fp96_76::new();

        // Sample first two polynomials with N+1 coefficients
        sample_gauss_n(&mut samples[0..N], &mut signs[0..N/8], &mut sqsum, seed, ni, N + 1);
        ni = ni.wrapping_add(1);
        sample_gauss_n(&mut samples[N..2*N], &mut signs[N/8..2*N/8], &mut sqsum, seed, ni, N + 1);
        ni = ni.wrapping_add(1);

        // Sample remaining polynomials with N coefficients
        for i in 2..(L + K) {
            sample_gauss_n(
                &mut samples[N * i..N * (i + 1)],
                &mut signs[N / 8 * i..N / 8 * (i + 1)],
                &mut sqsum,
                seed,
                ni,
                N,
            );
            ni = ni.wrapping_add(1);
        }

        // Divide sqsum by 2 and approximate inverse square root
        sqsum.limb48[0] = sqsum.limb48[0].wrapping_add(1); // Rounding
        sqsum.limb48[0] >>= 1;
        sqsum.limb48[0] = sqsum.limb48[0].wrapping_add((sqsum.limb48[1] & 1) << 47);
        sqsum.limb48[1] >>= 1;
        sqsum.limb48[1] = sqsum.limb48[1].wrapping_add(sqsum.limb48[0] >> 48);
        sqsum.limb48[0] &= (1u64 << 48) - 1;

        let invsqrt = fixpoint_newton_invsqrt(&sqsum);

        let scale = fixpoint_mul_high(&invsqrt, ((B0 * LN as f64 + SQNM / 2.0) as u64) << (28 - 13));

        // Apply normalization
        for i in 0..L {
            for j in 0..N {
                let sign = (signs[(i * N + j) / 8] >> ((i * N + j) % 8)) & 1;
                y1.vec[i].coeffs[j] = fixpoint_mul_rnd13(samples[i * N + j], &scale, sign);
            }
        }

        for i in L..(K + L) {
            for j in 0..N {
                let sign = (signs[(i * N + j) / 8] >> ((i * N + j) % 8)) & 1;
                y2.vec[i - L].coeffs[j] = fixpoint_mul_rnd13(samples[i * N + j], &scale, sign);
            }
        }

        // Check if norm is within bounds
        let final_norm = polyfixveclk_sqnorm2(y1, y2);
        let threshold = B0SQ as u64 * LN as u64 * LN as u64;

        if final_norm <= threshold {
            break;
        }
    }

    // Generate sign bit
    let mut tmp = vec![0u8; CRHBYTES + 2];
    tmp[..CRHBYTES].copy_from_slice(seed);
    tmp[CRHBYTES] = (ni & 0xff) as u8;
    tmp[CRHBYTES + 1] = (ni >> 8) as u8;

    let mut reader = crate::shake::shake256_multi(&[&tmp]);
    let mut b_out = [0u8; 1];
    reader.read_into(&mut b_out);
    *b = b_out[0];

    ni
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polyfix_add() {
        let a = PolyFix { coeffs: [100; N] };
        let mut b = Poly::new();
        b.coeffs[0] = 5;

        let mut c = PolyFix::new();
        c.add(&a, &b);

        assert_eq!(c.coeffs[0], 100 + 5 * (LN as i32));
        assert_eq!(c.coeffs[1], 100);
    }

    #[test]
    fn test_polyfix_round() {
        let mut p = PolyFix::new();
        p.coeffs[0] = LNHALF as i32;
        p.coeffs[1] = LN as i32;
        p.coeffs[2] = 2 * (LN as i32) + (LNHALF as i32);

        let rounded = p.round();
        assert_eq!(rounded.coeffs[0], 1);
        assert_eq!(rounded.coeffs[1], 1);
        assert_eq!(rounded.coeffs[2], 3);
    }

    #[test]
    fn test_polyfixveclk_sqnorm2() {
        let mut a = PolyFixVecL::new();
        let mut b = PolyFixVecK::new();

        a.vec[0].coeffs[0] = 10;
        b.vec[0].coeffs[0] = 20;

        let norm2 = polyfixveclk_sqnorm2(&a, &b);
        assert_eq!(norm2, 10 * 10 + 20 * 20);
    }
}
