//! Modular reduction operations for HAETAE
//!
//! This module implements various modular reduction operations used throughout
//! the HAETAE signature scheme. These are critical for maintaining correctness
//! of arithmetic operations modulo Q=64513.
//!
//! Transcopy from: metamui-haetae/src/reduce.c

use crate::params::{DQ, Q};

/// Montgomery constant: 2^32 % Q
pub const MONT: i32 = 14321;

/// Montgomery squared constant: 2^64 % Q
pub const MONTSQ: i32 = 4214;

/// Q inverse modulo 2^32: q^(-1) mod 2^32
pub const QINV: i32 = 940508161;

/// Barrett constant for Q: 2^32 / Q
pub const QREC: i32 = 66575;

/// Barrett constant for 2Q: 2^32 / (2Q)
pub const DQREC: i32 = 33287;

/// Montgomery reduction
///
/// For finite field element a with -2^31*Q <= a <= Q*2^31,
/// compute r ≡ a*2^(-32) (mod Q) such that -Q < r < Q.
///
/// # Arguments
/// * `a` - Finite field element
///
/// # Returns
/// Reduced value r with -Q < r < Q
///
/// Transcopy from: int32_t montgomery_reduce(int64_t a)
#[inline]
pub fn montgomery_reduce(a: i64) -> i32 {
    // IMPORTANT: t must be i32 to match C behavior (truncation on line 18 of C code)
    let t = (((a as i32) as i64) * (QINV as i64)) as i32;
    let t = ((a - (t as i64) * (Q as i64)) >> 32) as i32;
    t
}

/// Conditional add Q
///
/// Add Q if input coefficient is negative.
///
/// # Arguments
/// * `a` - Finite field element
///
/// # Returns
/// a + Q if a < 0, otherwise a
///
/// Transcopy from: int32_t caddq(int32_t a)
#[inline]
pub fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}

/// Freeze to canonical form [0, Q)
///
/// For finite field element a, compute standard representative r = a mod^+ Q.
/// Uses Barrett reduction followed by conditional subtraction.
///
/// # Arguments
/// * `a` - Finite field element
///
/// # Returns
/// Canonical representative in [0, Q)
///
/// Transcopy from: int32_t freeze(int32_t a)
#[inline]
pub fn freeze(a: i32) -> i32 {
    let mut t = ((a as i64) * (QREC as i64)) >> 32;
    t = (a as i64) - t * (Q as i64);        // -2Q <  t < 2Q
    t += (t >> 31) & (DQ as i64);           //   0 <= t < 2Q
    t -= !((t - (Q as i64)) >> 31) & (Q as i64); //   0 <= t < Q
    t as i32
}

/// Reduce to [-Q, Q) using 2Q modulus
///
/// Compute reduction with 2Q, returning result in centered representation.
///
/// # Arguments
/// * `a` - Finite field element
///
/// # Returns
/// Reduced value in centered representation
///
/// Transcopy from: int32_t reduce32_2q(int32_t a)
#[inline]
pub fn reduce32_2q(a: i32) -> i32 {
    let mut t = ((a as i64) * (DQREC as i64)) >> 32;
    t = (a as i64) - t * (DQ as i64);             // -4Q <  t < 4Q
    t += (t >> 31) & ((DQ * 2) as i64);           //   0 <= t < 4Q
    t -= !((t - (DQ as i64)) >> 31) & (DQ as i64); //   0 <= t < 2Q
    t -= !((t - (Q as i64)) >> 31) & (DQ as i64);  // centered representation
    t as i32
}

/// Freeze to canonical form [0, 2Q)
///
/// For finite field element a, compute standard representative r = a mod^+ 2Q.
///
/// # Arguments
/// * `a` - Finite field element
///
/// # Returns
/// Canonical representative in [0, 2Q)
///
/// Transcopy from: int32_t freeze2q(int32_t a)
#[inline]
pub fn freeze2q(a: i32) -> i32 {
    let mut t = ((a as i64) * (DQREC as i64)) >> 32;
    t = (a as i64) - t * (DQ as i64);             // -4Q <  t < 4Q
    t += (t >> 31) & ((DQ * 2) as i64);           //   0 <= t < 4Q
    t -= !((t - (DQ as i64)) >> 31) & (DQ as i64); //   0 <= t < 2Q
    t as i32
}

/// Alias for reduce32_2q (for compatibility with poly.rs)
#[inline]
pub fn reduce2q(a: i32) -> i32 {
    reduce32_2q(a)
}

/// Decompose coefficient into high bits for z1 decomposition
///
/// For coefficient a, compute high bits using decompose_z1.
/// This is used for z1 decomposition with fixed ALPHA=256.
///
/// Transcopy from: poly.c::poly_highbits (calls decompose_z1)
#[inline]
pub fn highbits(a: i32) -> i32 {
    let (hb, _lb) = decompose_z1(a);
    hb
}

/// Compute low bits of z1 decomposition
///
/// For coefficient a, compute low bits using decompose_z1.
/// This is used for z1 decomposition with fixed ALPHA=256.
///
/// Transcopy from: poly.c::poly_lowbits (calls decompose_z1)
#[inline]
pub fn lowbits(a: i32) -> i32 {
    let (_hb, lb) = decompose_z1(a);
    lb
}

/// Decompose for z1: compute high and low bits
///
/// For finite field element r, compute hb, lb such that r = hb * alpha + lb
/// with -alpha/4 < lb <= alpha/4.
///
/// Transcopy from: decompose.c::decompose_z1
pub fn decompose_z1(r: i32) -> (i32, i32) {
    const ALPHA: i32 = 256;
    const LOG_ALPHA: i32 = 8;
    const ALPHA_MASK: i32 = ALPHA - 1;

    let mut lb = r & ALPHA_MASK;
    let center = ((ALPHA >> 1) - (lb + 1)) >> 31; // if lb >= HALF_ALPHA
    lb -= ALPHA & center;
    let hb = (r + (ALPHA >> 1)) >> LOG_ALPHA;

    (hb, lb)
}

/// Decompose for hint: compute only high bits
///
/// For finite field element r, compute hb such that r = hb * ALPHA_HINT + lb
/// with -ALPHA_HINT/4 < lb <= ALPHA_HINT/4.
///
/// Transcopy from: decompose.c::decompose_hint
pub fn decompose_hint(r: i32) -> i32 {
    use crate::params::{DQ, ALPHA_HINT, HALF_ALPHA_HINT, LOG_ALPHA_HINT};

    let mut hb = (r + HALF_ALPHA_HINT) >> LOG_ALPHA_HINT;
    let edgecase = ((DQ - 2) / ALPHA_HINT - (hb + 1)) >> 31; // if hb == (DQ-2)/ALPHA
    hb -= (DQ - 2) / ALPHA_HINT & edgecase; // hb = 0

    hb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_reduce() {
        // Test with zero
        assert_eq!(montgomery_reduce(0), 0);

        // Test with Q: should reduce to 0
        let result = montgomery_reduce(Q as i64);
        assert_eq!(result, 0);
        assert!(result >= -Q && result < Q);

        // Test with 2^32: montgomery_reduce(2^32) = 2^32 * 2^(-32) mod Q = 1
        let result = montgomery_reduce(1i64 << 32);
        assert_eq!(result, 1);
        assert!(result >= -Q && result < Q);

        // Test with MONT * 2^32: should recover MONT
        let result = montgomery_reduce((MONT as i64) * (1i64 << 32));
        assert_eq!(result, MONT);
    }

    #[test]
    fn test_caddq() {
        // Positive number: no change
        assert_eq!(caddq(100), 100);

        // Negative number: add Q
        assert_eq!(caddq(-1), -1 + Q);
        assert_eq!(caddq(-Q), 0);
    }

    #[test]
    fn test_freeze() {
        // Already in range
        assert_eq!(freeze(100), 100);
        assert_eq!(freeze(Q - 1), Q - 1);

        // Needs reduction
        assert_eq!(freeze(Q), 0);
        assert_eq!(freeze(Q + 1), 1);
        assert_eq!(freeze(2 * Q), 0);

        // Negative
        assert_eq!(freeze(-1), Q - 1);
    }

    #[test]
    fn test_freeze2q() {
        // Already in range
        assert_eq!(freeze2q(100), 100);
        assert_eq!(freeze2q(DQ - 1), DQ - 1);

        // Needs reduction
        assert_eq!(freeze2q(DQ), 0);
        assert_eq!(freeze2q(DQ + 1), 1);
    }

    #[test]
    fn test_reduce32_2q() {
        // Test centered representation
        let result = reduce32_2q(0);
        assert!(result >= -Q && result < Q);

        let result = reduce32_2q(Q);
        assert!(result >= -Q && result < Q);

        let result = reduce32_2q(2 * Q);
        assert!(result >= -Q && result < Q);
    }

    #[test]
    fn test_highbits_lowbits() {
        // Test z1 decomposition with ALPHA=256
        const ALPHA: i32 = 256;

        let a = 1000;
        let high = highbits(a);
        let low = lowbits(a);

        // Reconstruction should equal original for z1 decomposition
        assert_eq!(high * ALPHA + low, a);

        // Test a few more values
        assert_eq!(highbits(767) * ALPHA + lowbits(767), 767);
        assert_eq!(highbits(-350) * ALPHA + lowbits(-350), -350);
        assert_eq!(highbits(24) * ALPHA + lowbits(24), 24);
    }
}
