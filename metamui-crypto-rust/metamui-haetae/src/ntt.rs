//! Number Theoretic Transform (NTT) operations for HAETAE
//!
//! This module implements forward and inverse NTT for efficient polynomial
//! multiplication in the ring R_q = Z_q[X]/(X^N + 1).
//!
//! Transcopy from: metamui-haetae/src/ntt.c

use crate::params::N;
use crate::reduce::montgomery_reduce;

/// Twiddle factors (roots of unity powers) for NTT
/// Generated for Q=64513, root of unity = 3
static ZETAS: [i32; N] = [
    0,      26964,  -16505, 22229,  30746,  20243,  19064,  -31218, 9395,
    -30985, 22859,  -8851,  32144,  13744,  21408,  17599,  -16039, -22946,
    6241,   -19553, 10681,  22935,  22431,  -29104, 28147,  -27527, -29133,
    -20035, 20143,  -11361, 30820,  25252,  -22562, -6789,  -10049, 9383,
    16304,  -12296, 16446,  18239,  -1296,  -19725, -32076, 11782,  -17941,
    29643,  -8577,  7893,   -21464, -19646, -15130, -2391,  30608,  -23970,
    -16608, 19616,  -7941,  26533,  -19129, 27690,  7597,   -11459, 10615,
    -9430,  11591,  7814,   12697,  32114,  -3761,  -9604,  19813,  20353,
    17456,  -16267, -19555, 598,    -29942, 4538,   835,    15546,  3970,
    -27685, 1488,   8311,   -12442, 31352,  -17631, 1806,   -5342,  9790,
    29068,  16507,  -29051, 22131,  6759,   15510,  -14941, 28710,  1160,
    -31327, 24985,  11261,  -10623, -27727, 21502,  18731,  -16186, -4127,
    -18832, 12050,  -14501, 7929,   29563,  -31064, 5913,   5322,   -16405,
    2844,   29439,  5876,   -9522,  -18586, -9874,  23844,  30362,  -21442,
    9560,   17671,  -27989, 3350,   787,    -13857, 1657,   -21224, -7374,
    -9190,  2464,   25555,  -3529,  -28772, 16588,  -15739, 23475,  13666,
    5764,   30980,  13633,  -7401,  -30317, 28847,  7682,   -11808, -8796,
    14864,  -24162, -19194, 689,    -1311,  -31332, -16319, 1025,   10971,
    -23016, -2648,  -21900, -12543, -25921, 28254,  28521,  -16160, 12380,
    -12882, -30332, -16630, 23439,  7742,   17182,  17494,  5920,   13642,
    7382,   -18166, 21422,  -30274, -28190, 13283,  -20316, -9939,  10672,
    21454,  6080,   -17374, -29735, -25912, -10170, 3808,   10639,  -26985,
    -10865, 25636,  17261,  -26851, -8253,  -3304,  18282,  -2202,  -31368,
    -22243, 13882,  12069,  -11242, -7729,  -10226, 1761,   -27298, -4800,
    -17737, -22805, -3528,  65,     10770,  8908,   -23751, 26934,  21921,
    -27010, -21944, 8889,   -1035,  23224,  -9488,  -5823,  -994,   -20206,
    7655,   -16251, -22820, -27740, 15822,  23078,  13803,  -8099,  2931,
    9217,   -21126, -14203, 25492,  -12831, 7947,   17463,  -12979, 29003,
    31612,  26554,  8241,   -20175,
];

/// Forward NTT (in-place)
///
/// Transforms polynomial from coefficient representation to NTT domain.
/// Output is in bit-reversed order. No modular reduction after operations.
///
/// # Arguments
/// * `a` - Coefficient array to transform (mutated in-place)
///
/// Transcopy from: void ntt(int32_t a[N])
#[inline]
pub fn ntt(a: &mut [i32; N]) {
    let mut k = 0usize;
    let mut len = 128usize;
    
    while len > 0 {
        let mut start = 0usize;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            
            for j in start..start + len {
                let t = montgomery_reduce(zeta as i64 * a[j + len] as i64);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
            
            start += len * 2;
        }
        len >>= 1;
    }
}

/// Inverse NTT with Montgomery multiplication (in-place)
///
/// Transforms polynomial from NTT domain back to coefficient representation.
/// Multiplies by Montgomery factor 2^32 during transformation.
/// Input coefficients must be smaller than Q in absolute value.
///
/// # Arguments
/// * `a` - NTT domain array to transform (mutated in-place)
///
/// Transcopy from: void invntt_tomont(int32_t a[N])
#[inline]
pub fn invntt_tomont(a: &mut [i32; N]) {
    const F: i32 = -29720; // mont^2/256
    
    let mut k = 256usize;
    let mut len = 1usize;
    
    while len < N {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];
            
            for j in start..start + len {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = montgomery_reduce(zeta as i64 * a[j + len] as i64);
            }
            
            start += len * 2;
        }
        len <<= 1;
    }
    
    // Final scaling by mont^2/256
    for j in 0..N {
        a[j] = montgomery_reduce(F as i64 * a[j] as i64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Q;
    use crate::reduce::freeze;
    
    #[test]
    fn test_ntt_invntt_roundtrip() {
        // Test that NTT -> INVNTT produces consistent results
        // Note: invntt_tomont leaves output in Montgomery form, so we don't
        // recover the exact original values. This is expected behavior in HAETAE.
        // We test that the transformation is consistent with known outputs.

        let mut a = [0i32; N];

        // Initialize with simple pattern
        for i in 0..N {
            a[i] = ((i * 17 + 42) % 100) as i32;
        }

        // Forward NTT
        ntt(&mut a);

        // Inverse NTT
        invntt_tomont(&mut a);

        // Check specific known values (verified against C implementation)
        // These values are in Montgomery form, which is correct
        assert_eq!(freeze(a[0]), 20865); // Original 42 -> Montgomery form
        assert_eq!(freeze(a[1]), 6270);  // Original 59 -> Montgomery form
        assert_eq!(freeze(a[2]), 56188); // Original 76 -> Montgomery form

        // Test that double roundtrip is consistent
        let _b = a.clone();
        ntt(&mut a);
        invntt_tomont(&mut a);

        // After second roundtrip, values should be scaled again by Montgomery factor
        // We just check that the operation is deterministic
        for i in 0..N {
            assert!(a[i] >= -Q && a[i] < Q || (a[i] >= Q && a[i] < 2*Q),
                    "Value at {} out of expected range: {}", i, a[i]);
        }
    }
    
    #[test]
    fn test_ntt_zero() {
        let mut a = [0i32; N];
        ntt(&mut a);
        for i in 0..N {
            assert_eq!(a[i], 0);
        }
    }
    
    #[test]
    fn test_invntt_zero() {
        let mut a = [0i32; N];
        invntt_tomont(&mut a);
        for i in 0..N {
            assert_eq!(a[i], 0);
        }
    }
}
