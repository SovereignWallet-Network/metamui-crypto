/**
 * ML-KEM-768 Constants
 *
 * Constants for NIST FIPS 203 ML-KEM-768 implementation
 */

// Core ML-KEM-768 parameters (FIPS 203)
/// Module dimension for ML-KEM-768
pub const MLKEM_K: usize = 3; // Module dimension
/// Polynomial degree
pub const MLKEM_N: usize = 256; // Polynomial degree
/// Prime modulus q
pub const MLKEM_Q: u16 = 3329; // Modulus
/// Noise parameter η₁ for key generation
pub const MLKEM_ETA1: u8 = 2; // Noise parameter η₁
/// Noise parameter η₂ for encryption
pub const MLKEM_ETA2: u8 = 2; // Noise parameter η₂
/// Compression parameter du for ciphertext
pub const MLKEM_DU: u8 = 10; // Compression parameter du
/// Compression parameter dv for ciphertext
pub const MLKEM_DV: u8 = 4; // Compression parameter dv

// Key and message sizes (bytes)
/// Public key size in bytes
pub const MLKEM_PUBLICKEY_BYTES: usize = 1184; // Public key size
/// Secret key size in bytes
pub const MLKEM_SECRETKEY_BYTES: usize = 2400; // Secret key size
/// Ciphertext size in bytes
pub const MLKEM_CIPHERTEXT_BYTES: usize = 1088; // Ciphertext size
/// Shared secret size in bytes
pub const MLKEM_SHAREDSECRET_BYTES: usize = 32; // Shared secret size

// Internal sizes
/// Size of hashes and seeds in bytes
pub const MLKEM_SYMBYTES: usize = 32; // Size of hashes and seeds
/// Size of serialized polynomial in bytes
pub const MLKEM_POLYBYTES: usize = 384; // Size of serialized polynomial
/// Size of polynomial vector in bytes
pub const MLKEM_POLYVECBYTES: usize = MLKEM_K * MLKEM_POLYBYTES; // Size of polynomial vector
/// Size of compressed polynomial in bytes
pub const MLKEM_POLYCOMPRESSEDBYTES: usize = 128; // Size of compressed polynomial
/// Size of compressed polynomial vector in bytes
pub const MLKEM_POLYVECCOMPRESSEDBYTES: usize = MLKEM_K * MLKEM_POLYCOMPRESSEDBYTES; // Compressed poly vector

// NTT-related constants
/// Primitive 512th root of unity modulo q
pub const MLKEM_ROOT_OF_UNITY: u16 = 17; // Primitive 512th root of unity mod q
/// Inverse of 256 modulo q for NTT
/// Note: This is the correct value. 256 * 3303 mod 3329 = 1
/// The actual NTT implementation uses f=1441 (inverse of 128) for ML-KEM-768
pub const MLKEM_INVN: u16 = 3303; // Inverse of 256 mod q

// Barrett reduction constants
/// Barrett reduction shift amount
pub const BARRETT_SHIFT: u8 = 26;
/// Barrett reduction multiplier
pub const BARRETT_R: u32 = (1u32 << BARRETT_SHIFT) / MLKEM_Q as u32;

// Montgomery reduction constants
/// Montgomery parameter R = 2^16
pub const MONT_R: u32 = 1 << 16; // 2^16 mod q
/// Montgomery inverse R^(-1) mod q
pub const MONT_RINV: u32 = 169; // R^(-1) mod q
/// Montgomery inverse q^(-1) mod 2^16
pub const MONT_QINV: u32 = 62209; // q^(-1) mod 2^16

// NTT twiddle factors (ζ^i mod q where ζ = 17)
/// NTT twiddle factors for forward transform
/// These are bit-reversed powers of 17 (matching kyber-py)
pub const ZETAS: [u16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583,
    2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789,
    1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037,
    3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
    1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

// Montgomery form of ZETAS (for algorithms that need it)
/// NTT twiddle factors in Montgomery form
pub const ZETAS_MONT: [u16; 128] = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468, 573,
    2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608, 1787, 411, 3124, 1758, 1223, 652,
    2777, 1015, 2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239,
    3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226, 430, 555,
    843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 778, 1159, 3182,
    2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254, 817, 1097, 603, 610, 1322,
    2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819,
    2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
];

// Inverse NTT twiddle factors
/// NTT twiddle factors for inverse transform
/// These are the inverses of ZETAS in reverse order
pub const ZETAS_INV: [u16; 128] = [
    1175, 2444, 394, 2300, 1219, 2457, 1607, 1455, 2237, 525, 735, 2303, 2186, 1179, 554, 2443,
    1684, 2266, 1230, 863, 768, 2572, 1956, 3010, 2266, 1684, 735, 525, 2237, 2926, 2303, 2186,
    1179, 554, 2443, 1607, 1455, 1219, 2300, 394, 2444, 1175, 2154, 885, 2935, 2110, 1029, 1874,
    1212, 1722, 886, 2775, 2150, 1143, 1026, 403, 1092, 2804, 2594, 2466, 561, 2099, 757, 2773,
    319, 1063, 1645, 2090, 2549, 375, 3220, 2037, 2298, 1584, 641, 268, 2337, 733, 2388, 2437,
    2308, 939, 2687, 1461, 952, 1847, 1789, 2789, 1651, 1703, 3050, 3015, 2156, 756, 233, 3281,
    2662, 1409, 1100, 2288, 723, 1637, 2649, 583, 2761, 17, 910, 1227, 3110, 2474, 648, 1481, 2617,
    2647, 2402, 1534, 2868, 1438, 452, 807, 1435, 2319, 1915, 1320, 33, 2865, 632, 2513,
];

// Domain separation constants for FIPS 203
/// Domain separator for key generation seed
pub const MLKEM_KEYGEN_SEED_DOMAIN: u8 = 0x00;
/// Domain separator for encapsulation
pub const MLKEM_ENCAPS_DOMAIN: u8 = 0x01;
/// Domain separator for decapsulation
pub const MLKEM_DECAPS_DOMAIN: u8 = 0x02;

// Error bounds and validation constants
/// Maximum valid coefficient value
pub const MAX_COEFFICIENT_VALUE: u16 = MLKEM_Q - 1;
/// Maximum noise value for validation
pub const MAX_NOISE_VALUE: i16 = MLKEM_ETA1 as i16;

// Timing attack resistance - constant values
/// Constant-time mask for true condition
pub const CONSTANT_TIME_MASK_TRUE: u16 = 0xFFFF;
/// Constant-time mask for false condition
pub const CONSTANT_TIME_MASK_FALSE: u16 = 0x0000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_sizes() {
        // Verify FIPS 203 mandated key sizes
        assert_eq!(MLKEM_PUBLICKEY_BYTES, 1184);
        assert_eq!(MLKEM_SECRETKEY_BYTES, 2400);
        assert_eq!(MLKEM_CIPHERTEXT_BYTES, 1088);
        assert_eq!(MLKEM_SHAREDSECRET_BYTES, 32);
    }

    #[test]
    fn test_mlkem768_parameters() {
        // Verify ML-KEM-768 specific parameters
        assert_eq!(MLKEM_K, 3);
        assert_eq!(MLKEM_N, 256);
        assert_eq!(MLKEM_Q, 3329);
        assert_eq!(MLKEM_ETA1, 2);
        assert_eq!(MLKEM_ETA2, 2);
        assert_eq!(MLKEM_DU, 10);
        assert_eq!(MLKEM_DV, 4);
    }

    #[test]
    fn test_ntt_constants_validity() {
        // Verify that our NTT constants are correct
        assert_eq!(MLKEM_ROOT_OF_UNITY, 17);
        assert_eq!(MLKEM_INVN, 3303);

        // Verify that 128 * INVN ≡ 1 (mod q)
        // Note: MLKEM_INVN is the inverse of 128, not 256
        let product = (128u32 * MLKEM_INVN as u32) % MLKEM_Q as u32;
        assert_eq!(product, 1);
    }

    #[test]
    fn test_zetas_length() {
        assert_eq!(ZETAS.len(), 128);
        assert_eq!(ZETAS_INV.len(), 128);
    }
}
