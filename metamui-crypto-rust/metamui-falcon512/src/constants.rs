/// Constants for Falcon-512

/// Security parameter
pub const FALCON_SEC: usize = 128;

/// Degree of the ring
pub const N: usize = 512;

/// Logarithm of the degree
pub const LOGN: usize = 9;

/// Prime modulus
pub const Q: u16 = 12289;

/// Inverse of 2 modulo Q
pub const INV2: u16 = 6145;

/// Inverse of N modulo Q (for NTT)
pub const N_INV: u16 = 12265;

/// Standard deviation for key generation
pub const SIGMA: f64 = 165.7366171829776;

/// Standard deviation for signing
pub const SIGMA_MIN: f64 = 1.2778336969128337;

/// σ_min for Falcon-1024 (logn = 10).
///
/// Reference value `fpr_sigma_min_10` from the Falcon reference code
/// (1.2982803343442918539708792538826807). The lower rejection bound
/// scales `ccs` in `sampler_z`; using the 512 value for 1024 would skew
/// acceptance, and 168.3885714457672 = 1.17 · SIGMA_MIN_1024 · √q.
pub const SIGMA_MIN_1024: f64 = 1.2982803343442918;

/// Bound for signature compression  
/// For Falcon-512: sqrt(34034726) ≈ 5834
pub const BETA: u32 = 5834;

/// Beta squared for norm checking
pub const BETA_SQUARED: u32 = 34034726;  // Correct NIST spec value for Falcon-512

// ============================================================================
// Signature size constants — see `crate::sizes` for the authoritative table.
//
// Round-3 Falcon-512 has THREE signature profiles (falcon.h): compressed
// (variable, at most 752 bytes detached), padded (exactly 666) and CT (exactly
// 809). The NIST submission's api.h CRYPTO_BYTES = 690 is NOT a signature size:
// it is the maximum overhead of the signed-message format
// (2-byte length + 40-byte nonce + compressed body). Sizing a buffer from 690
// and copying min(690) truncates valid compressed signatures — never do that;
// use `sizes::falcon512::SIG_COMPRESSED_MAX` or the padded profile.
// ============================================================================

/// Padded-profile signature length (public specification, exactly 666).
/// Alias of `sizes::falcon512::SIG_PADDED`; the compressed profile is NOT
/// bounded by this — see `sizes::falcon512::SIG_COMPRESSED_MAX` (752).
pub const SIGNATURE_SIZE: usize = 666;

/// NIST API `CRYPTO_BYTES` from the submission's api.h: the signed-message
/// overhead (2-byte length + 40-byte nonce + compressed body), used only for
/// NIST `sm` framing. Not a detached-signature bound.
pub const NIST_CRYPTO_BYTES: usize = 690;

/// Maximum signature size (internal buffer allocation)
pub const MAX_SIG_SIZE: usize = 1280;

/// Nonce size in bytes (NONCELEN in NIST code)
pub const NONCE_SIZE: usize = 40;

/// Salt size for signing (same as nonce)
pub const SALT_LEN: usize = 40;

/// Shake256 rate
pub const SHAKE256_RATE: usize = 136;

/// Number of bits for floating-point representation
pub const FP_BITS: usize = 53;

/// Precomputed twiddle factors for NTT (first few values)
pub const NTT_TWIDDLES: [u16; 8] = [
    1, 1175, 2375, 2916, 3900, 4663, 5008, 5435
];

/// Precomputed inverse twiddle factors for NTT
pub const INV_NTT_TWIDDLES: [u16; 8] = [
    1, 10114, 9325, 8281, 7625, 6388, 5914, 4856
];

/// Montgomery reduction constant
pub const MONT_R: u32 = 4091;
pub const MONT_R2: u32 = 10952;

/// Bit-reversal permutation table (first few values)
pub const BIT_REV: [usize; 16] = [
    0, 256, 128, 384, 64, 320, 192, 448,
    32, 288, 160, 416, 96, 352, 224, 480
];

/// Public key size in bytes (NIST format includes 1 header byte)
pub const PUBLIC_KEY_SIZE: usize = 897;

/// Private key size in bytes
pub const PRIVATE_KEY_SIZE: usize = 2305;

/// NIST API constants (match CRYPTO_* from api.h)
pub const CRYPTO_PUBLICKEYBYTES: usize = 897;
pub const CRYPTO_SECRETKEYBYTES: usize = 2305;
pub const CRYPTO_BYTES: usize = 690;

/// Re-export N as FALCON_N for compatibility
pub const FALCON_N: usize = N;