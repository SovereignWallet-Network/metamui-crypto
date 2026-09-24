//! AIMer parameter sets — AIM2 only (the KPQC winner, spec v260130).
//!
//! The AIM v1 sets were removed in 2026-09: v1 has known algebraic
//! vulnerabilities and was never a KPQC selection.

/// Common trait for AIMer parameter sets
pub trait AimerParams: Clone + Send + Sync {
    const NAME: &'static str;
    const SECURITY_LEVEL: u8;
    const PARAMETER_SET: &'static str;

    // Security parameters
    const SECURITY_BITS: usize;
    const FIELD_SIZE: usize;

    // MPC parameters
    const MPC_PARTIES: usize;
    const MPC_ROUNDS: usize;
    const TAPE_SIZE: usize;
    const RANDOM_BITS: usize;

    // Signature parameters
    const SALT_SIZE: usize;
    const DIGEST_SIZE: usize;
    const SEED_SIZE: usize;

    // Key sizes
    const PUBLIC_KEY_SIZE: usize;
    const SECRET_KEY_SIZE: usize;
    const SIGNATURE_SIZE: usize;

    // AIM2 cipher parameters

    /// Number of parallel inverse Mersenne S-boxes in layer 1
    const AIM2_NUM_SBOXES: usize = 0;
    /// Exponents for layer-1 inverse Mersenne S-boxes (one per S-box)
    const AIM2_LAYER1_EXPONENTS: &'static [usize] = &[];
    /// Exponent for layer-2 forward Mersenne S-box
    const AIM2_LAYER2_EXPONENT: usize = 0;
    /// Distinct constants (gamma_j) for each S-box lane, from digits of pi.
    /// Stored as concatenated little-endian byte arrays, each FIELD_SIZE bytes.
    const AIM2_GAMMA: &'static [u8] = &[];

    /// H₀ domain separation prefix for message pre-hashing (spec Section 4.1.2).
    /// AIMer-128f=0x00, 128s=0x10, 192f=0x20, 192s=0x30, 256f=0x40, 256s=0x50
    const H0_PREFIX: u8 = 0x00;

    /// Log₂ of MPC_PARTIES
    const LOG_N: usize = 8;
}

// ============================================================================
// AIM2 parameter sets (AIMer v2.0/v2.1 — KPQC winner)
// ============================================================================

/// Distinct constants (gamma) derived from digits of pi (nothing-up-my-sleeve).
/// Source: AIMer spec v260130 (Jan 30, 2026), Table 2.
///
/// Each security level uses a DIFFERENT contiguous segment of pi's hex expansion
/// after the decimal point. Values are stored in little-endian byte order
/// (reversed from the spec's big-endian hexadecimal notation).
///
/// Pi hex (big-endian): 3.243F6A88 85A308D3 13198A2E 03707344 A4093822 299F31D0 ...
///   L1 uses bytes 0-31, L3 uses bytes 32-79, L5 uses bytes 80-175.
mod aim2_constants {
    // AIM2-128 (L1): 2 gamma values, each 16 bytes (little-endian)
    // Spec γ₀ (BE): 0x243f6a88 85a308d3 13198a2e 03707344
    // Spec γ₁ (BE): 0xa4093822 299f31d0 082efa98 ec4e6c89
    pub const GAMMA_L1: &[u8] = &[
        // γ₀ (reversed from BE: 243f6a88 85a308d3 13198a2e 03707344)
        0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13,
        0xd3, 0x08, 0xa3, 0x85, 0x88, 0x6a, 0x3f, 0x24,
        // γ₁ (reversed from BE: a4093822 299f31d0 082efa98 ec4e6c89)
        0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08,
        0xd0, 0x31, 0x9f, 0x29, 0x22, 0x38, 0x09, 0xa4,
    ];

    // AIM2-192 (L3): 2 gamma values, each 24 bytes (little-endian)
    // Spec γ₀ (BE): 0x452821e6 38d01377 be5466cf 34e90c6c c0ac29b7 c97c50dd
    // Spec γ₁ (BE): 0x3f84d5b5 b5470917 9216d5d9 8979fb1b d1310ba6 98dfb5ac
    pub const GAMMA_L3: &[u8] = &[
        // γ₀ (reversed from BE: 452821e6 38d01377 be5466cf 34e90c6c c0ac29b7 c97c50dd)
        0xdd, 0x50, 0x7c, 0xc9, 0xb7, 0x29, 0xac, 0xc0,
        0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe,
        0x77, 0x13, 0xd0, 0x38, 0xe6, 0x21, 0x28, 0x45,
        // γ₁ (reversed from BE: 3f84d5b5 b5470917 9216d5d9 8979fb1b d1310ba6 98dfb5ac)
        0xac, 0xb5, 0xdf, 0x98, 0xa6, 0x0b, 0x31, 0xd1,
        0x1b, 0xfb, 0x79, 0x89, 0xd9, 0xd5, 0x16, 0x92,
        0x17, 0x09, 0x47, 0xb5, 0xb5, 0xd5, 0x84, 0x3f,
    ];

    // AIM2-256 (L5): 3 gamma values, each 32 bytes (little-endian)
    // Spec γ₀ (BE): 0x2ffd72db d01adfb7 b8e1afed 6a267e96 ba7c9045 f12c7f99 24a19947 b3916cf7
    // Spec γ₁ (BE): 0x0801f2e2 858efc16 636920d8 71574e69 a458fea3 f4933d7e 0d95748f 728eb658
    // Spec γ₂ (BE): 0x718bcd58 82154aee 7b54a41d c25a59b5 9c30d539 2af26013 c5d1b023 286085f0
    pub const GAMMA_L5: &[u8] = &[
        // γ₀
        0xf7, 0x6c, 0x91, 0xb3, 0x47, 0x99, 0xa1, 0x24,
        0x99, 0x7f, 0x2c, 0xf1, 0x45, 0x90, 0x7c, 0xba,
        0x96, 0x7e, 0x26, 0x6a, 0xed, 0xaf, 0xe1, 0xb8,
        0xb7, 0xdf, 0x1a, 0xd0, 0xdb, 0x72, 0xfd, 0x2f,
        // γ₁
        0x58, 0xb6, 0x8e, 0x72, 0x8f, 0x74, 0x95, 0x0d,
        0x7e, 0x3d, 0x93, 0xf4, 0xa3, 0xfe, 0x58, 0xa4,
        0x69, 0x4e, 0x57, 0x71, 0xd8, 0x20, 0x69, 0x63,
        0x16, 0xfc, 0x8e, 0x85, 0xe2, 0xf2, 0x01, 0x08,
        // γ₂
        0xf0, 0x85, 0x60, 0x28, 0x23, 0xb0, 0xd1, 0xc5,
        0x13, 0x60, 0xf2, 0x2a, 0x39, 0xd5, 0x30, 0x9c,
        0xb5, 0x59, 0x5a, 0xc2, 0x1d, 0xa4, 0x54, 0x7b,
        0xee, 0x4a, 0x15, 0x82, 0x58, 0xcd, 0x8b, 0x71,
    ];
}

/// AIM2er-I: Security Level 1 (128-bit) with AIM2 cipher
///
/// Corresponds to `aimer128s` in the AIMer v2.1 specification (N=256, tau=17).
/// Salt size is lambda/8 = 16 bytes (halved from v1's 2*lambda).
#[derive(Clone)]
pub struct Aim2erI;

impl AimerParams for Aim2erI {
    const NAME: &'static str = "AIM2er-I";
    const SECURITY_LEVEL: u8 = 1;
    const PARAMETER_SET: &'static str = "aimer128s";
    const H0_PREFIX: u8 = 0x10;     // upstream AIMER_HASH_PREFIX_0 for aimer128s

    const SECURITY_BITS: usize = 128;
    const FIELD_SIZE: usize = 16;

    const MPC_PARTIES: usize = 256;
    const MPC_ROUNDS: usize = 17;   // spec v2.1: tau=17 for aimer128s (N=256)
    const TAPE_SIZE: usize = 64;
    const RANDOM_BITS: usize = 256;

    const SALT_SIZE: usize = 16;    // spec v2.1: lambda/8 = 16 bytes
    const DIGEST_SIZE: usize = 32;
    const SEED_SIZE: usize = 16;

    const PUBLIC_KEY_SIZE: usize = 32;
    const SECRET_KEY_SIZE: usize = 48;
    const SIGNATURE_SIZE: usize = 4160; // spec v260130: (5+(8+2+5)*17)*128/8

    const AIM2_NUM_SBOXES: usize = 2;
    const AIM2_LAYER1_EXPONENTS: &'static [usize] = &[49, 91];
    const AIM2_LAYER2_EXPONENT: usize = 3;
    const AIM2_GAMMA: &'static [u8] = aim2_constants::GAMMA_L1;
    const LOG_N: usize = 8;
}

/// AIM2er-IF: Security Level 1 (128-bit) fast variant with AIM2 cipher
///
/// Corresponds to `aimer128f` in the AIMer v2.1 specification (N=16, tau=33).
/// Smaller N means smaller tree but more repetitions → larger signature than 128s.
#[derive(Clone)]
pub struct Aim2erIF;

impl AimerParams for Aim2erIF {
    const NAME: &'static str = "AIM2er-IF";
    const SECURITY_LEVEL: u8 = 1;
    const PARAMETER_SET: &'static str = "aimer128f";
    const H0_PREFIX: u8 = 0x00;     // upstream AIMER_HASH_PREFIX_0 for aimer128f

    const SECURITY_BITS: usize = 128;
    const FIELD_SIZE: usize = 16;

    const MPC_PARTIES: usize = 16;
    const MPC_ROUNDS: usize = 33;
    const TAPE_SIZE: usize = 64;
    const RANDOM_BITS: usize = 256;

    const SALT_SIZE: usize = 16;
    const DIGEST_SIZE: usize = 32;
    const SEED_SIZE: usize = 16;

    const PUBLIC_KEY_SIZE: usize = 32;
    const SECRET_KEY_SIZE: usize = 48;
    // salt[16] + h1[32] + h2[32] + 33*(path[4*16] + com[32] + delta_pt[16] + delta_ts[2*16] + delta_c[16] + alpha[16])
    // = 80 + 33*176 = 80 + 5808 = 5888
    const SIGNATURE_SIZE: usize = 5888;

    const AIM2_NUM_SBOXES: usize = 2;
    const AIM2_LAYER1_EXPONENTS: &'static [usize] = &[49, 91];
    const AIM2_LAYER2_EXPONENT: usize = 3;
    const AIM2_GAMMA: &'static [u8] = aim2_constants::GAMMA_L1;
    const LOG_N: usize = 4;     // log₂(16) = 4
}

/// AIM2er-III: Security Level 3 (192-bit) with AIM2 cipher
///
/// Corresponds to `aimer192s` in the AIMer v2.1 specification (N=256, tau=25).
#[derive(Clone)]
pub struct Aim2erIII;

impl AimerParams for Aim2erIII {
    const NAME: &'static str = "AIM2er-III";
    const SECURITY_LEVEL: u8 = 3;
    const PARAMETER_SET: &'static str = "aimer192s";
    const H0_PREFIX: u8 = 0x30;     // upstream AIMER_HASH_PREFIX_0 for aimer192s

    const SECURITY_BITS: usize = 192;
    const FIELD_SIZE: usize = 24;

    const MPC_PARTIES: usize = 256;
    const MPC_ROUNDS: usize = 25;   // spec v2.1: tau=25 for aimer192s (N=256)
    const TAPE_SIZE: usize = 96;
    const RANDOM_BITS: usize = 384;

    const SALT_SIZE: usize = 24;    // spec v2.1: lambda/8 = 24 bytes
    const DIGEST_SIZE: usize = 48;
    const SEED_SIZE: usize = 24;

    const PUBLIC_KEY_SIZE: usize = 48;
    const SECRET_KEY_SIZE: usize = 72;
    const SIGNATURE_SIZE: usize = 9120; // spec v260130: (5+(8+2+5)*25)*192/8

    const AIM2_NUM_SBOXES: usize = 2;
    const AIM2_LAYER1_EXPONENTS: &'static [usize] = &[17, 47];
    const AIM2_LAYER2_EXPONENT: usize = 5;
    const AIM2_GAMMA: &'static [u8] = aim2_constants::GAMMA_L3;
    const LOG_N: usize = 8;
}

/// AIM2er-IIIF: Security Level 3 (192-bit) fast variant with AIM2 cipher
///
/// Corresponds to `aimer192f` in the AIMer v2.1 specification (N=16, tau=49).
#[derive(Clone)]
pub struct Aim2erIIIF;

impl AimerParams for Aim2erIIIF {
    const NAME: &'static str = "AIM2er-IIIF";
    const SECURITY_LEVEL: u8 = 3;
    const PARAMETER_SET: &'static str = "aimer192f";
    const H0_PREFIX: u8 = 0x20;     // upstream AIMER_HASH_PREFIX_0 for aimer192f

    const SECURITY_BITS: usize = 192;
    const FIELD_SIZE: usize = 24;

    const MPC_PARTIES: usize = 16;
    const MPC_ROUNDS: usize = 49;
    const TAPE_SIZE: usize = 96;
    const RANDOM_BITS: usize = 384;

    const SALT_SIZE: usize = 24;
    const DIGEST_SIZE: usize = 48;
    const SEED_SIZE: usize = 24;

    const PUBLIC_KEY_SIZE: usize = 48;
    const SECRET_KEY_SIZE: usize = 72;
    // salt[24] + h1[48] + h2[48] + 49*(path[4*24] + com[48] + delta_pt[24] + delta_ts[2*24] + delta_c[24] + alpha[24])
    // = 120 + 49*264 = 120 + 12936 = 13056
    const SIGNATURE_SIZE: usize = 13056;

    const AIM2_NUM_SBOXES: usize = 2;
    const AIM2_LAYER1_EXPONENTS: &'static [usize] = &[17, 47];
    const AIM2_LAYER2_EXPONENT: usize = 5;
    const AIM2_GAMMA: &'static [u8] = aim2_constants::GAMMA_L3;
    const LOG_N: usize = 4;     // log₂(16) = 4
}

/// AIM2er-V: Security Level 5 (256-bit) with AIM2 cipher
///
/// Corresponds to `aimer256s` in the AIMer v2.1 specification (N=256, tau=33).
#[derive(Clone)]
pub struct Aim2erV;

impl AimerParams for Aim2erV {
    const NAME: &'static str = "AIM2er-V";
    const SECURITY_LEVEL: u8 = 5;
    const PARAMETER_SET: &'static str = "aimer256s";
    const H0_PREFIX: u8 = 0x50;     // upstream AIMER_HASH_PREFIX_0 for aimer256s

    const SECURITY_BITS: usize = 256;
    const FIELD_SIZE: usize = 32;

    const MPC_PARTIES: usize = 256;
    const MPC_ROUNDS: usize = 33;   // spec v2.1: tau=33 for aimer256s (N=256)
    const TAPE_SIZE: usize = 128;
    const RANDOM_BITS: usize = 512;

    const SALT_SIZE: usize = 32;    // spec v2.1: lambda/8 = 32 bytes
    const DIGEST_SIZE: usize = 64;
    const SEED_SIZE: usize = 32;

    const PUBLIC_KEY_SIZE: usize = 64;
    const SECRET_KEY_SIZE: usize = 96;
    const SIGNATURE_SIZE: usize = 17056; // spec v260130: (5+(8+3+5)*33)*256/8

    const AIM2_NUM_SBOXES: usize = 3;
    const AIM2_LAYER1_EXPONENTS: &'static [usize] = &[11, 141, 7];
    const AIM2_LAYER2_EXPONENT: usize = 3;
    const AIM2_GAMMA: &'static [u8] = aim2_constants::GAMMA_L5;
    const LOG_N: usize = 8;
}

/// AIM2er-VF: Security Level 5 (256-bit) fast variant with AIM2 cipher
///
/// Corresponds to `aimer256f` in the AIMer v2.1 specification (N=16, tau=65).
#[derive(Clone)]
pub struct Aim2erVF;

impl AimerParams for Aim2erVF {
    const NAME: &'static str = "AIM2er-VF";
    const SECURITY_LEVEL: u8 = 5;
    const PARAMETER_SET: &'static str = "aimer256f";
    const H0_PREFIX: u8 = 0x40;     // upstream AIMER_HASH_PREFIX_0 for aimer256f

    const SECURITY_BITS: usize = 256;
    const FIELD_SIZE: usize = 32;

    const MPC_PARTIES: usize = 16;
    const MPC_ROUNDS: usize = 65;
    const TAPE_SIZE: usize = 128;
    const RANDOM_BITS: usize = 512;

    const SALT_SIZE: usize = 32;
    const DIGEST_SIZE: usize = 64;
    const SEED_SIZE: usize = 32;

    const PUBLIC_KEY_SIZE: usize = 64;
    const SECRET_KEY_SIZE: usize = 96;
    // salt[32] + h1[64] + h2[64] + 65*(path[4*32] + com[64] + delta_pt[32] + delta_ts[3*32] + delta_c[32] + alpha[32])
    // = 160 + 65*384 = 160 + 24960 = 25120
    const SIGNATURE_SIZE: usize = 25120;

    const AIM2_NUM_SBOXES: usize = 3;
    const AIM2_LAYER1_EXPONENTS: &'static [usize] = &[11, 141, 7];
    const AIM2_LAYER2_EXPONENT: usize = 3;
    const AIM2_GAMMA: &'static [u8] = aim2_constants::GAMMA_L5;
    const LOG_N: usize = 4;     // log₂(16) = 4
}
