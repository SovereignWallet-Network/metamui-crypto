// SPDX-License-Identifier: MIT
//
// SMAUG-T v1.2.0 compile-time parameters.
//
// Mirrors `include/params.h` + `include/cbd.h` + `include/hwt.h` +
// `include/ciphertext.h` + `include/dg.h` + `include/indcpa.h` from the
// v1.2.0 reference implementation. C's `-DSMAUGT_CONFIG_MODE=N` build
// switch becomes a runtime `Mode` enum here; constants travel in a
// `Params` struct rather than as preprocessor macros.

/// SMAUG-T algorithm mode. The four standardized variants:
///
/// - `Mode1` — SMAUG-T1, NIST level 1, k=2, q=2^10 (default for ≥128-bit
///   classical security)
/// - `Mode3` — SMAUG-T3, NIST level 3, k=3, q=2^11
/// - `Mode5` — SMAUG-T5, NIST level 5, k=4, q=2^11
/// - `ModeT` — TiMER (Tiny sMaug using Error Reconciliation), NIST
///   level 1 with D2 encoding for smaller ciphertexts (608 vs 672)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    Mode1,
    Mode3,
    Mode5,
    ModeT,
}

/// SMAUG-T compile-time parameters for one mode.
///
/// All field names track the upstream C macros literally (lowercased
/// from `SMAUGT_*` → no prefix). See
/// `metamui-crypto-reference/.../SMAUG-T-1.2.0/reference_implementation/include/params.h`
/// for the authoritative definitions.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub mode: Mode,
    /// k — module rank, in {2, 3, 4}
    pub k: usize,
    /// `log_2(q)`. q is the public-key modulus.
    pub log_q: u8,
    /// `log_2(p)`. p is the ciphertext modulus.
    pub log_p: u8,
    /// `log_2(p')`. p' is the second ciphertext modulus.
    pub log_p_prime: u8,
    /// CBD seed bytes — input length to `sp_cbd`.
    pub cbdseed_bytes: usize,
    /// Plaintext message bytes (32 for modes 1/3/5; 16 for TiMER D2 encoding).
    pub msg_bytes: usize,
    /// Hamming weight of the secret-key polynomials (sampled by `hwt`).
    pub hs: usize,

    // Rounding constants for round1 (q → p) in `compute_c1`
    pub rd_add: u16,
    pub rd_and: u16,
    // Rounding constants for round2 (q → p') in `compute_c2`
    pub rd_add2: u16,
    pub rd_and2: u16,
}

/// `SMAUGT_N` — polynomial degree, common to all four modes.
pub const N: usize = 256;
/// `SMAUGT_DELTA_BYTES` — 32 bytes.
pub const DELTA_BYTES: usize = N / 8;
/// `SMAUGT_T_BYTES` — 32-byte rejection-path secret seed.
pub const T_BYTES: usize = N / 8;
/// `SMAUGT_PKSEED_BYTES` — 32-byte seed for matrix A.
pub const PKSEED_BYTES: usize = 32;
/// `SMAUGT_CRYPTO_BYTES` — 32-byte shared secret.
pub const CRYPTO_BYTES: usize = 32;
/// `SMAUGT_SHARED_SECRETE_BYTES` — same as CRYPTO_BYTES.
pub const SHARED_SECRET_BYTES: usize = CRYPTO_BYTES;
/// `SMAUGT_LOG_T = 1`. Plaintext modulus.
pub const LOG_T: u8 = 1;
/// `SMAUGT_MODULUS_16_LOG_T = 16 - LOG_T = 15`.
pub const MODULUS_16_LOG_T: u8 = 16 - LOG_T;
/// `SMAUGT_DEC_ADD = 0x4000 = 2^(15 - LOG_T)`. Rounding constant for `indcpa_dec`.
pub const DEC_ADD: i16 = 0x4000;
/// `SMAUGT_DG_RAND_BITS = 10` bits per Gaussian coefficient (RND + SIGN).
pub const DG_RAND_BITS: usize = 10;
/// `SMAUGT_DG_SMAUGT_SLEN = 2` — 2 boolean accumulators in d_gaussian_poly.
pub const DG_SLEN: usize = 2;
/// `SMAUGT_DG_SMAUGT_SEED_LEN = 10 * 256 / 64 = 40` u64s per polynomial.
pub const DG_SEED_LEN: usize = DG_RAND_BITS * N / 64;
/// `SMAUGT_HWTSEEDBYTES = (16 * 308) / 8 = 616` — enough randomness with
/// overwhelming probability of single shake squeeze succeeding.
pub const HWTSEEDBYTES: usize = (16 * 308) / 8;
/// `SMAUGT_MODULUS_SCALED_Q_HALF = 32767 = 2^15 - 1` — D2 encoding constant
/// for TiMER mode (Q/2 in left-aligned representation).
pub const MODULUS_SCALED_Q_HALF: i16 = 32767;

pub const MODE1: Params = Params {
    mode: Mode::Mode1,
    k: 2,
    log_q: 10,
    log_p: 8,
    log_p_prime: 5,
    cbdseed_bytes: (3 * N) / 8,   // 96
    msg_bytes: DELTA_BYTES,        // 32
    hs: 70,
    rd_add: 0x80,
    rd_and: 0xff00,
    rd_add2: 0x0400,
    rd_and2: 0xf800,
};

pub const MODE3: Params = Params {
    mode: Mode::Mode3,
    k: 3,
    log_q: 11,
    log_p: 9,
    log_p_prime: 4,
    cbdseed_bytes: (2 * N) / 8,   // 64
    msg_bytes: DELTA_BYTES,        // 32
    hs: 88,
    rd_add: 0x40,
    rd_and: 0xff80,
    rd_add2: 0x0800,
    rd_and2: 0xf000,
};

pub const MODE5: Params = Params {
    mode: Mode::Mode5,
    k: 4,
    log_q: 11,
    log_p: 9,
    log_p_prime: 7,
    cbdseed_bytes: (4 * N) / 8,   // 128
    msg_bytes: DELTA_BYTES,        // 32
    hs: 87,
    rd_add: 0x40,
    rd_and: 0xff80,
    rd_add2: 0x0100,
    rd_and2: 0xfe00,
};

pub const MODET: Params = Params {
    mode: Mode::ModeT,
    k: 2,
    log_q: 10,
    log_p: 8,
    log_p_prime: 3,
    cbdseed_bytes: (3 * N) / 8,   // 96
    msg_bytes: 16,                 // D2 encoding halves the message bytes
    hs: 70,
    rd_add: 0x80,
    rd_and: 0xff00,
    rd_add2: 0x1000,
    rd_and2: 0xe000,
};

impl Params {
    /// Resolve a `Mode` to its parameter table (compile-time-constant per mode).
    pub const fn for_mode(mode: Mode) -> &'static Params {
        match mode {
            Mode::Mode1 => &MODE1,
            Mode::Mode3 => &MODE3,
            Mode::Mode5 => &MODE5,
            Mode::ModeT => &MODET,
        }
    }

    /// `SMAUGT_MODULUS_16_LOG_Q = 16 - log_q`.
    pub const fn modulus_16_log_q(&self) -> u8 { 16 - self.log_q }
    /// `SMAUGT_MODULUS_16_LOG_P = 16 - log_p`.
    pub const fn modulus_16_log_p(&self) -> u8 { 16 - self.log_p }
    /// `SMAUGT_MODULUS_16_LOG_P_PRIME = 16 - log_p_prime`.
    pub const fn modulus_16_log_p_prime(&self) -> u8 { 16 - self.log_p_prime }

    /// `SMAUGT_PKPOLY_BYTES = log_q * N / 8`. One Rq polynomial packed.
    pub const fn pkpoly_bytes(&self) -> usize { (self.log_q as usize * N) / 8 }
    /// `SMAUGT_PKPOLYVEC_BYTES = PKPOLY_BYTES * k`. The b(x) vector packed.
    pub const fn pkpolyvec_bytes(&self) -> usize { self.pkpoly_bytes() * self.k }
    /// `SMAUGT_PUBLICKEY_BYTES = PKSEED_BYTES + PKPOLYVEC_BYTES`.
    pub const fn publickey_bytes(&self) -> usize { PKSEED_BYTES + self.pkpolyvec_bytes() }

    /// `SMAUGT_CTPOLY1_BYTES = log_p * N / 8`. One Rp polynomial packed.
    pub const fn ctpoly1_bytes(&self) -> usize { (self.log_p as usize * N) / 8 }
    /// `SMAUGT_CTPOLY2_BYTES = log_p_prime * N / 8`. One Rp' polynomial packed.
    pub const fn ctpoly2_bytes(&self) -> usize { (self.log_p_prime as usize * N) / 8 }
    /// `SMAUGT_CTPOLYVEC_BYTES = CTPOLY1_BYTES * k`. c1 vector packed.
    pub const fn ctpolyvec_bytes(&self) -> usize { self.ctpoly1_bytes() * self.k }
    /// `SMAUGT_CIPHERTEXT_BYTES = CTPOLYVEC_BYTES + CTPOLY2_BYTES`.
    pub const fn ciphertext_bytes(&self) -> usize { self.ctpolyvec_bytes() + self.ctpoly2_bytes() }

    /// `SMAUGT_SKPOLY_BYTES = N / 4 = 64`. One sparse-ternary poly packed (2 bits/coeff).
    pub const fn skpoly_bytes(&self) -> usize { N / 4 }
    /// `SMAUGT_SKPOLYVEC_BYTES = SKPOLY_BYTES * k`.
    pub const fn skpolyvec_bytes(&self) -> usize { self.skpoly_bytes() * self.k }
    /// `SMAUGT_PKE_SECRETKEY_BYTES = SKPOLYVEC_BYTES`. The s(x) vector packed.
    pub const fn pke_secretkey_bytes(&self) -> usize { self.skpolyvec_bytes() }
    /// `SMAUGT_KEM_SECRETKEY_BYTES = PKE_SECRETKEY + T_BYTES + PUBLICKEY`.
    pub const fn kem_secretkey_bytes(&self) -> usize {
        self.pke_secretkey_bytes() + T_BYTES + self.publickey_bytes()
    }
}
