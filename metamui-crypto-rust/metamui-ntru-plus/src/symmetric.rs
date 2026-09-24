//! Symmetric hash functions for NTRU+
//!
//! From `symmetric.c` of the ntruplus.org reference (commit 621c667):
//! - hash_f: SHAKE-256(0x00 || pk) → 32 bytes (public key hash)
//! - hash_g: SHAKE-256(0x01 || input) → N/4 bytes (SOTP key derivation)
//! - hash_h: SHAKE-256(0x02 || msg || pk_hash) → SSBYTES + N/4 bytes
//! - keygen PRF: SHAKE-256(coins) → N/4 bytes (CBD sampling tape)

use crate::params::NtruPlusParams;
use metamui_shake::shake256::Shake256;

/// hash_f: Hash public key using SHAKE-256 with domain separator 0x00.
/// H_f(pk) = SHAKE-256(0x00 || pk), 32 bytes.
///
/// The 2025 KpqClean revision used SHA-256 here; the 2026 reference
/// (ntruplus.org, spec dated 2026-02-02) moved every hash to SHAKE-256.
pub fn hash_f(out: &mut [u8], input: &[u8]) {
    let mut shake = Shake256::new();
    let _ = shake.update(&[0x00]);
    let _ = shake.update(input);
    let mut reader = shake.finalize_xof();
    let hash = reader.read(32);
    out[..32].copy_from_slice(&hash);
}

/// hash_g: Derive SOTP key using SHAKE-256 with domain separator 0x01.
/// H_g(input) = SHAKE-256(0x01 || input), expanded to N/4 bytes.
pub fn hash_g<P: NtruPlusParams>(out: &mut [u8], input: &[u8]) {
    let out_len = P::N / 4;
    let mut shake = Shake256::new();
    let _ = shake.update(&[0x01]);
    let _ = shake.update(input);
    let mut reader = shake.finalize_xof();
    let hash = reader.read(out_len);
    out[..out_len].copy_from_slice(&hash);
}

/// hash_h: Main KEM hash using SHAKE-256 with domain separator 0x02.
/// H_h(msg || pk_hash) = SHAKE-256(0x02 || msg || pk_hash),
/// expanded to SSBYTES + N/4 bytes.
pub fn hash_h<P: NtruPlusParams>(out: &mut [u8], input: &[u8]) {
    let out_len = P::SSBYTES + P::N / 4;
    let mut shake = Shake256::new();
    let _ = shake.update(&[0x02]);
    let _ = shake.update(input);
    let mut reader = shake.finalize_xof();
    let hash = reader.read(out_len);
    out[..out_len].copy_from_slice(&hash);
}

/// Keygen PRF: expand 32-byte seed to N/4 bytes using SHAKE-256.
/// This matches the reference's shake256(buf, N/4, buf, 32).
pub fn prf_keygen<P: NtruPlusParams>(out: &mut [u8], seed: &[u8]) {
    let out_len = P::N / 4;
    let mut shake = Shake256::new();
    let _ = shake.update(seed);
    let mut reader = shake.finalize_xof();
    let hash = reader.read(out_len);
    out[..out_len].copy_from_slice(&hash);
}
