//! Complete Falcon-512 sign/verify implementation with NIST-format signatures
//!
//! Signing produces NIST-format signatures:
//!   header(0x39) + nonce(40) + Golomb-Rice compressed s1
//!
//! Verification:
//!   1. Decode signature → (nonce, s1)
//!   2. Hash nonce || message → c (uniform mod q via SHAKE-256)
//!   3. Reconstruct s0 = c - s1*h (mod q) using NTT
//!   4. Check ||s0||² + ||s1||² ≤ ⌊β²⌋

use crate::constants::{N, Q, LOGN, BETA_SQUARED};
use crate::error::{Result, Falcon512Error};
use crate::poly::Poly;
use crate::{PublicKey, PrivateKey};
use rand::RngCore;
use alloc::vec::Vec;

/// Falcon-512 Gaussian sigma parameter
const SIGMA: f64 = 165.7366171829776;

/// Nonce length (bytes)
const SALT_LEN: usize = 40;

// ================================================================
// Norm check
// ================================================================

/// Verify that ||(s0, s1)||² ≤ ⌊β²⌋ (integer arithmetic, no floats; Algorithm 16, #352).
fn verify_signature_norm(s0: &[i16], s1: &[i16]) -> bool {
    let mut norm_sq: i64 = 0;
    for &x in s0 {
        norm_sq += (x as i64) * (x as i64);
    }
    for &x in s1 {
        norm_sq += (x as i64) * (x as i64);
    }
    norm_sq <= BETA_SQUARED as i64
}

// ================================================================
// Internal signing core
// ================================================================

/// Core signing: generate short (s0, s1) satisfying s0 + s1*h ≡ c (mod q)
/// and the nonce used for hashing.
///
/// Returns (s0, s1, nonce) on success, where:
///   - c = hash_to_point(nonce || message)
///   - s0 + s1*h = c (mod q) (NTRU lattice relation)
///   - ||(s0, s1)||² ≤ ⌊β²⌋ (the verifier's own norm check, so a candidate
///     exactly at the bound is kept)
///
/// Uses `ExpandedKey` to pre-compute the LDL tree and FFT-domain key polynomials
/// once, then reuse across all retry attempts. This is the key performance
/// optimization: the LDL tree construction (~60% of sign time) happens once
/// instead of on every retry.
fn sign_core<R: RngCore>(
    message: &[u8],
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<(Vec<i16>, Vec<i16>, Vec<u8>)> {
    const MAX_ATTEMPTS: usize = 100;

    for _attempt in 0..MAX_ATTEMPTS {
        // Generate random 40-byte nonce
        let mut nonce = vec![0u8; SALT_LEN];
        rng.fill_bytes(&mut nonce);

        // Hash nonce || message → challenge polynomial c ∈ [0, q)^n
        let c = crate::nist_hash::hash_to_point_nist(&nonce, message);

        // Sample short preimage (s0, s1) using canonical FFT + LDL signing
        // The SAME rng that drew the nonce above also drives the leaf Gaussian
        // sampler, so signing stays a pure function of the RNG stream: a caller
        // that seeds deterministically still gets byte-identical signatures.
        // `?` and not retry: the only error today is the LDL band violation,
        // which is a deterministic property of the key — retrying with a new
        // nonce cannot clear it.
        let (s0, s1) = crate::falcon_canonical::falcon_sign_sample(
            &private_key.f.coeffs,
            &private_key.g.coeffs,
            &private_key.big_f.coeffs,
            &private_key.big_g.coeffs,
            &c,
            SIGMA,
            rng,
        )?;

        if verify_signature_norm(&s0, &s1) {
            // Post-signing safety check: verify s0 + s1*h ≡ c (mod q)
            #[cfg(debug_assertions)]
            {
                let h = crate::ntt_falcon::compute_public_key_ntt(
                    &private_key.f.coeffs, &private_key.g.coeffs,
                ).expect("public key computation failed in post-signing check");
                let s1h = crate::ntt_falcon::multiply_ntt(&s1, &h);
                for i in 0..N {
                    let lhs = (s0[i] as i32 + s1h[i] as i32).rem_euclid(Q as i32);
                    let rhs = (c[i] as i32).rem_euclid(Q as i32);
                    debug_assert_eq!(lhs, rhs,
                        "Post-signing equation check failed at index {}", i);
                }
            }
            return Ok((s0, s1, nonce));
        }
        // Norm too large — retry with a new nonce
    }

    Err(Falcon512Error::SigningFailed)
}

/// KAT seam: like `sign_core` but with a caller-supplied nonce, mirroring the
/// reference `nist.c` (`randombytes(nonce)` once, then `sign_dyn` resamples
/// with the same hashed point until the norm bound holds). Not a production
/// entry point — production nonces come from the signing RNG.
/// Sample a short `(s0, s1)` for an already-computed challenge polynomial `c`,
/// retrying the Gaussian sampler until the norm bound holds. The Round-3 path
/// derives `c` from `nonce ‖ message`; the `fn-dsa-draft` path derives it with
/// the public-key hash bound in and the salt drawn once outside this loop.
pub(crate) fn sample_for_challenge<R: RngCore>(
    private_key: &PrivateKey,
    c: &[i16],
    rng: &mut R,
) -> Result<(Vec<i16>, Vec<i16>)> {
    const MAX_ATTEMPTS: usize = 100;
    for _attempt in 0..MAX_ATTEMPTS {
        let (s0, s1) = crate::falcon_canonical::falcon_sign_sample(
            &private_key.f.coeffs,
            &private_key.g.coeffs,
            &private_key.big_f.coeffs,
            &private_key.big_g.coeffs,
            c,
            SIGMA,
            rng,
        )?;
        if verify_signature_norm(&s0, &s1) {
            return Ok((s0, s1));
        }
    }
    Err(Falcon512Error::SigningFailed)
}

pub(crate) fn sign_core_with_nonce<R: RngCore>(
    message: &[u8],
    private_key: &PrivateKey,
    nonce: &[u8],
    rng: &mut R,
) -> Result<(Vec<i16>, Vec<i16>)> {
    if nonce.len() != SALT_LEN {
        return Err(Falcon512Error::InvalidNonce);
    }
    let c = crate::nist_hash::hash_to_point_nist(nonce, message);
    sample_for_challenge(private_key, &c, rng)
}

// ================================================================
// Public signing API
// ================================================================

/// Sign a message, returning a NIST-format Falcon-512 signature.
///
/// Output format: `header(0x39) + nonce(40) + Golomb-Rice(s1)`
///
/// Only s1 is stored; the verifier reconstructs s0 = c − s1·h (mod q).
pub fn sign_complete<R: RngCore>(
    message: &[u8],
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let (_s0, s1, nonce) = sign_core(message, private_key, rng)?;
    let sig = crate::nist_encoding::encode_signature(&s1, &nonce, LOGN);
    // Post-hoc bound, no extra RNG draws (callers seed the RNG deterministically
    // for consensus; the bytes for a given RNG stream must not move). The
    // reference coder cannot exceed this for a norm-bounded s1, so this is a
    // fail-closed guard against ever handing a consumer a truncatable value.
    if sig.len() > crate::sizes::falcon512::SIG_COMPRESSED_MAX {
        return Err(Falcon512Error::SignatureTooLong);
    }
    Ok(sig)
}

/// Sign a message in the **padded** profile: exactly
/// `sizes::falcon512::SIG_PADDED` (666) bytes, `[0x39] [nonce(40)] [comp(s1)]
/// [zero padding]`, the Round-3 `falcon.h` FALCON_SIG_PADDED format that
/// PQClean ships as `falcon-padded-512`.
///
/// A body that does not fit is retried with a fresh nonce, as the reference
/// does — the signature is never truncated. This is a separate entry point from
/// `sign_complete`, so the compressed profile's RNG consumption is unchanged.
pub fn sign_padded_complete<R: RngCore>(
    message: &[u8],
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    const MAX_ATTEMPTS: usize = 64;
    for _ in 0..MAX_ATTEMPTS {
        let (_s0, s1, nonce) = sign_core(message, private_key, rng)?;
        match crate::nist_encoding::encode_signature_padded(&s1, &nonce, LOGN) {
            Ok(sig) => return Ok(sig),
            Err(Falcon512Error::SignatureTooLong) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(Falcon512Error::SigningFailed)
}

/// Sign a message, returning (compressed_s2, nonce) separately.
///
/// Used by the NIST API layer (`nist_api.rs`) which assembles its own
/// signed-message format.
pub fn sign_nist<R: RngCore>(
    message: &[u8],
    private_key: &PrivateKey,
    rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (_s0, s1, nonce) = sign_core(message, private_key, rng)?;
    let compressed = crate::nist_encoding::comp_encode(&s1, LOGN);
    Ok((compressed, nonce))
}

// ================================================================
// Public verification API
// ================================================================

/// Verify a NIST-format Falcon-512 signature.
///
/// Signature format: `header(0x39) + nonce(40) + Golomb-Rice(s1)`
///
/// Steps:
/// 1. Decompress s1 from signature
/// 2. Recompute challenge c = SHAKE-256(nonce || message) → uniform mod q
/// 3. Reconstruct s0 = c − s1·h (mod q)
/// 4. Accept iff ||(s0, s1)||² ≤ ⌊β²⌋
pub fn verify_complete(
    message: &[u8],
    signature: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    // Decode NIST-format signature → (nonce, s1); strict, no trailing bytes.
    let (nonce, s1) = crate::nist_encoding::decode_signature(signature, LOGN)?;
    Ok(verify_decoded(message, &nonce, &s1, public_key))
}

/// Verify a **padded**-profile signature (exactly 666 bytes, zero padding
/// enforced). Same math as `verify_complete`; only the framing differs.
pub fn verify_padded_complete(
    message: &[u8],
    signature: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    let (nonce, s1) = crate::nist_encoding::decode_signature_padded(signature, LOGN)?;
    Ok(verify_decoded(message, &nonce, &s1, public_key))
}

/// Shared verification core over an already-decoded `(nonce, s1)`.
fn verify_decoded(message: &[u8], nonce: &[u8], s1: &[i16], public_key: &PublicKey) -> bool {
    // Hash nonce || message → challenge polynomial c
    let c = crate::nist_hash::hash_to_point_nist(nonce, message);
    verify_with_challenge(&c, s1, public_key)
}

/// Verification core over an already-computed challenge `c` and decoded `s1`.
pub(crate) fn verify_with_challenge(c: &[i16], s1: &[i16], public_key: &PublicKey) -> bool {
    // Reconstruct s0 = c − s1·h (mod q) using negacyclic NTT multiplication
    let s1h = crate::ntt_falcon::multiply_ntt(s1, &public_key.h.coeffs);
    let mut s0 = vec![0i16; N];
    for i in 0..N {
        let diff = (c[i] as i32 - s1h[i] as i32).rem_euclid(Q as i32);
        // Center-reduce to [−q/2, q/2)
        s0[i] = if diff >= (Q as i32 + 1) / 2 {
            (diff - Q as i32) as i16
        } else {
            diff as i16
        };
    }

    // Check norm bound: ||(s0, s1)||² ≤ ⌊β²⌋ (#352)
    verify_signature_norm(&s0, s1)
}

/// Verify with custom configuration (API compatibility).
///
/// With correct NIST-format signatures, most config options are not needed.
/// The verification equation is automatically satisfied by reconstruction,
/// and no error tolerance or iterative refinement is required.
pub fn verify_complete_with_config(
    message: &[u8],
    signature: &[u8],
    public_key: &PublicKey,
    _config: &crate::verification_config::VerificationConfig,
) -> Result<bool> {
    verify_complete(message, signature, public_key)
}

// ================================================================
// Key generation helpers (used by falcon.rs and tests)
// ================================================================

/// Key generation using the working NTRU solver with fallbacks.
pub fn keygen_complete_simple<R: RngCore + Send>(rng: &mut R) -> Result<(PublicKey, PrivateKey)> {
    const MAX_ATTEMPTS: usize = 50;

    for _attempt in 0..MAX_ATTEMPTS {
        if let Ok((f, g, big_f, big_g)) = crate::ntru_working::ntru_keygen_working(rng) {
            // Compute public key h = g·f⁻¹ (mod q) via NTT
            match crate::ntt_falcon::compute_public_key_ntt(&f, &g) {
                Ok(h) => {
                    return Ok((
                        PublicKey { h: Poly { coeffs: h } },
                        PrivateKey {
                            f: Poly { coeffs: f },
                            g: Poly { coeffs: g },
                            big_f: Poly { coeffs: big_f },
                            big_g: Poly { coeffs: big_g },
                        },
                    ));
                }
                Err(_) => continue,
            }
        }
    }

    Err(Falcon512Error::KeyGenerationFailed)
}

// ================================================================
// Legacy raw-byte API (used by kat_validation.rs)
// ================================================================

/// Generate keypair returning raw bytes (legacy format).
///
/// Returns (pk_bytes, sk_bytes) where each polynomial is stored as
/// 512 × 2 bytes in little-endian i16 format.
pub fn generate_keypair<R: RngCore + Send>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>)> {
    let (public_key, private_key) = keygen_complete_simple(rng)?;

    let mut pk_bytes = Vec::with_capacity(N * 2);
    for &coeff in &public_key.h.coeffs {
        pk_bytes.extend_from_slice(&coeff.to_le_bytes());
    }

    let mut sk_bytes = Vec::with_capacity(N * 8);
    for &coeff in &private_key.f.coeffs {
        sk_bytes.extend_from_slice(&coeff.to_le_bytes());
    }
    for &coeff in &private_key.g.coeffs {
        sk_bytes.extend_from_slice(&coeff.to_le_bytes());
    }
    for &coeff in &private_key.big_f.coeffs {
        sk_bytes.extend_from_slice(&coeff.to_le_bytes());
    }
    for &coeff in &private_key.big_g.coeffs {
        sk_bytes.extend_from_slice(&coeff.to_le_bytes());
    }

    Ok((pk_bytes, sk_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_sign_verify_nist_format() {
        let mut rng = StdRng::seed_from_u64(42);

        // Generate keypair
        let keypair = crate::generate_keypair(&mut rng)
            .expect("Key generation should succeed");

        let message = b"Test message for NIST format";

        // Sign
        let signature = sign_complete(message, &keypair.private_key, &mut rng)
            .expect("Signing should succeed");

        // Check NIST format: header(0x39) + nonce(40) + compressed
        assert_eq!(signature[0], 0x39, "Header should be 0x39 for Falcon-512");
        assert!(signature.len() > 41, "Signature must have header + nonce + data");
        assert!(signature.len() < 1200, "Compressed signature should be under 1200 bytes");

        // Verify
        let valid = verify_complete(message, &signature, &keypair.public_key)
            .expect("Verification should succeed");
        assert!(valid, "Valid signature should verify");

        // Wrong message should fail
        let wrong_msg = b"Wrong message";
        let invalid = verify_complete(wrong_msg, &signature, &keypair.public_key)
            .expect("Verification should succeed");
        assert!(!invalid, "Wrong message should fail verification");
    }

    #[test]
    fn test_sign_nist_api() {
        let mut rng = StdRng::seed_from_u64(123);

        let keypair = crate::generate_keypair(&mut rng)
            .expect("Key generation should succeed");

        let message = b"NIST API test";

        // sign_nist returns (compressed, nonce) separately
        let (compressed, nonce) = sign_nist(message, &keypair.private_key, &mut rng)
            .expect("Signing should succeed");

        assert_eq!(nonce.len(), 40);
        assert!(!compressed.is_empty());

        // Reconstruct full NIST signature for verification
        let mut full_sig = Vec::new();
        full_sig.push(0x39);
        full_sig.extend_from_slice(&nonce);
        full_sig.extend_from_slice(&compressed);

        let valid = verify_complete(message, &full_sig, &keypair.public_key)
            .expect("Verification should succeed");
        assert!(valid);
    }

    #[test]
    fn test_keygen_complete_simple() {
        let mut rng = StdRng::seed_from_u64(99);
        let (pk, sk) = keygen_complete_simple(&mut rng)
            .expect("Keygen should succeed");

        assert_eq!(pk.h.coeffs.len(), N);
        assert_eq!(sk.f.coeffs.len(), N);
        assert_eq!(sk.g.coeffs.len(), N);
        assert_eq!(sk.big_f.coeffs.len(), N);
        assert_eq!(sk.big_g.coeffs.len(), N);

        // Public key coefficients should be in [0, q)
        for &c in &pk.h.coeffs {
            assert!(c >= 0 && c < Q as i16, "pk coeff {} out of range", c);
        }
    }
}
