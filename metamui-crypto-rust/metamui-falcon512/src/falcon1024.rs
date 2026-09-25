//! Falcon-1024 implementation
//!
//! Extends the Falcon-512 crate to support Falcon-1024 (NIST Level 5, 256-bit security).
//! Uses the same core algorithms (NTT, NTRU solver, FFSampling, NIST encoding) but
//! parameterized for n=1024.
//!
//! Key differences from Falcon-512:
//!   - n=1024, logn=10
//!   - PSI=1945 (primitive 2048th root of unity mod q)
//!   - σ_sign=168.39 (vs 165.74), σ_keygen≈2.866 (vs 4.053)
//!   - ⌊β²⌋=70265242 (vs 34034726), the Round 3 reference l2bound[10] (#359)
//!   - Private key trim: f=5 bits, g=5 bits, F=8 bits (vs 6,6,8)
//!   - PK=1793 bytes, SK=2305 bytes, Sig≈1330 bytes

use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;
use rand::RngCore;

// ================================================================
// Constants for Falcon-1024
// ================================================================

const N: usize = 1024;
const LOGN: usize = 10;
const Q: u16 = 12289;

/// Gaussian sigma for signing (FFSampling LDL tree).
///
/// Spec value: 1.17 · σ_min(1024) · √q = 1.17 · 1.2982803343442918 · √12289.
/// This previously read 203.93, which is not any Falcon parameter. Besides
/// mis-sizing signatures, 203.93 put the LDL leaf widths (σ / √d, d ≈ q) at
/// ~1.84 — above `sampler_z`'s SIGMA_MAX = 1.8205, so the leaves could not
/// even have been sampled correctly. See #143.
const SIGMA: f64 = 168.3885714457672;

/// Gaussian sigma for key generation polynomial sampling
/// σ = 1.17 · √(q / (2n)) ≈ 2.8660 for n=1024, q=12289
const KEYGEN_SIGMA: f64 = 2.866;

/// Signature norm bound (beta squared)
const BETA_SQUARED: u64 = 70265242;

/// Nonce size in bytes
const SALT_LEN: usize = 40;

/// Public key size: 1 header + ceil(1024 * 14 / 8) = 1793 bytes
pub const PUBLIC_KEY_SIZE: usize = 1793;

/// Private key size: 1 header + ceil(1024 * (5 + 5 + 8) / 8) = 2305 bytes
pub const PRIVATE_KEY_SIZE: usize = 2305;

// ================================================================
// Key types
// ================================================================

/// Falcon-1024 public key
#[derive(Clone, Debug)]
pub struct PublicKey1024 {
    pub h: Vec<i16>,
}

impl PublicKey1024 {
    pub fn new(h: Vec<i16>) -> Result<Self> {
        if h.len() != N {
            return Err(Falcon512Error::InvalidPolynomialSize);
        }
        Ok(PublicKey1024 { h })
    }

    /// Deserialize from NIST format [header(0x0A)] [14-bit packed h] (1793
    /// bytes) or the legacy raw format, 1024 little-endian i16 coefficients
    /// (2048 bytes). Both require every coefficient in [0, q).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == PUBLIC_KEY_SIZE {
            let h = crate::nist_encoding::decode_public_key(bytes, LOGN)?;
            Ok(PublicKey1024 { h })
        } else if bytes.len() == N * 2 {
            // Legacy raw format; it used to take any i16, so x and x ± q
            // were different encodings of one key (M-19).
            let h = crate::nist_encoding::decode_raw_public_key(bytes, LOGN)?;
            Ok(PublicKey1024 { h })
        } else {
            Err(Falcon512Error::InvalidPublicKey)
        }
    }

    /// Serialize to NIST format: [header(0x0A)] [14-bit packed h]
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::nist_encoding::encode_public_key(&self.h, LOGN)
    }
}

/// Falcon-1024 private key
#[derive(Clone, Debug)]
pub struct PrivateKey1024 {
    pub f: Vec<i16>,
    pub g: Vec<i16>,
    pub big_f: Vec<i16>,
    pub big_g: Vec<i16>,
}

impl Drop for PrivateKey1024 {
    fn drop(&mut self) {
        use crate::secure_zeroize::secure_zero_i16;
        secure_zero_i16(&mut self.f);
        secure_zero_i16(&mut self.g);
        secure_zero_i16(&mut self.big_f);
        secure_zero_i16(&mut self.big_g);
    }
}

impl PrivateKey1024 {
    pub fn new(f: Vec<i16>, g: Vec<i16>, big_f: Vec<i16>, big_g: Vec<i16>) -> Result<Self> {
        if f.len() != N || g.len() != N || big_f.len() != N || big_g.len() != N {
            return Err(Falcon512Error::InvalidPolynomialSize);
        }
        Ok(PrivateKey1024 { f, g, big_f, big_g })
    }

    /// Deserialize from NIST format: [header(0x5A)] [f:5bit] [g:5bit] [F:8bit]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == PRIVATE_KEY_SIZE {
            let (f, g, big_f) = crate::nist_encoding::decode_private_key(bytes, LOGN)?;
            // Recover G from NTRU equation: f·G − g·F = q  →  G = (q + g·F) · f⁻¹ mod q
            let big_g = crate::ntt_falcon::recover_big_g_n(&f, &g, &big_f, N)?;
            Ok(PrivateKey1024 { f, g, big_f, big_g })
        } else if bytes.len() >= N * 2 * 4 {
            // Legacy raw format
            let bp = N * 2;
            let to_poly = |b: &[u8]| -> Vec<i16> {
                b.chunks(2).map(|c| i16::from_le_bytes([c[0], c[1]])).collect()
            };
            Ok(PrivateKey1024 {
                f: to_poly(&bytes[0..bp]),
                g: to_poly(&bytes[bp..bp*2]),
                big_f: to_poly(&bytes[bp*2..bp*3]),
                big_g: to_poly(&bytes[bp*3..bp*4]),
            })
        } else {
            Err(Falcon512Error::InvalidPrivateKey)
        }
    }

    /// Serialize to NIST format: [header(0x5A)] [f:5bit] [g:5bit] [F:8bit]
    ///
    /// # Panics
    /// If a coefficient does not fit the encoding, which no key from keygen or
    /// `from_bytes` has; use [`try_to_bytes`](Self::try_to_bytes) for keys
    /// assembled from arbitrary polynomials (#341).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("Falcon-1024 private key coefficients outside the NIST encoding range")
    }

    /// Serialize to NIST format, refusing a key whose coefficients do not fit.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        crate::nist_encoding::encode_private_key(&self.f, &self.g, &self.big_f, LOGN)
    }
}

/// Falcon-1024 key pair
#[derive(Clone, Debug)]
pub struct KeyPair1024 {
    pub public_key: PublicKey1024,
    pub private_key: PrivateKey1024,
}

// ================================================================
// Key generation
// ================================================================

/// Generate a Falcon-1024 key pair.
///
/// Uses recursive field norm NTRU solver and NTT-based public key computation,
/// the same algorithms as Falcon-512 but parameterized for n=1024.
// ================================================================
// Deep-stack entry points
// ================================================================

/// Falcon-1024's NTRU solve and ff-sampling recurse deeply enough to need more
/// than 2 MB of stack — measured on Windows: 1, 1.5 and 2 MB overflow, 3 and
/// 8 MB pass. Linux's 8 MB default hides that; Windows' 1 MB default does not,
/// so `generate_keypair_1024` and the signing path abort a default-stack thread
/// with STATUS_STACK_OVERFLOW. Run them where there is room. See issue #188.
/// The worker lives in `crate::deep_stack`, shared with Falcon-512's keygen
/// since #265 found the same overflow there.
///
/// Verification does not recurse this way and is left on the caller's thread.
use crate::deep_stack::with_deep_stack;

pub fn generate_keypair_1024<R: RngCore + Send>(rng: &mut R) -> Result<KeyPair1024> {
    with_deep_stack(move || generate_keypair_1024_inner(rng))
}

fn generate_keypair_1024_inner<R: RngCore>(rng: &mut R) -> Result<KeyPair1024> {
    const MAX_OUTER_ATTEMPTS: usize = 50;

    for _ in 0..MAX_OUTER_ATTEMPTS {
        // Use the parameterized NTRU keygen with n=1024 sigma
        if let Ok((f, g, big_f, big_g)) = crate::ntru_working::ntru_keygen_n(rng, N, KEYGEN_SIGMA) {
            // Compute public key h = g·f⁻¹ (mod q) via NTT
            match crate::ntt_falcon::compute_public_key_ntt_n(&f, &g, N) {
                Ok(h) => {
                    let public_key = PublicKey1024::new(h)?;
                    let private_key = PrivateKey1024::new(f, g, big_f, big_g)?;
                    return Ok(KeyPair1024 { public_key, private_key });
                }
                Err(_) => continue,
            }
        }
    }

    Err(Falcon512Error::KeyGenerationFailed)
}

// ================================================================
// Norm check
// ================================================================

/// Verify that ||(s0, s1)||² ≤ ⌊β²⌋ (Algorithm 16 of the specification, #352).
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
// Signing
// ================================================================

/// Core signing: generate short (s0, s1) satisfying s0 + s1·h ≡ c (mod q).
fn sign_core<R: RngCore + Send>(
    message: &[u8],
    private_key: &PrivateKey1024,
    rng: &mut R,
) -> Result<(Vec<i16>, Vec<i16>, Vec<u8>)> {
    with_deep_stack(move || sign_core_inner(message, private_key, rng))
}

fn sign_core_inner<R: RngCore>(
    message: &[u8],
    private_key: &PrivateKey1024,
    rng: &mut R,
) -> Result<(Vec<i16>, Vec<i16>, Vec<u8>)> {
    const MAX_ATTEMPTS: usize = 100;

    for _ in 0..MAX_ATTEMPTS {
        // Generate random 40-byte nonce
        let mut nonce = vec![0u8; SALT_LEN];
        rng.fill_bytes(&mut nonce);

        // Hash nonce || message → challenge polynomial c ∈ [0, q)^n
        let c = crate::nist_hash::hash_to_point_nist_n(&nonce, message, N);

        // Sample short preimage (s0, s1) via FFSampling
        let sampling_result = crate::ffsampling_falcon::falcon_sign_sample(
            &private_key.f,
            &private_key.g,
            &private_key.big_f,
            &private_key.big_g,
            &c,
            SIGMA,
            rng,
        );

        match sampling_result {
            Ok((s0, s1)) => {
                if verify_signature_norm(&s0, &s1) {
                    return Ok((s0, s1, nonce));
                }
                // Norm too large — retry
            }
            Err(_) => continue,
        }
    }

    Err(Falcon512Error::SigningFailed)
}

/// Sign a message, returning a NIST-format Falcon-1024 signature.
///
/// Output format: `header(0x3A) + nonce(40) + Golomb-Rice(s1)`
pub fn sign_1024<R: RngCore + Send>(
    message: &[u8],
    private_key: &PrivateKey1024,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let (_s0, s1, nonce) = sign_core(message, private_key, rng)?;
    let sig = crate::nist_encoding::encode_signature(&s1, &nonce, LOGN);
    if sig.len() > crate::sizes::falcon1024::SIG_COMPRESSED_MAX {
        return Err(Falcon512Error::SignatureTooLong);
    }
    Ok(sig)
}

/// Sign in the **padded** profile: exactly `sizes::falcon1024::SIG_PADDED`
/// (1280) bytes, `[0x3A] [nonce(40)] [comp(s1)] [zero padding]`. Oversize
/// bodies are retried with a fresh nonce, never truncated.
pub fn sign_padded_1024<R: RngCore + Send>(
    message: &[u8],
    private_key: &PrivateKey1024,
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

// ================================================================
// Verification
// ================================================================

/// Verify a NIST-format Falcon-1024 signature.
///
/// Signature format: `header(0x3A) + nonce(40) + Golomb-Rice(s1)`
pub fn verify_1024(
    message: &[u8],
    signature: &[u8],
    public_key: &PublicKey1024,
) -> Result<bool> {
    // Decode NIST-format signature → (nonce, s1); strict, no trailing bytes.
    let (nonce, s1) = crate::nist_encoding::decode_signature(signature, LOGN)?;
    Ok(verify_decoded_1024(message, &nonce, &s1, public_key))
}

/// Verify a **padded**-profile Falcon-1024 signature (exactly 1280 bytes).
pub fn verify_padded_1024(
    message: &[u8],
    signature: &[u8],
    public_key: &PublicKey1024,
) -> Result<bool> {
    let (nonce, s1) = crate::nist_encoding::decode_signature_padded(signature, LOGN)?;
    Ok(verify_decoded_1024(message, &nonce, &s1, public_key))
}

fn verify_decoded_1024(message: &[u8], nonce: &[u8], s1: &[i16], public_key: &PublicKey1024) -> bool {
    // Hash nonce || message → challenge polynomial c
    let c = crate::nist_hash::hash_to_point_nist_n(nonce, message, N);

    // Reconstruct s0 = c − s1·h (mod q) using negacyclic NTT
    let q = Q as i32;
    let s1h = crate::ntt_falcon::multiply_ntt_n(s1, &public_key.h, N);
    let mut s0 = vec![0i16; N];
    for i in 0..N {
        let diff = (c[i] as i32 - s1h[i] as i32).rem_euclid(q);
        s0[i] = if diff >= (q + 1) / 2 {
            (diff - q) as i16
        } else {
            diff as i16
        };
    }

    // Check norm bound
    verify_signature_norm(&s0, s1)
}

// ================================================================
// Tests
// ================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_falcon1024_keygen() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let keypair = generate_keypair_1024(&mut rng).expect("Key generation should succeed");

        assert_eq!(keypair.public_key.h.len(), 1024);
        assert_eq!(keypair.private_key.f.len(), 1024);
        assert_eq!(keypair.private_key.g.len(), 1024);
        assert_eq!(keypair.private_key.big_f.len(), 1024);
        assert_eq!(keypair.private_key.big_g.len(), 1024);

        // Public key coefficients should be in [0, q)
        for &c in &keypair.public_key.h {
            assert!(c >= 0 && c < Q as i16, "pk coeff {} out of range", c);
        }

        // Verify NTRU equation
        assert!(
            crate::ntru_working::verify_ntru_equation_n(
                &keypair.private_key.f,
                &keypair.private_key.g,
                &keypair.private_key.big_f,
                &keypair.private_key.big_g,
                N,
            ),
            "NTRU equation f*G - g*F = q should hold"
        );
    }

    #[test]
    fn test_falcon1024_sign_verify() {
        let mut rng = ChaCha20Rng::from_seed([43u8; 32]);
        let keypair = generate_keypair_1024(&mut rng).expect("Key generation should succeed");

        let message = b"Test message for Falcon-1024";
        let signature = sign_1024(message, &keypair.private_key, &mut rng)
            .expect("Signing should succeed");

        // Check NIST format
        assert_eq!(signature[0], 0x3A, "Header should be 0x3A for Falcon-1024");
        assert!(signature.len() > 41, "Signature must have header + nonce + data");
        assert!(signature.len() < 2000, "Compressed signature should be reasonable size");

        // Verify signature
        let valid = verify_1024(message, &signature, &keypair.public_key)
            .expect("Verification should succeed");
        assert!(valid, "Valid signature should verify");

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let invalid = verify_1024(wrong_message, &signature, &keypair.public_key)
            .expect("Verification should succeed");
        assert!(!invalid, "Wrong message should fail verification");
    }

    #[test]
    fn test_falcon1024_nist_key_encoding() {
        let mut rng = ChaCha20Rng::from_seed([44u8; 32]);
        let keypair = generate_keypair_1024(&mut rng).expect("Key generation should succeed");

        // Test public key encoding roundtrip
        let pk_bytes = keypair.public_key.to_bytes();
        assert_eq!(pk_bytes.len(), PUBLIC_KEY_SIZE);
        assert_eq!(pk_bytes[0], LOGN as u8); // header = 0x0A

        let pk_decoded = PublicKey1024::from_bytes(&pk_bytes)
            .expect("Public key decode should succeed");
        assert_eq!(pk_decoded.h, keypair.public_key.h);

        // Test private key encoding roundtrip
        let sk_bytes = keypair.private_key.to_bytes();
        assert_eq!(sk_bytes.len(), PRIVATE_KEY_SIZE);
        assert_eq!(sk_bytes[0], 0x5A); // header = 0x50 | 0x0A

        let sk_decoded = PrivateKey1024::from_bytes(&sk_bytes)
            .expect("Private key decode should succeed");
        assert_eq!(sk_decoded.f, keypair.private_key.f);
        assert_eq!(sk_decoded.g, keypair.private_key.g);
        assert_eq!(sk_decoded.big_f, keypair.private_key.big_f);
        // big_g is not encoded in NIST format (recomputed from equation)
    }

    /// A canonical h (every coefficient in [0, q)); decoding never needs a real key.
    fn canonical_h() -> Vec<i16> {
        (0..N).map(|i| ((i * 7919 + 5) % Q as usize) as i16).collect()
    }

    fn raw_public_key(h: &[i16]) -> Vec<u8> {
        h.iter().flat_map(|c| c.to_le_bytes()).collect()
    }

    /// M-19: the raw 2048-byte form must name one key per byte string, as the
    /// 14-bit form does, while the canonical raw form keeps decoding.
    #[test]
    fn test_falcon1024_public_key_forms_are_canonical() {
        let h = canonical_h();
        let pk = PublicKey1024 { h: h.clone() };
        let standard = pk.to_bytes();
        let raw = raw_public_key(&h);
        assert_eq!(PublicKey1024::from_bytes(&standard).unwrap().h, h);
        assert_eq!(PublicKey1024::from_bytes(&raw).unwrap().h, h);

        let q = Q as i16;
        for (i, bad) in [(0, h[0] + q), (N - 1, h[N - 1] - q), (3, -1), (4, q), (5, i16::MAX)] {
            let mut coeffs = h.clone();
            coeffs[i] = bad;
            assert!(PublicKey1024::from_bytes(&raw_public_key(&coeffs)).is_err(), "raw h[{i}] = {bad}");
        }

        // Coefficient 0 of the 14-bit form is byte 1 and the top 6 bits of byte 2.
        for bad in [Q, 0x3FFF] {
            let mut bytes = standard.clone();
            bytes[1] = (bad >> 6) as u8;
            bytes[2] = (bytes[2] & 0x03) | ((bad as u8 & 0x3F) << 2);
            assert!(PublicKey1024::from_bytes(&bytes).is_err(), "packed h[0] = {bad}");
        }

        for len in [0, 897, 1024, 1792, 1794, 2047, 2049] {
            let mut bytes = raw.clone();
            bytes.resize(len, 0);
            assert!(PublicKey1024::from_bytes(&bytes).is_err(), "{len}-byte public key");
        }
    }

    #[test]
    fn test_falcon1024_corrupted_signature() {
        let mut rng = ChaCha20Rng::from_seed([45u8; 32]);
        let keypair = generate_keypair_1024(&mut rng).expect("Key generation should succeed");

        let message = b"Corruption test";
        let mut signature = sign_1024(message, &keypair.private_key, &mut rng)
            .expect("Signing should succeed");

        // Flip a bit in the compressed s1 portion
        let mid = signature.len() / 2;
        signature[mid] ^= 0xFF;

        // Either decompression fails or norm check fails
        let result = verify_1024(message, &signature, &keypair.public_key);
        match result {
            Ok(valid) => assert!(!valid, "Corrupted signature should not verify"),
            Err(_) => {} // Decompression failure is also acceptable
        }
    }
}
