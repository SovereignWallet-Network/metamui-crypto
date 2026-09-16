//! FN-DSA (FIPS 206) **draft hooks** — behind the `fn-dsa-draft` feature, off
//! by default, and deliberately not wire-compatible with anything.
//!
//! NIST submitted FIPS 206 for approval on 2025-08-28 and stated what changes
//! relative to Round-3 Falcon, without publishing the IPD text: the salt is
//! sampled once outside the retry loop, the public-key hash is bound into
//! the message hash (a BUFF transform), signing is randomized only, and the
//! pure / pre-hash (HashFN-DSA) / external-μ variants exist as in FIPS 204;
//! encodings and OIDs "are not yet locked". This module lays those hooks out
//! so that the byte layouts can be swapped for the standard's ones when the
//! text lands, and so the code paths exist and are tested now. Every layout
//! below is an assumption and is marked as such:
//!
//! * `M'` follows FIPS 204 §5.2 / §5.4 (`0x00 ‖ |ctx| ‖ ctx ‖ M`,
//!   `0x01 ‖ |ctx| ‖ ctx ‖ OID ‖ PH(M)`) through the shared
//!   `metamui-prehash-oids` table — **assumed**;
//! * the challenge is `HashToPoint(SHAKE256(salt ‖ H(pk) ‖ M'))` with
//!   `H(pk) = SHAKE256(pk, 64)` — the binding is NIST's stated intent, the
//!   order and length are **assumed**;
//! * the signature encoding is the Round-3 compressed one (`0x30|logn ‖ salt
//!   ‖ comp(s2)`), so the signature *shape* is Falcon-512's; the bytes cannot
//!   verify under a Round-3 verifier because the challenge differs, which the
//!   tests assert.
//!
//! The Round-3 profiles (`sign`, `sign_padded`, `verify`, …) are untouched:
//! the default build does not compile this module.

use crate::constants::LOGN;
use crate::error::{Falcon512Error, Result};
use crate::shake::Shake256Context;
use crate::{PrivateKey, PublicKey};
use alloc::vec;
use alloc::vec::Vec;
use rand::{CryptoRng, RngCore};

pub use metamui_prehash_oids::PreHashAlgorithm;

/// Length of `H(pk)` bound into the challenge (assumed: 64 bytes of SHAKE256).
pub const PK_HASH_LEN: usize = 64;

/// How the message enters `M'` (FIPS 204-style, assumed for FN-DSA).
#[derive(Clone, Copy, Debug)]
pub enum MessageEncoding<'a> {
    /// `M' = 0x00 ‖ |ctx| ‖ ctx ‖ M`
    Pure { context: &'a [u8] },
    /// `M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID(alg) ‖ alg(M)` (HashFN-DSA)
    PreHash { alg: PreHashAlgorithm, context: &'a [u8] },
}

/// `H(pk)`: SHAKE256 of the encoded public key, `PK_HASH_LEN` bytes.
pub fn public_key_hash(public_key: &PublicKey) -> [u8; PK_HASH_LEN] {
    let mut h = Shake256Context::new();
    h.update(&public_key.to_bytes());
    let mut r = h.finalize_xof();
    let mut out = [0u8; PK_HASH_LEN];
    r.read(&mut out);
    out
}

/// Build the message representative `M'` for `encoding`.
pub fn message_representative(encoding: MessageEncoding<'_>, message: &[u8]) -> Result<Vec<u8>> {
    let (tag, context, tail): (u8, &[u8], Vec<u8>) = match encoding {
        MessageEncoding::Pure { context } => (0x00, context, message.to_vec()),
        MessageEncoding::PreHash { alg, context } => {
            let mut t = alg.oid().to_vec();
            t.extend_from_slice(&alg.hash(message));
            (0x01, context, t)
        }
    };
    if context.len() > 255 {
        return Err(Falcon512Error::InvalidParameter);
    }
    let mut m = Vec::with_capacity(2 + context.len() + tail.len());
    m.push(tag);
    m.push(context.len() as u8);
    m.extend_from_slice(context);
    m.extend_from_slice(&tail);
    Ok(m)
}

/// Draft challenge: `HashToPoint(SHAKE256(salt ‖ H(pk) ‖ M'))`, the same
/// rejection sampling as the Round-3 `hash_to_point_nist` (big-endian 16-bit
/// draws, threshold 5·q) over a different absorb layout.
pub fn hash_to_point_fn_dsa(salt: &[u8], pk_hash: &[u8; PK_HASH_LEN], m_prime: &[u8]) -> Vec<i16> {
    use crate::constants::{N, Q};
    let mut hasher = Shake256Context::new();
    hasher.update(salt);
    hasher.update(pk_hash);
    hasher.update(m_prime);
    let mut reader = hasher.finalize_xof();
    let mut c = vec![0i16; N];
    for coeff in c.iter_mut() {
        loop {
            let buf = reader.read_bytes(2);
            let val = ((buf[0] as u16) << 8) | (buf[1] as u16);
            if val < 61445 {
                *coeff = (val % Q) as i16;
                break;
            }
        }
    }
    c
}

/// Randomized draft signing over an externally supplied `M'` (the external-μ
/// entry): the 40-byte salt is drawn **once**, before the sampler retry loop.
pub fn sign_draft_external_mu<R: RngCore + CryptoRng>(
    m_prime: &[u8],
    private_key: &PrivateKey,
    public_key: &PublicKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; crate::sizes::NONCE_LEN];
    rng.fill_bytes(&mut salt);
    let c = hash_to_point_fn_dsa(&salt, &public_key_hash(public_key), m_prime);
    let (_s0, s1) = crate::falcon_complete::sample_for_challenge(private_key, &c, rng)?;
    let sig = crate::nist_encoding::encode_signature(&s1, &salt, LOGN);
    if sig.len() > crate::sizes::falcon512::SIG_COMPRESSED_MAX {
        return Err(Falcon512Error::SignatureTooLong);
    }
    Ok(sig)
}

/// Randomized draft signing of `message` under `encoding` (pure or HashFN-DSA).
pub fn sign_draft<R: RngCore + CryptoRng>(
    message: &[u8],
    encoding: MessageEncoding<'_>,
    private_key: &PrivateKey,
    public_key: &PublicKey,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let m_prime = message_representative(encoding, message)?;
    sign_draft_external_mu(&m_prime, private_key, public_key, rng)
}

/// Verify a draft signature over an externally supplied `M'`.
pub fn verify_draft_external_mu(m_prime: &[u8], signature: &[u8], public_key: &PublicKey) -> Result<bool> {
    let (salt, s1) = match crate::nist_encoding::decode_signature(signature, LOGN) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    let c = hash_to_point_fn_dsa(&salt, &public_key_hash(public_key), m_prime);
    Ok(crate::falcon_complete::verify_with_challenge(&c, &s1, public_key))
}

/// Verify a draft signature of `message` under `encoding`.
pub fn verify_draft(
    message: &[u8],
    encoding: MessageEncoding<'_>,
    signature: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    let m_prime = message_representative(encoding, message)?;
    verify_draft_external_mu(&m_prime, signature, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn keys() -> (PublicKey, PrivateKey) {
        let mut rng = StdRng::seed_from_u64(7);
        let kp = crate::generate_keypair(&mut rng).expect("keygen");
        (kp.public_key, kp.private_key)
    }

    #[test]
    fn pure_round_trip_and_context_binding() {
        let (pk, sk) = keys();
        let mut rng = StdRng::seed_from_u64(1);
        let ctx = b"fn-dsa-draft";
        let sig = sign_draft(b"hello", MessageEncoding::Pure { context: ctx }, &sk, &pk, &mut rng).unwrap();
        assert!(verify_draft(b"hello", MessageEncoding::Pure { context: ctx }, &sig, &pk).unwrap());
        assert!(!verify_draft(b"hello", MessageEncoding::Pure { context: b"" }, &sig, &pk).unwrap());
        assert!(!verify_draft(b"hellp", MessageEncoding::Pure { context: ctx }, &sig, &pk).unwrap());
    }

    #[test]
    fn prehash_round_trip_matches_external_mu() {
        let (pk, sk) = keys();
        let mut rng = StdRng::seed_from_u64(2);
        let enc = MessageEncoding::PreHash { alg: PreHashAlgorithm::Sha256, context: b"" };
        let sig = sign_draft(b"hash me", enc, &sk, &pk, &mut rng).unwrap();
        assert!(verify_draft(b"hash me", enc, &sig, &pk).unwrap());
        let mu = message_representative(enc, b"hash me").unwrap();
        assert!(verify_draft_external_mu(&mu, &sig, &pk).unwrap());
        assert!(!verify_draft(b"hash me", MessageEncoding::PreHash { alg: PreHashAlgorithm::Sha512, context: b"" }, &sig, &pk).unwrap());
    }

    #[test]
    fn public_key_is_bound_and_signing_is_randomized() {
        let (pk, sk) = keys();
        let mut rng = StdRng::seed_from_u64(3);
        let enc = MessageEncoding::Pure { context: b"" };
        let a = sign_draft(b"m", enc, &sk, &pk, &mut rng).unwrap();
        let b = sign_draft(b"m", enc, &sk, &pk, &mut rng).unwrap();
        assert_ne!(a, b, "randomized-only: two signatures of one message must differ");
        // the same secret key with a different (wrong) public key hash must not verify
        let mut rng2 = StdRng::seed_from_u64(99);
        let other = crate::generate_keypair(&mut rng2).unwrap();
        assert!(!verify_draft(b"m", enc, &a, &other.public_key).unwrap());
        // and a Round-3 verifier rejects a draft signature: the challenge differs
        assert!(!crate::verify(b"m", &a, &pk).unwrap_or(false));
        // salt is drawn once: it is the signature's nonce field
        let (salt, _) = crate::nist_encoding::decode_signature(&a, LOGN).unwrap();
        assert_eq!(salt.len(), crate::sizes::NONCE_LEN);
    }

    #[test]
    fn context_too_long_is_rejected() {
        let (pk, sk) = keys();
        let mut rng = StdRng::seed_from_u64(4);
        let ctx = [0u8; 256];
        assert!(sign_draft(b"m", MessageEncoding::Pure { context: &ctx }, &sk, &pk, &mut rng).is_err());
    }
}
