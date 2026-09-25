//! SLH-DSA signing implementation
//!
//! This module implements the complete signing algorithm for SLH-DSA,
//! combining FORS and the hypertree to create signatures.

use crate::{Parameters, address::Address, hash::Hash, fors, hypertree, Error, Result};
use rand_core::{CryptoRng, RngCore};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

pub use metamui_prehash_oids::PreHashAlgorithm;


/// Core signing implementation (FIPS 205 Algorithm 19 — `slh_sign_internal`).
///
/// Operates on the already-constructed message input `M'` and the explicit
/// randomizer `opt_rand`. Every signing function in this crate builds its
/// message format and then delegates here. The crate-public name is
/// `slh_sign_core` below, compiled only with `kat-internal`.
pub(crate) fn sign_core<P: Parameters>(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    m_prime: &[u8],
    opt_rand: &[u8],
) -> Result<Vec<u8>> {
    let mut sig = Vec::with_capacity(P::SIG_BYTES);

    // Compute R = PRF_msg(SK.prf, opt_rand, M') per FIPS 205 Algorithm 19 line 3
    let mut r = vec![0u8; P::N];
    Hash::<P>::prf_msg(&mut r, sk_prf, opt_rand, m_prime);

    // Add R to signature
    sig.extend_from_slice(&r);

    // Compute message digest using R and M'
    let (md, idx_tree, idx_leaf) = compute_digest_and_index::<P>(
        &r,
        pk_seed,
        pk_root,
        m_prime,
    );

    // Sign with FORS
    let mut fors_addr = Address::new();
    fors_addr.set_tree(idx_tree as u128);
    fors_addr.set_type_fors_tree();
    fors_addr.set_keypair(idx_leaf);

    let fors_sig_len = P::K * (P::A + 1) * P::N;
    let mut fors_sig = vec![0u8; fors_sig_len];
    let fors_pk = fors::fors_sign::<P>(
        &mut fors_sig,
        &md,
        sk_seed,
        pk_seed,
        &fors_addr,
    );

    sig.extend_from_slice(&fors_sig);

    // Sign with hypertree using FORS public key
    let ht_sig_len = hypertree::hypertree_sig_len::<P>();
    let mut ht_sig = vec![0u8; ht_sig_len];
    hypertree::hypertree_sign::<P>(
        &mut ht_sig,
        &fors_pk,
        sk_seed,
        pk_seed,
        idx_tree as u128,
        idx_leaf,
    );

    sig.extend_from_slice(&ht_sig);

    Ok(sig)
}

/// FIPS 205 Algorithm 19 over an already-built `M'` with an explicit
/// randomizer `opt_rand`. ACVP sigGen drives every interface / pre-hash /
/// deterministic-vs-hedged combination through it with the answer file's
/// `additionalRandomness`.
///
/// Test-only: compiled with the `kat-internal` feature (see the crate docs).
/// An application signs with `slh_sign`, `slh_sign_deterministic` or
/// `SigningKey::sign`, which choose the randomizer themselves.
#[cfg(feature = "kat-internal")]
pub fn slh_sign_core<P: Parameters>(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    m_prime: &[u8],
    opt_rand: &[u8],
) -> Result<Vec<u8>> {
    sign_core::<P>(sk_seed, sk_prf, pk_seed, pk_root, m_prime, opt_rand)
}

/// Sign a message using SLH-DSA (FIPS 205 Algorithm 22 - pure/external interface)
///
/// Builds M' = 0x00 || len(ctx) || ctx || msg, then delegates to core.
pub fn slh_sign<P: Parameters, R>(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    rng: Option<&mut R>,
    context: &[u8],
) -> Result<Vec<u8>>
where
    R: RngCore + CryptoRng + ?Sized,
{
    // Validate input sizes
    if sk_seed.len() != P::N || sk_prf.len() != P::N ||
       pk_seed.len() != P::N || pk_root.len() != P::N {
        return Err(Error::InvalidKeySize);
    }

    if context.len() > crate::MAX_CONTEXT_BYTES {
        return Err(Error::ContextTooLong);
    }

    // Build M' = 0x00 || len(ctx) || ctx || msg per FIPS 205 Algorithm 22
    let mut m_prime = Vec::with_capacity(1 + 1 + context.len() + msg.len());
    m_prime.push(0x00);
    m_prime.push(context.len() as u8);
    m_prime.extend_from_slice(context);
    m_prime.extend_from_slice(msg);

    // Generate randomizer (opt_rand) per FIPS 205 Algorithm 19
    // Deterministic: opt_rand = pk_seed; Randomized: opt_rand = random(n)
    let mut opt_rand = pk_seed.to_vec();
    if let Some(rng) = rng {
        rng.fill_bytes(&mut opt_rand);
    }

    sign_core::<P>(sk_seed, sk_prf, pk_seed, pk_root, &m_prime, &opt_rand)
}

/// Sign a message using SLH-DSA internal interface (FIPS 205 Algorithm 19)
///
/// No M' preprocessing - the message is passed directly to PRF_msg and H_msg.
/// Used by ACVP "internal" signature interface tests.
///
/// Test-only: compiled with the `kat-internal` feature (see the crate docs).
#[cfg(feature = "kat-internal")]
pub fn slh_sign_internal<P: Parameters>(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    opt_rand: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if sk_seed.len() != P::N || sk_prf.len() != P::N ||
       pk_seed.len() != P::N || pk_root.len() != P::N {
        return Err(Error::InvalidKeySize);
    }

    let rand = opt_rand.unwrap_or(pk_seed);
    sign_core::<P>(sk_seed, sk_prf, pk_seed, pk_root, msg, rand)
}

/// Sign a message using HashSLH-DSA (FIPS 205 Algorithm 24 - preHash interface)
///
/// Builds M' = 0x01 || len(ctx) || ctx || OID || PH(msg), then delegates to core.
pub fn slh_hash_sign_deterministic<P: Parameters>(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    context: &[u8],
    hash_alg: PreHashAlgorithm,
) -> Result<Vec<u8>> {
    if sk_seed.len() != P::N || sk_prf.len() != P::N ||
       pk_seed.len() != P::N || pk_root.len() != P::N {
        return Err(Error::InvalidKeySize);
    }

    let oid = hash_alg.oid();
    let ph = hash_alg.hash(msg);

    if context.len() > crate::MAX_CONTEXT_BYTES {
        return Err(Error::ContextTooLong);
    }

    // M' = 0x01 || len(ctx) || ctx || OID || PH(msg)
    let mut m_prime = Vec::with_capacity(1 + 1 + context.len() + oid.len() + ph.len());
    m_prime.push(0x01);
    m_prime.push(context.len() as u8);
    m_prime.extend_from_slice(context);
    m_prime.extend_from_slice(oid);
    m_prime.extend_from_slice(&ph);

    // Deterministic: opt_rand = pk_seed
    sign_core::<P>(sk_seed, sk_prf, pk_seed, pk_root, &m_prime, pk_seed)
}

/// Compute message digest and extract tree/leaf indices per FIPS 205 Algorithm 19 lines 5-10
fn compute_digest_and_index<P: Parameters>(
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    m_prime: &[u8],
) -> (Vec<u8>, u64, u32) {
    // Digest layout: md || tmp_idx_tree || tmp_idx_leaf
    let md_len = (P::K * P::A + 7) / 8;
    let tree_idx_len = (P::H - P::H / P::D + 7) / 8;
    let leaf_idx_len = (P::H + 8 * P::D - 1) / (8 * P::D);
    let digest_len = md_len + tree_idx_len + leaf_idx_len;

    let mut digest = vec![0u8; digest_len];
    Hash::<P>::h_msg(&mut digest, r, pk_seed, pk_root, m_prime);

    // Extract md (FORS message)
    let md = digest[..md_len].to_vec();

    // Extract idx_tree = toInt(tmp_idx_tree) mod 2^(h - h/d)
    let tree_bits = P::H - P::H / P::D;
    let tmp_idx_tree = &digest[md_len..md_len + tree_idx_len];
    let mut idx_tree: u64 = 0;
    for &b in tmp_idx_tree {
        idx_tree = (idx_tree << 8) | (b as u64);
    }
    if tree_bits < 64 {
        idx_tree &= (1u64 << tree_bits) - 1;
    }

    // Extract idx_leaf = toInt(tmp_idx_leaf) mod 2^(h/d)
    let leaf_bits = P::H / P::D;
    let tmp_idx_leaf = &digest[md_len + tree_idx_len..md_len + tree_idx_len + leaf_idx_len];
    let mut idx_leaf: u64 = 0;
    for &b in tmp_idx_leaf {
        idx_leaf = (idx_leaf << 8) | (b as u64);
    }
    if leaf_bits < 64 {
        idx_leaf &= (1u64 << leaf_bits) - 1;
    }

    (md, idx_tree, idx_leaf as u32)
}

/// Deterministic signing (without randomization)
pub fn slh_sign_deterministic<P: Parameters>(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    context: &[u8],
) -> Result<Vec<u8>> {
    // Use a dummy RNG type for deterministic signing (None case)
    struct DummyRng;
    impl RngCore for DummyRng {
        fn next_u32(&mut self) -> u32 { 0 }
        fn next_u64(&mut self) -> u64 { 0 }
        fn fill_bytes(&mut self, _dest: &mut [u8]) {}
        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> { Ok(()) }
    }
    impl CryptoRng for DummyRng {}

    slh_sign::<P, DummyRng>(sk_seed, sk_prf, pk_seed, pk_root, msg, None, context)
}

/// Randomized signing
pub fn slh_sign_randomized<P: Parameters, R: RngCore + CryptoRng>(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    rng: &mut R,
    context: &[u8],
) -> Result<Vec<u8>> {
    slh_sign::<P, R>(sk_seed, sk_prf, pk_seed, pk_root, msg, Some(rng), context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SlhDsa128s;
    
    #[test]
    fn test_signature_size() {
        type P = SlhDsa128s;

        let sk_seed = vec![0x01; P::N];
        let sk_prf = vec![0x02; P::N];
        let pk_seed = vec![0x03; P::N];
        let pk_root = vec![0x04; P::N];
        let msg = b"Test message";

        let sig = slh_sign_deterministic::<P>(
            &sk_seed,
            &sk_prf,
            &pk_seed,
            &pk_root,
            msg,
            &[],
        ).unwrap();

        // Verify FIPS 205 compliant signature size
        assert_eq!(sig.len(), P::SIG_BYTES,
                   "FIPS 205 SLH-DSA-128s signature size: expected {} bytes, got {} bytes",
                   P::SIG_BYTES, sig.len());
    }

    #[test]
    fn test_deterministic_signing() {
        type P = SlhDsa128s;

        let sk_seed = vec![0x01; P::N];
        let sk_prf = vec![0x02; P::N];
        let pk_seed = vec![0x03; P::N];
        let pk_root = vec![0x04; P::N];
        let msg = b"Test message";

        // Two deterministic signatures should be identical
        let sig1 = slh_sign_deterministic::<P>(
            &sk_seed,
            &sk_prf,
            &pk_seed,
            &pk_root,
            msg,
            &[],
        ).unwrap();

        let sig2 = slh_sign_deterministic::<P>(
            &sk_seed,
            &sk_prf,
            &pk_seed,
            &pk_root,
            msg,
            &[],
        ).unwrap();

        assert_eq!(sig1, sig2);
    }
}