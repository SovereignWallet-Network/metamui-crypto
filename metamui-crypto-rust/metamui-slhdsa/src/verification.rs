//! SLH-DSA verification implementation
//!
//! This module implements the complete verification algorithm for SLH-DSA,
//! verifying FORS and hypertree signatures.

use crate::{Parameters, address::Address, hash::Hash, fors, hypertree, Error, Result};
use crate::signing::PreHashAlgorithm;
use subtle::ConstantTimeEq;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// Core verification logic (FIPS 205 Algorithm 20)
///
/// Operates on the already-constructed m_prime. All public verification
/// functions build their message format and then delegate to this core.
fn slh_verify_core<P: Parameters>(
    pk_seed: &[u8],
    pk_root: &[u8],
    m_prime: &[u8],
    sig: &[u8],
) -> Result<()> {
    let mut sig_pos = 0;

    // Extract randomizer from signature
    let r = &sig[sig_pos..sig_pos + P::N];
    sig_pos += P::N;

    // Compute message digest and extract indices
    let (md, idx_tree, idx_leaf) = compute_digest_and_index::<P>(r, pk_seed, pk_root, m_prime);

    // Extract and verify FORS signature
    let mut fors_addr = Address::new();
    fors_addr.set_tree(idx_tree as u128);
    fors_addr.set_type_fors_tree();
    fors_addr.set_keypair(idx_leaf);

    let fors_sig_len = P::K * (P::A + 1) * P::N;
    let fors_sig = &sig[sig_pos..sig_pos + fors_sig_len];
    sig_pos += fors_sig_len;

    let fors_pk = fors::fors_pk_from_sig::<P>(
        fors_sig,
        &md,
        pk_seed,
        &fors_addr,
    );

    // Extract and verify hypertree signature
    let ht_sig = &sig[sig_pos..];

    let computed_root = hypertree::hypertree_verify::<P>(
        ht_sig,
        &fors_pk,
        pk_seed,
        idx_tree as u128,
        idx_leaf,
    );

    // Verify that computed root matches public key root
    if computed_root.ct_eq(pk_root).unwrap_u8() != 1 {
        return Err(Error::VerificationFailed);
    }

    Ok(())
}

/// Verify an SLH-DSA signature (FIPS 205 Algorithm 24 - pure/external interface)
///
/// Builds M' = 0x00 || len(ctx) || ctx || msg, then delegates to core.
pub fn slh_verify<P: Parameters>(
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    context: &[u8],
    sig: &[u8],
) -> Result<()> {
    // Validate input sizes
    if pk_seed.len() != P::N || pk_root.len() != P::N {
        return Err(Error::InvalidKeySize);
    }

    if sig.len() != P::SIG_BYTES {
        return Err(Error::InvalidSignatureSize);
    }

    if context.len() > crate::MAX_CONTEXT_BYTES {
        return Err(Error::ContextTooLong);
    }

    // Build M' = 0x00 || len(ctx) || ctx || msg per FIPS 205 Algorithm 24
    let mut m_prime = Vec::with_capacity(1 + 1 + context.len() + msg.len());
    m_prime.push(0x00);
    m_prime.push(context.len() as u8);
    m_prime.extend_from_slice(context);
    m_prime.extend_from_slice(msg);

    slh_verify_core::<P>(pk_seed, pk_root, &m_prime, sig)
}

/// Verify an SLH-DSA signature using the internal interface (FIPS 205 Algorithm 20)
///
/// No M' preprocessing — the message is passed directly as m_prime.
/// Used by ACVP "internal" signature verification tests.
pub fn slh_verify_internal<P: Parameters>(
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<()> {
    if pk_seed.len() != P::N || pk_root.len() != P::N {
        return Err(Error::InvalidKeySize);
    }

    if sig.len() != P::SIG_BYTES {
        return Err(Error::InvalidSignatureSize);
    }

    slh_verify_core::<P>(pk_seed, pk_root, msg, sig)
}

/// Verify a HashSLH-DSA signature (FIPS 205 Algorithm 24 - preHash interface)
///
/// Builds M' = 0x01 || len(ctx) || ctx || OID || PH(msg), then delegates to core.
pub fn slh_hash_verify<P: Parameters>(
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    context: &[u8],
    sig: &[u8],
    hash_alg: PreHashAlgorithm,
) -> Result<()> {
    if pk_seed.len() != P::N || pk_root.len() != P::N {
        return Err(Error::InvalidKeySize);
    }

    if sig.len() != P::SIG_BYTES {
        return Err(Error::InvalidSignatureSize);
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

    slh_verify_core::<P>(pk_seed, pk_root, &m_prime, sig)
}

/// Compute message digest and extract tree/leaf indices per FIPS 205 Algorithm 20 lines 8-13
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

/// Batch verification of multiple signatures (optional optimization)
pub fn slh_verify_batch<P: Parameters>(
    pk_seeds: &[&[u8]],
    pk_roots: &[&[u8]],
    messages: &[&[u8]],
    signatures: &[&[u8]],
) -> Result<Vec<bool>> {
    if pk_seeds.len() != pk_roots.len() ||
       pk_seeds.len() != messages.len() ||
       pk_seeds.len() != signatures.len() {
        return Err(Error::InvalidParameters);
    }

    let mut results = Vec::with_capacity(pk_seeds.len());

    for i in 0..pk_seeds.len() {
        let valid = slh_verify::<P>(
            pk_seeds[i],
            pk_roots[i],
            messages[i],
            &[],
            signatures[i],
        ).is_ok();
        results.push(valid);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypertree::hypertree_root;
    use crate::params::SlhDsa128s;
    use crate::signing;
    
    #[test]
    fn test_verify_valid_signature() {
        type P = SlhDsa128s;

        let sk_seed = vec![0x01; P::N];
        let sk_prf = vec![0x02; P::N];
        let pk_seed = vec![0x03; P::N];
        let pk_root = hypertree_root::<P>(&sk_seed, &pk_seed);
        let msg = b"Test message";

        // Generate signature
        let sig = signing::slh_sign_deterministic::<P>(
            &sk_seed,
            &sk_prf,
            &pk_seed,
            &pk_root,
            msg,
            &[],
        ).unwrap();

        // Verify signature
        let result = slh_verify::<P>(&pk_seed, &pk_root, msg, &[], &sig);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        type P = SlhDsa128s;

        let pk_seed = vec![0x03; P::N];
        let pk_root = vec![0x04; P::N];
        let msg = b"Test message";

        // Create invalid signature (wrong size)
        let sig = vec![0u8; P::SIG_BYTES - 1];

        let result = slh_verify::<P>(&pk_seed, &pk_root, msg, &[], &sig);
        assert_eq!(result, Err(Error::InvalidSignatureSize));
    }

    #[test]
    fn test_batch_verification() {
        type P = SlhDsa128s;

        let sk_seed = vec![0x01; P::N];
        let sk_prf = vec![0x02; P::N];
        let pk_seed = vec![0x03; P::N];
        let pk_root = vec![0x04; P::N];

        let msg1 = b"Message 1";
        let msg2 = b"Message 2";

        let sig1 = signing::slh_sign_deterministic::<P>(
            &sk_seed,
            &sk_prf,
            &pk_seed,
            &pk_root,
            msg1,
            &[],
        ).unwrap();

        let sig2 = signing::slh_sign_deterministic::<P>(
            &sk_seed,
            &sk_prf,
            &pk_seed,
            &pk_root,
            msg2,
            &[],
        ).unwrap();

        let results = slh_verify_batch::<P>(
            &[&pk_seed, &pk_seed],
            &[&pk_root, &pk_root],
            &[msg1, msg2],
            &[&sig1, &sig2],
        ).unwrap();

        assert_eq!(results.len(), 2);
    }
}
