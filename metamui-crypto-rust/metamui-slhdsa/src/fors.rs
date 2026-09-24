//! FORS (Forest of Random Subsets) implementation for SLH-DSA
//!
//! Implements FIPS 205 Algorithms 14-17.

use crate::{Parameters, address::Address, hash::Hash};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// Algorithm 14: fors_SKgen - Generate a FORS private-key value
fn fors_sk_gen<P: Parameters>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Address,
    idx: u32,
) -> Vec<u8> {
    // 1: skADRS ← ADRS
    let mut sk_adrs = *adrs;

    // 2: skADRS.setTypeAndClear(FORS_PRF)
    sk_adrs.set_type_and_clear(6); // FORS_PRF

    // 3: skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    sk_adrs.set_keypair(adrs.keypair);

    // 4: skADRS.setTreeIndex(idx)
    sk_adrs.set_tree_index(idx);

    // 5: return PRF(PK.seed, SK.seed, skADRS)
    let mut out = vec![0u8; P::N];
    Hash::<P>::prf(&mut out, pk_seed, sk_seed, &sk_adrs);
    out
}

/// Algorithm 15: fors_node - Compute the root of a Merkle subtree of FORS public values
fn fors_node<P: Parameters>(
    sk_seed: &[u8],
    i: u32,
    z: u32,
    pk_seed: &[u8],
    adrs: &Address,
) -> Vec<u8> {
    let mut adrs = *adrs;

    if z == 0 {
        // 2: sk ← fors_SKgen(SK.seed, PK.seed, ADRS, i)
        let sk = fors_sk_gen::<P>(sk_seed, pk_seed, &adrs, i);

        // 3: ADRS.setTreeHeight(0)
        adrs.set_tree_height(0);

        // 4: ADRS.setTreeIndex(i)
        adrs.set_tree_index(i);

        // 5: node ← F(PK.seed, ADRS, sk)
        let mut out = vec![0u8; P::N];
        Hash::<P>::f(&mut out, pk_seed, &adrs, &sk);
        out
    } else {
        // 7: lnode ← fors_node(SK.seed, 2i, z − 1, PK.seed, ADRS)
        let left = fors_node::<P>(sk_seed, 2 * i, z - 1, pk_seed, &adrs);

        // 8: rnode ← fors_node(SK.seed, 2i + 1, z − 1, PK.seed, ADRS)
        let right = fors_node::<P>(sk_seed, 2 * i + 1, z - 1, pk_seed, &adrs);

        // 9: ADRS.setTreeHeight(z)
        adrs.set_tree_height(z);

        // 10: ADRS.setTreeIndex(i)
        adrs.set_tree_index(i);

        // 11: node ← H(PK.seed, ADRS, lnode ∥ rnode)
        let mut out = vec![0u8; P::N];
        Hash::<P>::h(&mut out, pk_seed, &adrs, &left, &right);
        out
    }
}

/// Algorithm 16: fors_sign - Generate a FORS signature
pub fn fors_sign<P: Parameters>(
    sig: &mut [u8],
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Address,
) -> Vec<u8> {
    let mut sig_pos = 0;

    // 2: indices ← base_2b(md, a, k)
    let indices = base_2b::<P>(md);

    // 3: for i from 0 to k − 1 do
    for i in 0..P::K {
        let i32 = i as u32;
        let a32 = P::A as u32;

        // 4: SIG_FORS ← SIG_FORS ∥ fors_SKgen(SK.seed, PK.seed, ADRS, i·2^a + indices[i])
        let sk = fors_sk_gen::<P>(sk_seed, pk_seed, adrs, (i32 << a32) + indices[i]);
        sig[sig_pos..sig_pos + P::N].copy_from_slice(&sk);
        sig_pos += P::N;

        // 5: for j from 0 to a − 1 do
        for j in 0..a32 {
            // 6: s ← indices[i]/2^j xor 1
            let s = (indices[i] >> j) ^ 1;

            // 7: AUTH[j] ← fors_node(SK.seed, i·2^{a−j} + s, j, PK.seed, ADRS)
            let node = fors_node::<P>(
                sk_seed,
                (i32 << (a32 - j)) + s,
                j,
                pk_seed,
                adrs,
            );
            sig[sig_pos..sig_pos + P::N].copy_from_slice(&node);
            sig_pos += P::N;
        }
    }

    // Compute FORS public key: need all roots
    let mut roots = Vec::with_capacity(P::K * P::N);
    for i in 0..P::K {
        let i32 = i as u32;
        let a32 = P::A as u32;
        let root = fors_node::<P>(sk_seed, i32, a32, pk_seed, adrs);
        roots.extend_from_slice(&root);
    }

    // forspkADRS ← ADRS
    let mut fors_pk_adrs = *adrs;

    // forspkADRS.setTypeAndClear(FORS_ROOTS)
    fors_pk_adrs.set_type_and_clear(4); // FORS_ROOTS

    // forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    fors_pk_adrs.set_keypair(adrs.keypair);

    let mut pk = vec![0u8; P::N];
    Hash::<P>::t_l(&mut pk, pk_seed, &fors_pk_adrs, &roots);
    pk
}

/// Algorithm 17: fors_pkFromSig - Compute FORS public key from signature
pub fn fors_pk_from_sig<P: Parameters>(
    sig: &[u8],
    md: &[u8],
    pk_seed: &[u8],
    adrs: &Address,
) -> Vec<u8> {
    let mut adrs = *adrs;
    let mut sig_pos = 0;
    let a32 = P::A as u32;

    // 1: indices ← base_2b(md, a, k)
    let indices = base_2b::<P>(md);

    // 2: for i from 0 to k − 1 do
    let mut roots = Vec::with_capacity(P::K * P::N);
    for i in 0..P::K {
        let i32 = i as u32;

        // 3: sk ← SIG_FORS.getSK(i)
        let sk = &sig[sig_pos..sig_pos + P::N];
        sig_pos += P::N;

        // 4: ADRS.setTreeHeight(0)
        adrs.set_tree_height(0);

        // 5: ADRS.setTreeIndex(i·2^a + indices[i])
        adrs.set_tree_index((i32 << a32) + indices[i]);

        // 6: node[0] ← F(PK.seed, ADRS, sk)
        let mut node = vec![0u8; P::N];
        Hash::<P>::f(&mut node, pk_seed, &adrs, sk);

        // 8: for j from 0 to a − 1 do
        for j in 0..a32 {
            let auth_node = &sig[sig_pos..sig_pos + P::N];
            sig_pos += P::N;

            // 9: ADRS.setTreeHeight(j + 1)
            adrs.set_tree_height(j + 1);

            // 10: if indices[i]/2^j is even then
            if ((indices[i] >> j) & 1) == 0 {
                // 11: ADRS.setTreeIndex(ADRS.getTreeIndex()/2)
                let tmp = adrs.hash_keypair / 2;
                adrs.set_tree_index(tmp);

                // 12: node[1] ← H(PK.seed, ADRS, node[0] ∥ auth[j])
                let mut new_node = vec![0u8; P::N];
                Hash::<P>::h(&mut new_node, pk_seed, &adrs, &node, auth_node);
                node = new_node;
            } else {
                // 14: ADRS.setTreeIndex((ADRS.getTreeIndex() − 1)/2)
                let tmp = (adrs.hash_keypair - 1) / 2;
                adrs.set_tree_index(tmp);

                // 15: node[1] ← H(PK.seed, ADRS, auth[j] ∥ node[0])
                let mut new_node = vec![0u8; P::N];
                Hash::<P>::h(&mut new_node, pk_seed, &adrs, auth_node, &node);
                node = new_node;
            }
        }

        // 19: root[i] ← node[0]
        roots.extend_from_slice(&node);
    }

    // 21: forspkADRS ← ADRS
    let mut fors_pk_adrs = adrs;

    // 22: forspkADRS.setTypeAndClear(FORS_ROOTS)
    fors_pk_adrs.set_type_and_clear(4); // FORS_ROOTS

    // 23: forspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    fors_pk_adrs.set_keypair(adrs.keypair);

    // 24: pk ← Tk(PK.seed, forspkADRS, root)
    let mut pk = vec![0u8; P::N];
    Hash::<P>::t_l(&mut pk, pk_seed, &fors_pk_adrs, &roots);
    pk
}

/// base_2b: Convert byte string to base 2^b representation (FIPS 205 Algorithm 4)
fn base_2b<P: Parameters>(x: &[u8]) -> Vec<u32> {
    let b = P::A as u32;
    let out_len = P::K;
    let mut baseb = Vec::with_capacity(out_len);

    let mut inn = 0usize;
    let mut bits = 0u32;
    let mut total = 0u32;

    for _ in 0..out_len {
        while bits < b {
            if inn < x.len() {
                total = (total << 8) + (x[inn] as u32);
            } else {
                total = total << 8;
            }
            inn += 1;
            bits += 8;
        }
        bits -= b;
        baseb.push((total >> bits) & ((1u32 << b) - 1));
    }

    baseb
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SlhDsa128s;

    #[test]
    fn test_base_2b() {
        type P = SlhDsa128s;

        // For A=12, each index needs 12 bits
        let msg = vec![0xFF; 21];
        let indices = base_2b::<P>(&msg);

        assert_eq!(indices.len(), P::K);
        for idx in indices.iter().take(14) {
            assert_eq!(*idx, (1 << P::A) - 1);
        }
    }

    #[test]
    fn test_base_2b_zeros() {
        type P = SlhDsa128s;

        let msg = vec![0u8; 30];
        let indices = base_2b::<P>(&msg);

        assert_eq!(indices.len(), P::K);
        for idx in indices {
            assert_eq!(idx, 0);
        }
    }

    #[test]
    fn test_fors_node_leaf() {
        type P = SlhDsa128s;

        let sk_seed = vec![0x01; P::N];
        let pk_seed = vec![0x02; P::N];
        let addr = Address::new();

        let leaf = fors_node::<P>(&sk_seed, 0, 0, &pk_seed, &addr);
        assert_eq!(leaf.len(), P::N);
    }
}
