//! Hypertree implementation for SLH-DSA
//!
//! The hypertree is a tree of XMSS trees that enables stateless signing
//! in SLH-DSA. It consists of D layers, each containing multiple XMSS trees.

use crate::{Parameters, address::Address, xmss, wots};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Generate the root of the hypertree
pub fn hypertree_root<P: Parameters>(
    sk_seed: &[u8],
    pk_seed: &[u8],
) -> Vec<u8> {
    let mut addr = Address::new();
    addr.set_layer(P::D as u32 - 1);
    addr.set_tree(0);
    
    xmss::xmss_root::<P>(sk_seed, pk_seed, &addr)
}

/// Sign a message with the hypertree (FIPS 205 Algorithm 12)
pub fn hypertree_sign<P: Parameters>(
    sig: &mut [u8],
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx_tree: u128,
    idx_leaf: u32,
) {
    let mut sig_pos = 0;
    let mut addr = Address::new();
    let mut idx_tree = idx_tree;

    // 2: ADRS.setTreeAddress(idx_tree)
    addr.set_tree(idx_tree);

    let xmss_sig_len = (wots::wots_len::<P>() + P::H_PRIME) * P::N;

    // 3: SIG_tmp ← xmss_sign(M, SK.seed, idx_leaf, PK.seed, ADRS)
    xmss::xmss_sign::<P>(&mut sig[sig_pos..sig_pos + xmss_sig_len], msg, sk_seed, idx_leaf, pk_seed, &addr);
    sig_pos += xmss_sig_len;

    // 5: root ← xmss_PKFromSig(idx_leaf, SIG_tmp, M, PK.seed, ADRS)
    let mut root = xmss::xmss_pk_from_sig::<P>(&sig[sig_pos - xmss_sig_len..sig_pos], msg, idx_leaf, pk_seed, &addr);

    // 6: for j from 1 to d − 1 do
    // Sign each layer of the hypertree (FIPS 205 Algorithm 11)
    // Iteratively peel off H_PRIME bits from idx_tree at each layer
    for j in 1..P::D {
        // 7: idx_leaf ← idx_tree mod 2^{h'} (extract bottom h' bits)
        let idx_leaf = (idx_tree & ((1u128 << P::H_PRIME) - 1)) as u32;

        // 8: idx_tree ← idx_tree >> h' (remove bottom h' bits)
        idx_tree >>= P::H_PRIME;

        // 9: ADRS.setLayerAddress(j)
        addr.set_layer(j as u32);

        // 10: ADRS.setTreeAddress(idx_tree)
        addr.set_tree(idx_tree);

        // 11: SIG_tmp ← xmss_sign(root, SK.seed, idx_leaf, PK.seed, ADRS)
        xmss::xmss_sign::<P>(&mut sig[sig_pos..sig_pos + xmss_sig_len], &root, sk_seed, idx_leaf, pk_seed, &addr);
        sig_pos += xmss_sig_len;

        // 14: root ← xmss_PKFromSig(idx_leaf, SIG_tmp, root, PK.seed, ADRS)
        if j < P::D - 1 {
            root = xmss::xmss_pk_from_sig::<P>(&sig[sig_pos - xmss_sig_len..sig_pos], &root, idx_leaf, pk_seed, &addr);
        }
    }
}

/// Verify a hypertree signature and extract the root (FIPS 205 Algorithm 13)
pub fn hypertree_verify<P: Parameters>(
    sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    mut idx_tree: u128,
    idx_leaf: u32,
) -> Vec<u8> {
    let mut sig_pos = 0;
    let mut addr = Address::new();

    // 2: ADRS.setTreeAddress(idx_tree)
    addr.set_tree(idx_tree);

    let xmss_sig_len = (wots::wots_len::<P>() + P::H_PRIME) * P::N;

    // 4: node ← xmss_PKFromSig(idx_leaf, SIG_tmp, M, PK.seed, ADRS)
    let mut root = xmss::xmss_pk_from_sig::<P>(&sig[sig_pos..sig_pos + xmss_sig_len], msg, idx_leaf, pk_seed, &addr);
    sig_pos += xmss_sig_len;

    // 5: for j from 1 to d − 1 do
    // Verify each layer of the hypertree (FIPS 205 Algorithm 12)
    // Iteratively peel off H_PRIME bits from idx_tree at each layer
    for j in 1..P::D {
        // 6: idx_leaf ← idx_tree mod 2^{h'}
        let idx_leaf = (idx_tree & ((1u128 << P::H_PRIME) - 1)) as u32;

        // 7: idx_tree ← idx_tree >> h'
        idx_tree >>= P::H_PRIME;

        // 8: ADRS.setLayerAddress(j)
        addr.set_layer(j as u32);

        // 9: ADRS.setTreeAddress(idx_tree)
        addr.set_tree(idx_tree);

        // 11: node ← xmss_PKFromSig(idx_leaf, SIG_tmp, node, PK.seed, ADRS)
        root = xmss::xmss_pk_from_sig::<P>(&sig[sig_pos..sig_pos + xmss_sig_len], &root, idx_leaf, pk_seed, &addr);
        sig_pos += xmss_sig_len;
    }

    root
}

/// Compute the size of a hypertree signature in bytes
pub fn hypertree_sig_len<P: Parameters>() -> usize {
    P::D * (wots::wots_len::<P>() + P::H_PRIME) * P::N
}

/// Tree index calculation for hypertree
pub fn tree_index<P: Parameters>(idx: u128, layer: usize) -> u128 {
    let shift_amount = layer * P::H_PRIME;
    if shift_amount < 128 {
        idx >> shift_amount
    } else {
        0
    }
}

/// Leaf index calculation within a tree
pub fn leaf_index<P: Parameters>(idx: u128, layer: usize) -> u32 {
    if layer == 0 {
        return 0;
    }
    let shift_amount = (layer - 1) * P::H_PRIME;
    if shift_amount < 128 {
        ((idx >> shift_amount) as u32) & ((1 << P::H_PRIME) - 1)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SlhDsa128s;
    
    #[test]
    fn test_hypertree_sig_len() {
        type P = SlhDsa128s;
        
        let expected_len = P::D * (wots::wots_len::<P>() + P::H_PRIME) * P::N;
        assert_eq!(hypertree_sig_len::<P>(), expected_len);
    }
    
    #[test]
    fn test_tree_index() {
        type P = SlhDsa128s;

        // With H_PRIME = 9, each layer shifts by 9 bits
        let idx = 0x123456789ABCDEF0u128;

        assert_eq!(tree_index::<P>(idx, 0), idx);
        assert_eq!(tree_index::<P>(idx, 1), 0x91A2B3C4D5E6F);
        assert_eq!(tree_index::<P>(idx, 2), 0x48D159E26AF);
    }

    #[test]
    fn test_leaf_index() {
        type P = SlhDsa128s;

        let idx = 0x123456789ABCDEF0u128;

        // Leaf index extracts H_PRIME=9 bits at the appropriate position
        assert_eq!(leaf_index::<P>(idx, 1), 0xF0);  // 240
        assert_eq!(leaf_index::<P>(idx, 2), 0x6F);  // 111
    }
}