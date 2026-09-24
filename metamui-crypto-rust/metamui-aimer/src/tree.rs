//! GGM seed tree for AIMer (spec v260130, Figure 2).
//!
//! A binary tree that expands a single root seed into N party seeds.
//! Revealing log₂N sibling nodes lets the verifier reconstruct all
//! party seeds except one, enabling compact signatures.

use crate::params::AimerParams;
use metamui_shake::Shake128;
use metamui_shake::Shake256;
use alloc::vec;
use alloc::vec::Vec;

/// Number of bits in log₂(N) for N parties.
fn log2(n: usize) -> usize {
    debug_assert!(n.is_power_of_two() && n >= 2);
    n.trailing_zeros() as usize
}

/// H₄: hash function for seed tree expansion (domain prefix 0x04).
///
/// H₄(salt, k, i, node) = SHAKE_λ(0x04 ‖ salt ‖ k ‖ i ‖ node, 2λ)
///
/// Produces two child seeds (each λ bits) from a parent node.
fn h4<P: AimerParams>(salt: &[u8], k: u8, i: u8, node: &[u8]) -> Vec<u8> {
    let output_bytes = 2 * (P::SECURITY_BITS / 8);

    if P::SECURITY_BITS == 128 {
        let mut shake = Shake128::new();
        let _ = shake.update(&[0x04]);
        let _ = shake.update(salt);
        let _ = shake.update(&[k]);
        let _ = shake.update(&[i]);
        let _ = shake.update(node);
        let mut reader = shake.finalize_xof();
        reader.read(output_bytes)
    } else {
        let mut shake = Shake256::new();
        let _ = shake.update(&[0x04]);
        let _ = shake.update(salt);
        let _ = shake.update(&[k]);
        let _ = shake.update(&[i]);
        let _ = shake.update(node);
        let mut reader = shake.finalize_xof();
        reader.read(output_bytes)
    }
}

/// Expand a root seed into a full GGM tree of 2N-1 nodes.
///
/// Spec: ExpandTree(salt, k, seed) — Figure 2.
///
/// Returns all 2N-1 nodes. Party i's seed is `nodes[N-1+i]`.
pub fn expand_tree<P: AimerParams>(
    salt: &[u8],
    k: u8,
    seed: &[u8],
) -> Vec<Vec<u8>> {
    let n = P::MPC_PARTIES;
    let seed_size = P::SECURITY_BITS / 8;
    let total = 2 * n - 1;

    let mut nodes: Vec<Vec<u8>> = vec![vec![0u8; seed_size]; total];
    nodes[0] = seed[..seed_size].to_vec();

    for i in 0..(n - 1) {
        // Spec §4.1.3 Fig. 2: H₄ third arg is the 1-indexed node index (1..N-1)
        let children = h4::<P>(salt, k, (i + 1) as u8, &nodes[i]);
        nodes[2 * i + 1] = children[..seed_size].to_vec();
        nodes[2 * i + 2] = children[seed_size..].to_vec();
    }

    nodes
}

/// Extract log₂N sibling nodes to reveal all parties except one.
///
/// Spec: RevealAllBut(nodes, ī) — Figure 2.
///
/// Returns a path of log₂N seeds that allows reconstructing all
/// party seeds except party `excluded`.
pub fn reveal_all_but<P: AimerParams>(
    nodes: &[Vec<u8>],
    excluded: usize,
) -> Vec<Vec<u8>> {
    let n = P::MPC_PARTIES;
    let log_n = log2(n);

    let mut path = Vec::with_capacity(log_n);
    let mut j = n + excluded; // 1-indexed leaf position

    for _d in 0..log_n {
        // j is 1-indexed. Sibling = j⊕1. Convert to 0-indexed for array access.
        let sibling_0idx = (j ^ 1) - 1;
        path.push(nodes[sibling_0idx].clone());
        j /= 2; // 1-indexed parent
    }

    path
}

/// Reconstruct N party seeds from log₂N sibling nodes.
///
/// Spec: ReconstructTree(salt, path, k, ī) — Figure 2.
///
/// The excluded party's seed is returned as all zeros.
/// Returns only the N leaf seeds (party seeds), not all 2N-1 nodes.
pub fn reconstruct_tree<P: AimerParams>(
    salt: &[u8],
    path: &[Vec<u8>],
    k: u8,
    excluded: usize,
) -> Vec<Vec<u8>> {
    let n = P::MPC_PARTIES;
    let seed_size = P::SECURITY_BITS / 8;
    let log_n = log2(n);
    let total = 2 * n - 1;

    let mut nodes: Vec<Vec<u8>> = vec![vec![0u8; seed_size]; total];

    // Determine 1-indexed sibling positions at each tree level.
    // path[0] = leaf-level sibling, path[log_n-1] = root-level sibling.
    let mut j_1idx = n + excluded; // 1-indexed leaf
    let mut sib_1idx_by_depth = Vec::with_capacity(log_n);
    for _ in 0..log_n {
        sib_1idx_by_depth.push(j_1idx ^ 1);
        j_1idx /= 2;
    }

    // Place siblings and expand subtrees TOP-DOWN (root toward leaves).
    // The subtrees are disjoint (each is on the opposite side of the
    // excluded path), so top-down expansion is safe.
    for d in (0..log_n).rev() {
        let sib_0idx = sib_1idx_by_depth[d] - 1;
        nodes[sib_0idx] = path[d].clone();
        expand_subtree::<P>(&mut nodes, sib_0idx, salt, k, n);
    }

    nodes[n - 1..].to_vec()
}

/// Recursively expand a subtree rooted at `root` (0-indexed).
fn expand_subtree<P: AimerParams>(
    nodes: &mut [Vec<u8>],
    root: usize,
    salt: &[u8],
    k: u8,
    n: usize,
) {
    if root >= n - 1 {
        return; // leaf node — nothing to expand
    }
    let seed_size = P::SECURITY_BITS / 8;
    // 1-indexed node index to match spec §4.1.3 Fig. 2
    let children = h4::<P>(salt, k, (root + 1) as u8, &nodes[root]);
    nodes[2 * root + 1] = children[..seed_size].to_vec();
    nodes[2 * root + 2] = children[seed_size..].to_vec();
    expand_subtree::<P>(nodes, 2 * root + 1, salt, k, n);
    expand_subtree::<P>(nodes, 2 * root + 2, salt, k, n);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Aim2erI;

    #[test]
    fn test_expand_and_reveal_roundtrip() {
        let salt = vec![0x42u8; 16];
        let seed = vec![0x13u8; 16];

        let nodes = expand_tree::<Aim2erI>(&salt, 0, &seed);
        assert_eq!(nodes.len(), 2 * 256 - 1);

        // Party seeds are leaves: nodes[255..511]
        let party_seeds: Vec<_> = nodes[255..].to_vec();
        assert_eq!(party_seeds.len(), 256);

        // All party seeds should be non-zero (overwhelmingly likely)
        for (i, seed) in party_seeds.iter().enumerate() {
            assert!(!seed.iter().all(|&b| b == 0), "party {} seed is zero", i);
        }

        // Test RevealAllBut + ReconstructTree roundtrip for several parties
        for excluded in [0, 1, 127, 255] {
            let path = reveal_all_but::<Aim2erI>(&nodes, excluded);
            assert_eq!(path.len(), 8); // log₂(256) = 8

            let reconstructed = reconstruct_tree::<Aim2erI>(&salt, &path, 0, excluded);
            assert_eq!(reconstructed.len(), 256);

            // All parties except excluded should match
            for i in 0..256 {
                if i == excluded {
                    // Excluded party's seed should be zeros
                    assert!(
                        reconstructed[i].iter().all(|&b| b == 0),
                        "excluded party {} should be zeros",
                        i
                    );
                } else {
                    assert_eq!(
                        reconstructed[i], party_seeds[i],
                        "party {} seed mismatch",
                        i
                    );
                }
            }
        }
    }

    #[test]
    fn test_tree_deterministic() {
        let salt = vec![0xAAu8; 16];
        let seed = vec![0xBBu8; 16];

        let nodes1 = expand_tree::<Aim2erI>(&salt, 3, &seed);
        let nodes2 = expand_tree::<Aim2erI>(&salt, 3, &seed);
        assert_eq!(nodes1, nodes2);
    }

    #[test]
    fn test_different_round_different_tree() {
        let salt = vec![0xAAu8; 16];
        let seed = vec![0xBBu8; 16];

        let nodes_k0 = expand_tree::<Aim2erI>(&salt, 0, &seed);
        let nodes_k1 = expand_tree::<Aim2erI>(&salt, 1, &seed);
        assert_ne!(nodes_k0[255], nodes_k1[255]); // party 0 seeds differ
    }
}
