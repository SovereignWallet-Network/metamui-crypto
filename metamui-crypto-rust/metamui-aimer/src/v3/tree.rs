//! Seed trees (`tree.c` upstream). Nodes are stored in heap order with the
//! root at tree index 1; `expand_tree` keeps `nodes[i] = node i+1`, the
//! verifier's `reconstruct_tree` keeps `nodes[i] = node i+2` (no root).

use super::hash::{Hash, PREFIX_4};
use super::params::AimerV3Params;
use alloc::vec;
use alloc::vec::Vec;

/// Both children of `parent` (node `index` of repetition `rep`), `2·FB` bytes.
///
/// Hidden from the documentation: exposed for a [`super::backend`] crate.
#[doc(hidden)]
pub fn children<P: AimerV3Params>(salt: &[u8], rep: usize, index: usize, parent: &[u8]) -> Vec<u8> {
    let mut h = Hash::with_prefix::<P>(PREFIX_4);
    h.update(salt);
    h.update(&[rep as u8]);
    h.update(&[index as u8]);
    h.update(parent);
    h.finalize().squeeze(2 * P::FB)
}

/// All `2N − 1` nodes of repetition `rep`'s tree from its root seed.
pub fn expand_tree<P: AimerV3Params>(salt: &[u8], rep: usize, seed: &[u8]) -> Vec<Vec<u8>> {
    let mut nodes = vec![vec![0u8; P::FB]; 2 * P::N - 1];
    nodes[0].copy_from_slice(seed);
    for node in 1..P::N {
        let out = children::<P>(salt, rep, node, &nodes[node - 1]);
        nodes[2 * node - 1].copy_from_slice(&out[..P::FB]);
        nodes[2 * node].copy_from_slice(&out[P::FB..]);
    }
    nodes
}

/// The `LOGN` sibling seeds that reveal every leaf except `cover_index`.
pub fn reveal_all_but<P: AimerV3Params>(nodes: &[Vec<u8>], cover_index: usize) -> Vec<Vec<u8>> {
    let mut path = Vec::with_capacity(P::LOGN);
    let mut index = cover_index + P::N;
    for _ in 0..P::LOGN {
        path.push(nodes[(index ^ 1) - 1].clone());
        index >>= 1;
    }
    path
}

/// Rebuild the `2N − 2` non-root nodes from a reveal path; the nodes on the
/// path to `cover_index` (including its leaf) are left as zeros and must not
/// be read.
pub fn reconstruct_tree<P: AimerV3Params>(
    salt: &[u8],
    reveal_path: &[Vec<u8>],
    rep: usize,
    cover_index: usize,
) -> Vec<Vec<u8>> {
    let mut nodes = vec![vec![0u8; P::FB]; 2 * P::N - 2];
    let mut depth = 1;
    while depth < P::LOGN {
        let path = ((cover_index + P::N) >> (P::LOGN - depth)) ^ 1;
        nodes[path - 2].copy_from_slice(&reveal_path[P::LOGN - depth]);
        for index in (1usize << depth)..(2usize << depth) {
            let out = children::<P>(salt, rep, index, &nodes[index - 2]);
            nodes[2 * index - 2].copy_from_slice(&out[..P::FB]);
            nodes[2 * index - 1].copy_from_slice(&out[P::FB..]);
        }
        depth += 1;
    }
    let path = ((cover_index + P::N) >> (P::LOGN - depth)) ^ 1;
    nodes[path - 2].copy_from_slice(&reveal_path[P::LOGN - depth]);
    nodes
}
