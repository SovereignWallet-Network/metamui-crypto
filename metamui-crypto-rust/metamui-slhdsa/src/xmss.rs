//! XMSS (eXtended Merkle Signature Scheme) implementation for SLH-DSA
//!
//! XMSS provides the Merkle tree structure used in the hypertree construction
//! of SLH-DSA. Each XMSS tree uses WOTS+ for signing the tree roots.

use crate::{Parameters, address::Address, hash::Hash, wots};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// Generate a leaf node for XMSS tree
fn xmss_node<P: Parameters>(
    sk_seed: &[u8],
    i: u32,
    z: u32,
    pk_seed: &[u8],
    addr: &Address,
) -> Vec<u8> {
    if z == 0 {
        // Leaf node - generate WOTS+ public key
        let mut wots_addr = *addr;
        wots_addr.set_type_wots();
        wots_addr.set_keypair(i);
        
        wots::wots_gen_pk::<P>(sk_seed, pk_seed, &wots_addr)
    } else {
        // Internal node - compute from children
        let left = xmss_node::<P>(sk_seed, 2 * i, z - 1, pk_seed, addr);
        let right = xmss_node::<P>(sk_seed, 2 * i + 1, z - 1, pk_seed, addr);
        
        let mut tree_addr = *addr;
        tree_addr.set_type_tree();
        tree_addr.set_tree_height(z);
        tree_addr.set_tree_index(i);
        
        let mut out = vec![0u8; P::N];
        Hash::<P>::h(&mut out, pk_seed, &tree_addr, &left, &right);
        out
    }
}

/// Generate an XMSS signature
pub fn xmss_sign<P: Parameters>(
    sig: &mut [u8],
    msg: &[u8],
    sk_seed: &[u8],
    idx: u32,
    pk_seed: &[u8],
    addr: &Address,
) {
    let mut sig_pos = 0;
    
    // Get WOTS+ signature
    let mut wots_addr = *addr;
    wots_addr.set_type_wots();
    wots_addr.set_keypair(idx);
    
    let wots_sig = wots::wots_sign::<P>(msg, sk_seed, pk_seed, &wots_addr);
    let wots_sig_len = wots_sig.len();
    sig[sig_pos..sig_pos + wots_sig_len].copy_from_slice(&wots_sig);
    sig_pos += wots_sig_len;
    
    // Build authentication path
    for j in 0..P::H_PRIME {
        let k = (idx >> j) ^ 1;
        let auth_node = xmss_node::<P>(
            sk_seed,
            k,
            j as u32,
            pk_seed,
            addr,
        );
        sig[sig_pos..sig_pos + P::N].copy_from_slice(&auth_node);
        sig_pos += P::N;
    }
}

/// Extract XMSS public key (root) from signature
pub fn xmss_pk_from_sig<P: Parameters>(
    sig: &[u8],
    msg: &[u8],
    idx: u32,
    pk_seed: &[u8],
    addr: &Address,
) -> Vec<u8> {
    let mut sig_pos = 0;
    
    // Extract WOTS+ public key from signature
    let wots_sig_len = (wots::wots_len::<P>()) * P::N;
    let wots_sig = &sig[sig_pos..sig_pos + wots_sig_len];
    sig_pos += wots_sig_len;
    
    let mut wots_addr = *addr;
    wots_addr.set_type_wots();
    wots_addr.set_keypair(idx);
    
    let mut node = wots::wots_pk_from_sig::<P>(wots_sig, msg, pk_seed, &wots_addr);
    
    // Traverse authentication path to root
    let mut tree_addr = *addr;
    tree_addr.set_type_tree();

    for j in 0..P::H_PRIME {
        // At iteration j, we're hashing two height-j nodes to produce a height-(j+1) node
        tree_addr.set_tree_height((j + 1) as u32);

        let auth = &sig[sig_pos..sig_pos + P::N];
        sig_pos += P::N;

        if ((idx >> j) & 1) == 0 {
            tree_addr.set_tree_index(idx >> (j + 1));
            let mut new_node = vec![0u8; P::N];
            Hash::<P>::h(&mut new_node, pk_seed, &tree_addr, &node, auth);
            node = new_node;
        } else {
            tree_addr.set_tree_index(idx >> (j + 1));
            let mut new_node = vec![0u8; P::N];
            Hash::<P>::h(&mut new_node, pk_seed, &tree_addr, auth, &node);
            node = new_node;
        }
    }
    
    node
}

/// Compute root of an XMSS tree
pub fn xmss_root<P: Parameters>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    addr: &Address,
) -> Vec<u8> {
    xmss_node::<P>(sk_seed, 0, P::H_PRIME as u32, pk_seed, addr)
}

/// Build an authentication path for a given leaf
pub fn xmss_auth_path<P: Parameters>(
    auth: &mut [u8],
    sk_seed: &[u8],
    idx: u32,
    pk_seed: &[u8],
    addr: &Address,
) {
    let mut auth_pos = 0;

    for j in 0..P::H_PRIME {
        let k = (idx >> j) ^ 1;
        let auth_node = xmss_node::<P>(
            sk_seed,
            k,
            j as u32,
            pk_seed,
            addr,
        );
        auth[auth_pos..auth_pos + P::N].copy_from_slice(&auth_node);
        auth_pos += P::N;
    }
}

/// Treehash algorithm for efficient tree computation
pub struct TreeHash<P: Parameters> {
    stack: Vec<(Vec<u8>, u32)>, // (node, height) pairs
    _phantom: core::marker::PhantomData<P>,
}

impl<P: Parameters> TreeHash<P> {
    /// Create a new TreeHash instance
    pub fn new() -> Self {
        TreeHash {
            stack: Vec::new(),
            _phantom: core::marker::PhantomData,
        }
    }
    
    /// Update treehash with a new leaf
    pub fn update(
        &mut self,
        leaf: Vec<u8>,
        leaf_idx: u32,
        pk_seed: &[u8],
        addr: &Address,
    ) {
        let mut node = leaf;
        let mut height = 0u32;
        
        // Find the number of trailing zeros in leaf_idx
        let mut idx = leaf_idx;
        while idx > 0 && (idx & 1) == 0 {
            idx >>= 1;
            height += 1;
        }
        
        // Pop and hash while we can
        while !self.stack.is_empty() && self.stack.last().unwrap().1 == height {
            let (left, _) = self.stack.pop().unwrap();
            
            let mut tree_addr = *addr;
            tree_addr.set_type_tree();
            tree_addr.set_tree_height(height);
            tree_addr.set_tree_index(leaf_idx >> (height + 1));
            
            let mut new_node = vec![0u8; P::N];
            Hash::<P>::h(&mut new_node, pk_seed, &tree_addr, &left, &node);
            node = new_node;
            height += 1;
        }
        
        self.stack.push((node, height));
    }
    
    /// Finalize and get the root
    pub fn finalize(mut self, pk_seed: &[u8], addr: &Address) -> Vec<u8> {
        // Complete any remaining hashing
        while self.stack.len() > 1 {
            let (right, h_right) = self.stack.pop().unwrap();
            let (left, h_left) = self.stack.pop().unwrap();
            
            let height = core::cmp::max(h_left, h_right) + 1;
            
            let mut tree_addr = *addr;
            tree_addr.set_type_tree();
            tree_addr.set_tree_height(height);
            tree_addr.set_tree_index(0);
            
            let mut node = vec![0u8; P::N];
            Hash::<P>::h(&mut node, pk_seed, &tree_addr, &left, &right);
            
            self.stack.push((node, height));
        }
        
        self.stack.pop().map(|(node, _)| node).unwrap_or_else(|| vec![0u8; P::N])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SlhDsa128s;
    
    #[test]
    fn test_xmss_root() {
        type P = SlhDsa128s;
        
        let sk_seed = vec![0x01; P::N];
        let pk_seed = vec![0x02; P::N];
        let addr = Address::new();
        
        let root = xmss_root::<P>(&sk_seed, &pk_seed, &addr);
        assert_eq!(root.len(), P::N);
    }
    
    #[test]
    fn test_treehash() {
        type P = SlhDsa128s;
        
        let pk_seed = vec![0x02; P::N];
        let addr = Address::new();
        
        let mut treehash = TreeHash::<P>::new();
        
        // Add some leaves
        for i in 0..4 {
            let leaf = vec![i as u8; P::N];
            treehash.update(leaf, i, &pk_seed, &addr);
        }
        
        let root = treehash.finalize(&pk_seed, &addr);
        assert_eq!(root.len(), P::N);
    }
}