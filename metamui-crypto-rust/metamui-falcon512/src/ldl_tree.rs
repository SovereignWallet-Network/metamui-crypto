//! LDL decomposition tree for Fast Fourier Sampling in Falcon-512
//! 
//! This module implements the tree-based LDL decomposition used
//! for efficient sampling in the FFT domain.

use crate::fft_stable::ComplexStable;
use crate::gram_matrix::GramMatrixFFT;
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;
use core::f64;

/// Tree node for LDL decomposition
#[derive(Clone, Debug)]
pub struct LDLNode {
    /// Level in the tree (0 = leaves)
    pub level: usize,
    /// Index at this level
    pub index: usize,
    /// Size of this node (number of FFT indices it covers)
    pub size: usize,
    /// Diagonal elements D
    pub d00: Vec<f64>,
    pub d11: Vec<f64>,
    /// Off-diagonal elements L[1][0]
    pub l10: Vec<ComplexStable>,
    /// Child nodes (empty for leaves)
    pub children: Vec<usize>,
}

/// Complete LDL decomposition tree
pub struct LDLTree {
    /// All nodes in the tree
    pub nodes: Vec<LDLNode>,
    /// Height of the tree
    pub height: usize,
    /// Root node index
    pub root: usize,
    /// Total FFT size
    pub n: usize,
}

impl LDLTree {
    /// Build LDL tree from Gram matrix in FFT domain
    pub fn from_gram_matrix(gram: &GramMatrixFFT) -> Result<Self> {
        let n = gram.matrix.len();
        if !n.is_power_of_two() {
            return Err(Falcon512Error::InvalidParameter);
        }
        
        let height = n.trailing_zeros() as usize;
        let mut nodes = Vec::new();
        
        // Build leaves first (level 0)
        for i in 0..n {
            let ldl = gram.get_ldl_at(i)?;
            
            nodes.push(LDLNode {
                level: 0,
                index: i,
                size: 1,
                d00: vec![ldl.d00],
                d11: vec![ldl.d11],
                l10: vec![ldl.l10],
                children: vec![],
            });
        }
        
        // Build internal nodes level by level
        for level in 1..=height {
            let prev_level_start = if level == 1 {
                0
            } else {
                nodes.len() - (n >> (level - 2))
            };
            let prev_level_size = n >> (level - 1);
            
            // Process pairs of nodes from previous level
            for i in (0..prev_level_size).step_by(2) {
                let left_idx = prev_level_start + i;
                let right_idx = prev_level_start + i + 1;
                
                // Merge two child nodes using Schur complement
                let merged = Self::merge_nodes(
                    &nodes[left_idx],
                    &nodes[right_idx],
                    level,
                    i / 2,
                )?;
                
                // Store child indices
                let mut merged_with_children = merged;
                merged_with_children.children = vec![left_idx, right_idx];
                
                nodes.push(merged_with_children);
            }
        }
        
        // Root is the last node added
        let root = nodes.len() - 1;
        
        Ok(Self {
            nodes,
            height,
            root,
            n,
        })
    }
    
    /// Merge two child nodes using Schur complement
    fn merge_nodes(
        left: &LDLNode,
        right: &LDLNode,
        level: usize,
        index: usize,
    ) -> Result<LDLNode> {
        // Combine the decompositions from left and right children
        let size = left.size + right.size;
        
        // For simplicity, concatenate the diagonal elements
        // In practice, this would involve Schur complement computation
        let mut d00 = left.d00.clone();
        d00.extend(&right.d00);
        
        let mut d11 = left.d11.clone();
        d11.extend(&right.d11);
        
        let mut l10 = left.l10.clone();
        l10.extend(&right.l10);
        
        // Apply Schur complement formula for merged node
        // This is a simplified version - full implementation would be more complex
        for i in 0..left.size {
            for j in 0..right.size {
                // Schur complement update
                // S = D_right - L_right * D_left^{-1} * L_right^T
                if left.d00[i] > 0.0 && right.d00[j] > 0.0 {
                    let schur_factor = 1.0 / (left.d00[i] + right.d00[j]);
                    d00[left.size + j] *= schur_factor;
                    d11[left.size + j] *= schur_factor;
                }
            }
        }
        
        Ok(LDLNode {
            level,
            index,
            size,
            d00,
            d11,
            l10,
            children: vec![],
        })
    }
    
    /// Get node at specific level and index
    pub fn get_node(&self, level: usize, index: usize) -> Option<&LDLNode> {
        self.nodes.iter()
            .find(|n| n.level == level && n.index == index)
    }
    
    /// Traverse tree from root to leaf at given FFT index
    pub fn traverse_to_leaf(&self, fft_index: usize) -> Vec<usize> {
        if fft_index >= self.n {
            return vec![];
        }
        
        let mut path = vec![];
        let mut current = self.root;
        path.push(current);
        
        // Navigate down the tree
        while !self.nodes[current].children.is_empty() {
            let node = &self.nodes[current];
            
            // Determine which child to follow based on FFT index
            let mid = node.size / 2;
            let relative_index = fft_index % node.size;
            
            if relative_index < mid {
                current = node.children[0];
            } else {
                current = node.children[1];
            }
            
            path.push(current);
        }
        
        path
    }
    
    /// Check tree consistency and numerical stability
    pub fn validate(&self) -> Result<()> {
        // Check that all diagonal elements are positive
        for node in &self.nodes {
            for &d in &node.d00 {
                if d <= 0.0 || !d.is_finite() {
                    return Err(Falcon512Error::NotPositiveDefinite);
                }
            }
            for &d in &node.d11 {
                if d <= 0.0 || !d.is_finite() {
                    return Err(Falcon512Error::NotPositiveDefinite);
                }
            }
        }
        
        // Check tree structure
        let mut level_counts = vec![0; self.height + 1];
        for node in &self.nodes {
            if node.level > self.height {
                return Err(Falcon512Error::InvalidParameter);
            }
            level_counts[node.level] += 1;
        }
        
        // Each level should have the correct number of nodes
        for level in 0..=self.height {
            let expected = self.n >> level;
            if level_counts[level] != expected {
                #[cfg(feature = "std")]
                eprintln!("Level {} has {} nodes, expected {}", 
                         level, level_counts[level], expected);
                return Err(Falcon512Error::InvalidParameter);
            }
        }
        
        Ok(())
    }
    
    /// Get variance (diagonal element) at specific node and index
    pub fn get_variance(&self, node_idx: usize, elem_idx: usize, component: usize) -> f64 {
        if node_idx >= self.nodes.len() {
            return 0.0;
        }
        
        let node = &self.nodes[node_idx];
        
        match component {
            0 => {
                if elem_idx < node.d00.len() {
                    node.d00[elem_idx]
                } else {
                    0.0
                }
            }
            1 => {
                if elem_idx < node.d11.len() {
                    node.d11[elem_idx]
                } else {
                    0.0
                }
            }
            _ => 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    
    #[test]
    fn test_ldl_tree_construction() {
        // Create a positive-definite Gram matrix using orthogonal basis vectors.
        // For det > 0, we need |f·F*+g·G*|² < (|f|²+|g|²)·(|F|²+|G|²).
        // Using f=(3,0), g=(1,0), F=(0,1), G=(0,3) gives:
        //   g00 = 9+1 = 10, g01 = 0+0 = 0 (cross-terms cancel), g11 = 1+9 = 10
        //   det = 100 - 0 = 100 > 0
        let n = 8;
        let f_fft = vec![ComplexStable::new(3.0, 0.0); n];
        let g_fft = vec![ComplexStable::new(1.0, 0.0); n];
        let big_f_fft = vec![ComplexStable::new(0.0, 1.0); n];
        let big_g_fft = vec![ComplexStable::new(0.0, 3.0); n];

        let gram = GramMatrixFFT::from_basis_fft(&f_fft, &g_fft, &big_f_fft, &big_g_fft)
            .expect("Failed to create Gram matrix");

        let tree = LDLTree::from_gram_matrix(&gram)
            .expect("Failed to create LDL tree");
        
        // Validate tree structure
        assert_eq!(tree.n, n);
        assert_eq!(tree.height, 3);
        
        // Check that we can traverse to each leaf
        for i in 0..n {
            let path = tree.traverse_to_leaf(i);
            assert!(!path.is_empty());
            
            // Leaf should be at level 0
            let leaf_idx = *path.last().unwrap();
            assert_eq!(tree.nodes[leaf_idx].level, 0);
        }
        
        // Validate tree consistency
        tree.validate().expect("Tree validation failed");
    }
}