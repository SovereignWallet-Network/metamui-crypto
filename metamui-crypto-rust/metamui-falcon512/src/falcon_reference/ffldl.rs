//! Fast Fourier LDL Decomposition
//! 
//! Based on the Python reference implementation from https://github.com/tprest/falcon.py
//! Implements algorithms 8 (LDL*) and 9 (ffLDL) from Falcon documentation

use crate::error::{Result, Falcon512Error};
use crate::fft::FFTComplex;
use alloc::vec::Vec;

/// LDL decomposition node in the tree
#[derive(Clone, Debug)]
pub struct LDLNode {
    /// L matrix element (only L[1][0] is stored as others are 0 or 1)
    pub l10: Vec<FFTComplex>,
    /// D matrix diagonal elements
    pub d00: Vec<FFTComplex>,
    pub d11: Vec<FFTComplex>,
}

/// Compute Gram matrix G = B * B^T in FFT domain
/// B is a 2x2 matrix where each element is a polynomial in FFT form
pub fn gram_fft(b: &[[Vec<FFTComplex>; 2]; 2]) -> [[Vec<FFTComplex>; 2]; 2] {
    let n = b[0][0].len();
    let mut g = [[vec![FFTComplex::zero(); n], vec![FFTComplex::zero(); n]],
                 [vec![FFTComplex::zero(); n], vec![FFTComplex::zero(); n]]];
    
    // G[i][j] = sum_k B[i][k] * conj(B[j][k])
    for i in 0..2 {
        for j in 0..2 {
            for idx in 0..n {
                // G[i][j] = B[i][0] * conj(B[j][0]) + B[i][1] * conj(B[j][1])
                g[i][j][idx] = b[i][0][idx].mul(&b[j][0][idx].conj())
                             .add(&b[i][1][idx].mul(&b[j][1][idx].conj()));
            }
        }
    }
    
    g
}

/// Compute LDL decomposition of a 2x2 Gram matrix in FFT domain
/// Returns (L, D) where G = L * D * L^T
pub fn ldl_fft(g: &[[Vec<FFTComplex>; 2]; 2]) -> Result<LDLNode> {
    let n = g[0][0].len();
    
    // D[0][0] = G[0][0]
    let d00 = g[0][0].clone();
    
    // L[1][0] = G[1][0] / G[0][0]
    let mut l10 = vec![FFTComplex::zero(); n];
    for i in 0..n {
        if g[0][0][i].norm_sqr() < 1e-10 {
            return Err(Falcon512Error::InvalidParameter);
        }
        l10[i] = g[1][0][i].div(&g[0][0][i]);
    }
    
    // D[1][1] = G[1][1] - L[1][0] * conj(L[1][0]) * G[0][0]
    let mut d11 = vec![FFTComplex::zero(); n];
    for i in 0..n {
        d11[i] = g[1][1][i].sub(&l10[i].mul(&l10[i].conj()).mul(&g[0][0][i]));
    }
    
    Ok(LDLNode { l10, d00, d11 })
}

/// Split FFT representation for recursive decomposition
/// Takes n FFT coefficients and splits them into two sets of n/2
pub fn split_fft(v: &[FFTComplex]) -> (Vec<FFTComplex>, Vec<FFTComplex>) {
    let n = v.len();
    let hn = n / 2;
    
    let mut v0 = vec![FFTComplex::zero(); hn];
    let mut v1 = vec![FFTComplex::zero(); hn];
    
    for i in 0..hn {
        // Split according to FFT structure
        // v0[i] = (v[i] + v[i + hn]) / 2
        // v1[i] = (v[i] - v[i + hn]) / 2
        v0[i] = v[i].add(&v[i + hn]).mul(&FFTComplex::new(0.5, 0.0));
        v1[i] = v[i].sub(&v[i + hn]).mul(&FFTComplex::new(0.5, 0.0));
    }
    
    (v0, v1)
}

/// Merge two FFT representations back together
pub fn merge_fft(v0: &[FFTComplex], v1: &[FFTComplex]) -> Vec<FFTComplex> {
    let hn = v0.len();
    let n = hn * 2;
    let mut v = vec![FFTComplex::zero(); n];
    
    for i in 0..hn {
        v[i] = v0[i].add(&v1[i]);
        v[i + hn] = v0[i].sub(&v1[i]);
    }
    
    v
}

/// FFT adjoint (complex conjugate)
pub fn adj_fft(v: &[FFTComplex]) -> Vec<FFTComplex> {
    v.iter().map(|&c| c.conj()).collect()
}

/// Build the ffLDL decomposition tree
pub enum FFLDLTree {
    /// Leaf node (n = 1 in FFT domain)
    Leaf {
        l10: Vec<FFTComplex>,  // Should have 1 element
        d00: Vec<FFTComplex>,  // Should have 1 element
        d11: Vec<FFTComplex>,  // Should have 1 element
    },
    /// Internal node
    Node {
        l10: Vec<FFTComplex>,
        left: Box<FFLDLTree>,
        right: Box<FFLDLTree>,
    },
}

/// Compute the ffLDL decomposition tree of G
/// This corresponds to algorithm 9 of Falcon's documentation
pub fn ffldl_fft(g: &[[Vec<FFTComplex>; 2]; 2]) -> Result<FFLDLTree> {
    let n = g[0][0].len();
    
    // Compute LDL decomposition at this level
    let ldl = ldl_fft(g)?;
    
    if n == 1 {
        // Base case: we're at a leaf
        return Ok(FFLDLTree::Leaf {
            l10: ldl.l10,
            d00: ldl.d00,
            d11: ldl.d11,
        });
    }
    
    // Split D matrix elements for recursion
    let (d00_0, d00_1) = split_fft(&ldl.d00);
    let (d11_0, d11_1) = split_fft(&ldl.d11);
    
    // Create new Gram matrices for left and right subtrees
    // G0 = [[d00_0, d00_1], [conj(d00_1), d00_0]]
    let g0 = [
        [d00_0.clone(), d00_1.clone()],
        [adj_fft(&d00_1), d00_0],
    ];
    
    // G1 = [[d11_0, d11_1], [conj(d11_1), d11_0]]
    let g1 = [
        [d11_0.clone(), d11_1.clone()],
        [adj_fft(&d11_1), d11_0],
    ];
    
    // Recursively decompose
    let left = Box::new(ffldl_fft(&g0)?);
    let right = Box::new(ffldl_fft(&g1)?);
    
    Ok(FFLDLTree::Node {
        l10: ldl.l10,
        left,
        right,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_split_merge_fft() {
        let v = vec![
            FFTComplex::new(1.0, 0.0),
            FFTComplex::new(2.0, 0.0),
            FFTComplex::new(3.0, 0.0),
            FFTComplex::new(4.0, 0.0),
        ];
        
        let (v0, v1) = split_fft(&v);
        let v_reconstructed = merge_fft(&v0, &v1);
        
        for i in 0..v.len() {
            assert!(v[i].sub(&v_reconstructed[i]).norm_sqr() < 1e-10);
        }
    }
    
    #[test]
    fn test_gram_matrix() {
        // Simple 2x2 matrix test
        let b = [
            [vec![FFTComplex::new(1.0, 0.0)], vec![FFTComplex::new(0.0, 0.0)]],
            [vec![FFTComplex::new(0.0, 0.0)], vec![FFTComplex::new(1.0, 0.0)]],
        ];
        
        let g = gram_fft(&b);
        
        // For identity matrix, Gram matrix should also be identity
        assert!(g[0][0][0].sub(&FFTComplex::new(1.0, 0.0)).norm_sqr() < 1e-10);
        assert!(g[0][1][0].norm_sqr() < 1e-10);
        assert!(g[1][0][0].norm_sqr() < 1e-10);
        assert!(g[1][1][0].sub(&FFTComplex::new(1.0, 0.0)).norm_sqr() < 1e-10);
    }
}