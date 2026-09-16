//! Hybrid FFT LDL Decomposition with selectable precision
//! 
//! Uses emulated floating-point for critical operations to ensure
//! numerical stability in the LDL decomposition.

use crate::error::{Result, Falcon512Error};
use crate::fft_hybrid::{HybridComplex, FFTMode};
use crate::falcon_fpr::FPR;
use alloc::vec::Vec;

/// Hybrid LDL decomposition tree node
#[derive(Clone, Debug)]
pub enum HybridFFLDLTree {
    /// Leaf node (n = 1 in FFT domain)
    Leaf {
        l10: Vec<HybridComplex>,
        d00: Vec<HybridComplex>,
        d11: Vec<HybridComplex>,
    },
    /// Internal node
    Node {
        l10: Vec<HybridComplex>,
        left: Box<HybridFFLDLTree>,
        right: Box<HybridFFLDLTree>,
    },
}

/// Compute Gram matrix G = B * B^T in hybrid FFT domain
pub fn gram_fft_hybrid(
    b: &[[Vec<HybridComplex>; 2]; 2],
    mode: FFTMode,
) -> [[Vec<HybridComplex>; 2]; 2] {
    let n = b[0][0].len();
    let mut g = [[vec![HybridComplex::zero(mode); n], vec![HybridComplex::zero(mode); n]],
                 [vec![HybridComplex::zero(mode); n], vec![HybridComplex::zero(mode); n]]];
    
    // G[i][j] = sum_k B[i][k] * conj(B[j][k])
    for i in 0..2 {
        for j in 0..2 {
            for idx in 0..n {
                // G[i][j] = B[i][0] * conj(B[j][0]) + B[i][1] * conj(B[j][1])
                g[i][j][idx] = b[i][0][idx].mul(b[j][0][idx].conj())
                             .add(b[i][1][idx].mul(b[j][1][idx].conj()));
            }
        }
    }
    
    g
}

/// Compute LDL decomposition with hybrid precision
pub fn ldl_fft_hybrid(
    g: &[[Vec<HybridComplex>; 2]; 2],
    mode: FFTMode,
) -> Result<(Vec<HybridComplex>, Vec<HybridComplex>, Vec<HybridComplex>)> {
    let n = g[0][0].len();
    
    // D[0][0] = G[0][0]
    let d00 = g[0][0].clone();
    
    // L[1][0] = G[1][0] / G[0][0]
    let mut l10 = vec![HybridComplex::zero(mode); n];
    for i in 0..n {
        // Check for near-zero diagonal
        if g[0][0][i].norm_sqr() < 1e-10 {
            return Err(Falcon512Error::InvalidParameter);
        }
        l10[i] = g[1][0][i].div(g[0][0][i]);
    }
    
    // D[1][1] = G[1][1] - L[1][0] * conj(L[1][0]) * G[0][0]
    let mut d11 = vec![HybridComplex::zero(mode); n];
    for i in 0..n {
        d11[i] = g[1][1][i].sub(l10[i].mul(l10[i].conj()).mul(g[0][0][i]));
        
        // Ensure positive definiteness
        let (d11_re, _) = d11[i].to_native();
        if d11_re < 1e-10 {
            // Add small regularization if needed
            d11[i] = HybridComplex::new(1e-8, 0.0, mode);
        }
    }
    
    Ok((l10, d00, d11))
}

/// Build the hybrid ffLDL decomposition tree
pub fn ffldl_fft_hybrid(
    g: &[[Vec<HybridComplex>; 2]; 2],
    mode: FFTMode,
) -> Result<HybridFFLDLTree> {
    let n = g[0][0].len();
    
    // Compute LDL decomposition at this level
    let (l10, d00, d11) = ldl_fft_hybrid(g, mode)?;
    
    if n == 1 {
        // Base case: we're at a leaf
        return Ok(HybridFFLDLTree::Leaf { l10, d00, d11 });
    }
    
    // Split D matrix elements for recursion
    let (d00_0, d00_1) = split_fft_hybrid(&d00);
    let (d11_0, d11_1) = split_fft_hybrid(&d11);
    
    // Create new Gram matrices for left and right subtrees
    let g0 = [
        [d00_0.clone(), d00_1.clone()],
        [adj_fft_hybrid(&d00_1), d00_0],
    ];
    
    let g1 = [
        [d11_0.clone(), d11_1.clone()],
        [adj_fft_hybrid(&d11_1), d11_0],
    ];
    
    // Recursively decompose
    let left = Box::new(ffldl_fft_hybrid(&g0, mode)?);
    let right = Box::new(ffldl_fft_hybrid(&g1, mode)?);
    
    Ok(HybridFFLDLTree::Node { l10, left, right })
}

/// Split FFT representation for recursive decomposition
pub fn split_fft_hybrid(v: &[HybridComplex]) -> (Vec<HybridComplex>, Vec<HybridComplex>) {
    let n = v.len();
    let hn = n / 2;
    
    let mut v0 = Vec::with_capacity(hn);
    let mut v1 = Vec::with_capacity(hn);
    
    for i in 0..hn {
        // v0[i] = (v[i] + v[i + hn]) / 2
        // v1[i] = (v[i] - v[i + hn]) / 2
        let sum = v[i].add(v[i + hn]);
        let diff = v[i].sub(v[i + hn]);
        
        // Divide by 2
        let half = match sum {
            HybridComplex::Native { re, im } => {
                HybridComplex::Native { re: re * 0.5, im: im * 0.5 }
            }
            HybridComplex::Emulated { re, im } => {
                let half_fpr = FPR::from_f64(0.5);
                HybridComplex::Emulated {
                    re: re.mul(half_fpr),
                    im: im.mul(half_fpr),
                }
            }
        };
        
        v0.push(half);
        
        let half_diff = match diff {
            HybridComplex::Native { re, im } => {
                HybridComplex::Native { re: re * 0.5, im: im * 0.5 }
            }
            HybridComplex::Emulated { re, im } => {
                let half_fpr = FPR::from_f64(0.5);
                HybridComplex::Emulated {
                    re: re.mul(half_fpr),
                    im: im.mul(half_fpr),
                }
            }
        };
        
        v1.push(half_diff);
    }
    
    (v0, v1)
}

/// Merge two FFT representations back together
pub fn merge_fft_hybrid(v0: &[HybridComplex], v1: &[HybridComplex]) -> Vec<HybridComplex> {
    let hn = v0.len();
    let n = hn * 2;
    let mut v = Vec::with_capacity(n);
    
    for i in 0..hn {
        v.push(v0[i].add(v1[i]));
    }
    for i in 0..hn {
        v.push(v0[i].sub(v1[i]));
    }
    
    v
}

/// FFT adjoint (complex conjugate)
pub fn adj_fft_hybrid(v: &[HybridComplex]) -> Vec<HybridComplex> {
    v.iter().map(|&c| c.conj()).collect()
}