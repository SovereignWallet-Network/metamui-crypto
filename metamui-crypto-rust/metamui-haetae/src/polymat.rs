//! Polynomial matrix operations for HAETAE
//!
//! This module implements matrix operations on polynomial vectors.
//! HAETAE uses two primary matrix types:
//! - K×L matrices (array of K PolyVecL rows)
//! - K×M matrices (array of K PolyVecM rows)
//!
//! Transcopy from: metamui-haetae/src/polymat.c

use crate::params::{K, L, M, N, SEEDBYTES};
use crate::polyvec::{PolyVecK, PolyVecL, PolyVecM};

/// Expand K×L matrix from seed (partial expansion)
///
/// Generates matrix A with uniformly random coefficients by performing
/// rejection sampling on SHAKE128(rho|j|i) for each element.
///
/// **Important**: This only expands the K×M submatrix (columns 1..L),
/// leaving column 0 of each row as zeros. This matches HAETAE's structure
/// where the matrix has a special form.
///
/// # Arguments
/// * `mat` - Output K×L matrix (array of K rows, each is PolyVecL)
/// * `rho` - Seed bytes for matrix expansion
///
/// Transcopy from: void polymatkl_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES])
pub fn polymatkl_expand(mat: &mut [PolyVecL; K], rho: &[u8; SEEDBYTES]) {
    for i in 0..K {
        for j in 0..M {
            // Note: Expands into mat[i].vec[j+1], not mat[i].vec[j]
            // This leaves mat[i].vec[0] as zero
            let nonce = ((i << 8) + j) as u16;
            mat[i].vec[j + 1].uniform(rho, nonce);
        }
    }
}

/// Expand K×M matrix from seed (full expansion)
///
/// Similar to polymatkl_expand but expands all M columns of each row.
///
/// # Arguments
/// * `mat` - Output K×M matrix (array of K rows, each is PolyVecM)
/// * `rho` - Seed bytes for matrix expansion
///
/// Transcopy from: void polymatkm_expand(polyvecm mat[K], const uint8_t rho[SEEDBYTES])
pub fn polymatkm_expand(mat: &mut [PolyVecM; K], rho: &[u8; SEEDBYTES]) {
    for i in 0..K {
        for j in 0..M {
            let nonce = ((i << 8) + j) as u16;
            mat[i].vec[j].uniform(rho, nonce);
        }
    }
}

/// Double the K×M submatrix of K×L matrix
///
/// Multiplies all coefficients in columns 1..L (the K×M submatrix) by 2.
/// Column 0 is left unchanged.
///
/// # Arguments
/// * `mat` - K×L matrix to modify
///
/// Transcopy from: void polymatkl_double(polyvecl mat[K])
pub fn polymatkl_double(mat: &mut [PolyVecL; K]) {
    for i in 0..K {
        for j in 1..L {
            for k in 0..N {
                mat[i].vec[j].coeffs[k] *= 2;
            }
        }
    }
}

/// Matrix-vector multiplication: t = mat * v (K×L matrix)
///
/// Computes matrix-vector product in NTT domain using Montgomery multiplication.
/// For each row i: t[i] = sum(mat[i][j] * v[j]) for j in 0..L
///
/// # Arguments
/// * `t` - Output vector (K polynomials)
/// * `mat` - Input K×L matrix (array of K rows)
/// * `v` - Input vector (L polynomials)
///
/// # Preconditions
/// - Matrix and vector must be in NTT domain
///
/// Transcopy from: void polymatkl_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v)
pub fn polymatkl_pointwise_montgomery(
    t: &mut PolyVecK,
    mat: &[PolyVecL; K],
    v: &PolyVecL
) {
    for i in 0..K {
        // Compute dot product of row i with vector v
        t.vec[i] = mat[i].pointwise_acc_montgomery(v);
    }
}

/// Matrix-vector multiplication: t = mat * v (K×M matrix)
///
/// Similar to polymatkl_pointwise_montgomery but for K×M matrices.
///
/// # Arguments
/// * `t` - Output vector (K polynomials)
/// * `mat` - Input K×M matrix (array of K rows)
/// * `v` - Input vector (M polynomials)
///
/// # Preconditions
/// - Matrix and vector must be in NTT domain
///
/// Transcopy from: void polymatkm_pointwise_montgomery(polyveck *t, const polyvecm mat[K], const polyvecm *v)
pub fn polymatkm_pointwise_montgomery(
    t: &mut PolyVecK,
    mat: &[PolyVecM; K],
    v: &PolyVecM
) {
    for i in 0..K {
        // Compute dot product of row i with vector v
        t.vec[i] = mat[i].pointwise_acc_montgomery(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polymatkl_expand() {
        let seed = [0u8; SEEDBYTES];
        let mut mat: [PolyVecL; K] = core::array::from_fn(|_| PolyVecL::new());

        polymatkl_expand(&mut mat, &seed);

        // Column 0 should remain zero (not expanded)
        for i in 0..K {
            for k in 0..N {
                assert_eq!(mat[i].vec[0].coeffs[k], 0);
            }
        }

        // Columns 1..L should be non-zero (expanded)
        for i in 0..K {
            for j in 1..L {
                let mut has_nonzero = false;
                for k in 0..N {
                    if mat[i].vec[j].coeffs[k] != 0 {
                        has_nonzero = true;
                        break;
                    }
                }
                assert!(has_nonzero, "Row {} col {} should have non-zero coefficients", i, j);
            }
        }
    }

    #[test]
    fn test_polymatkm_expand() {
        let seed = [0u8; SEEDBYTES];
        let mut mat: [PolyVecM; K] = core::array::from_fn(|_| PolyVecM::new());

        polymatkm_expand(&mut mat, &seed);

        // All columns should be non-zero
        for i in 0..K {
            for j in 0..M {
                let mut has_nonzero = false;
                for k in 0..N {
                    if mat[i].vec[j].coeffs[k] != 0 {
                        has_nonzero = true;
                        break;
                    }
                }
                assert!(has_nonzero, "Row {} col {} should have non-zero coefficients", i, j);
            }
        }
    }

    #[test]
    fn test_polymatkl_expand_deterministic() {
        let seed = [42u8; SEEDBYTES];
        let mut mat1: [PolyVecL; K] = core::array::from_fn(|_| PolyVecL::new());
        let mut mat2: [PolyVecL; K] = core::array::from_fn(|_| PolyVecL::new());

        polymatkl_expand(&mut mat1, &seed);
        polymatkl_expand(&mut mat2, &seed);

        // Same seed should produce same matrix
        for i in 0..K {
            for j in 0..L {
                for k in 0..N {
                    assert_eq!(mat1[i].vec[j].coeffs[k], mat2[i].vec[j].coeffs[k]);
                }
            }
        }
    }

    #[test]
    fn test_polymatkl_double() {
        let seed = [0u8; SEEDBYTES];
        let mut mat: [PolyVecL; K] = core::array::from_fn(|_| PolyVecL::new());

        polymatkl_expand(&mut mat, &seed);

        // Save original values from columns 1..L
        let mut original: [PolyVecL; K] = core::array::from_fn(|_| PolyVecL::new());
        for i in 0..K {
            for j in 1..L {
                for k in 0..N {
                    original[i].vec[j].coeffs[k] = mat[i].vec[j].coeffs[k];
                }
            }
        }

        // Double the matrix
        polymatkl_double(&mut mat);

        // Check that columns 1..L are doubled
        for i in 0..K {
            for j in 1..L {
                for k in 0..N {
                    assert_eq!(mat[i].vec[j].coeffs[k], original[i].vec[j].coeffs[k] * 2);
                }
            }
        }

        // Column 0 should still be zero
        for i in 0..K {
            for k in 0..N {
                assert_eq!(mat[i].vec[0].coeffs[k], 0);
            }
        }
    }

    #[test]
    fn test_polymatkl_pointwise_montgomery() {
        use crate::ntt::ntt;

        let seed = [0u8; SEEDBYTES];
        let mut mat: [PolyVecL; K] = core::array::from_fn(|_| PolyVecL::new());
        let mut v = PolyVecL::new();
        let mut t = PolyVecK::new();

        // Expand matrix and vector
        polymatkl_expand(&mut mat, &seed);
        for j in 0..L {
            v.vec[j].uniform(&seed, (1000 + j) as u16);
        }

        // Convert to NTT domain
        for i in 0..K {
            for j in 0..L {
                ntt(&mut mat[i].vec[j].coeffs);
            }
        }
        v.ntt();

        // Compute matrix-vector product
        polymatkl_pointwise_montgomery(&mut t, &mat, &v);

        // Result should be non-zero (sanity check)
        let mut has_nonzero = false;
        for i in 0..K {
            for k in 0..N {
                if t.vec[i].coeffs[k] != 0 {
                    has_nonzero = true;
                    break;
                }
            }
        }
        assert!(has_nonzero, "Matrix-vector product should be non-zero");
    }

    #[test]
    fn test_polymatkm_pointwise_montgomery() {
        let seed = [0u8; SEEDBYTES];
        let mut mat: [PolyVecM; K] = core::array::from_fn(|_| PolyVecM::new());
        let mut v = PolyVecM::new();
        let mut t = PolyVecK::new();

        // Expand matrix and vector
        polymatkm_expand(&mut mat, &seed);
        for j in 0..M {
            v.vec[j].uniform(&seed, (2000 + j) as u16);
        }

        // Convert to NTT domain
        for i in 0..K {
            mat[i].ntt();
        }
        v.ntt();

        // Compute matrix-vector product
        polymatkm_pointwise_montgomery(&mut t, &mat, &v);

        // Result should be non-zero (sanity check)
        let mut has_nonzero = false;
        for i in 0..K {
            for k in 0..N {
                if t.vec[i].coeffs[k] != 0 {
                    has_nonzero = true;
                    break;
                }
            }
        }
        assert!(has_nonzero, "Matrix-vector product should be non-zero");
    }
}
