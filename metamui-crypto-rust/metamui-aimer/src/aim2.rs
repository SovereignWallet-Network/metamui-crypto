//! AIM2 one-way function (AIMer v2.0/v2.1 — KPQC winner)
//!
//! AIM2 is a two-layer tweakable one-way function with parallel inverse Mersenne
//! S-boxes in layer 1 and a single forward Mersenne S-box in layer 2.
//!
//! Structure:
//!   AIM2(iv, pt):
//!     1. (A_1, ..., A_l, b_iv) = XOF(iv)      // key-dependent affine layer
//!     2. t_* = b_iv
//!     3. for j = 1..l:
//!          t_j = Mer[e_j]^{-1}(pt + gamma_j)   // inverse Mersenne S-box
//!          t_* += A_j * t_j                      // linear combination
//!     4. ct = Mer[e_*](t_*) + pt                // forward S-box + feed-forward
//!     return ct
//!
//! Key differences from AIM v1:
//! - Parallel (not serial) S-boxes in layer 1
//! - Layer-1 S-boxes use INVERSE Mersenne maps
//! - Affine layer is key-dependent (generated from iv)
//! - Distinct constants (gamma) break common-input structure
//! - Feed-forward XOR with plaintext

use crate::{params::AimerParams, error::AimerError, field};
use metamui_shake::Shake128;
use metamui_shake::Shake256;
use alloc::vec;
use alloc::vec::Vec;

/// AIM2 one-way function
pub struct Aim2<P: AimerParams> {
    pub field_size: usize,
    _phantom: core::marker::PhantomData<P>,
}

impl<P: AimerParams> Aim2<P> {
    /// Create a new AIM2 instance
    pub fn new() -> Self {
        Self {
            field_size: P::FIELD_SIZE,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Evaluate the AIM2 function: ct = AIM2(iv, pt)
    ///
    /// - `iv`: initialization vector (used to generate the key-dependent affine layer)
    /// - `pt`: plaintext (the secret key in the AIMer signature scheme)
    pub fn evaluate(&self, iv: &[u8], pt: &[u8]) -> Result<Vec<u8>, AimerError> {
        if iv.len() != self.field_size || pt.len() != self.field_size {
            return Err(AimerError::InvalidInputSize);
        }

        let l = P::AIM2_NUM_SBOXES;
        assert_eq!(P::AIM2_LAYER1_EXPONENTS.len(), l);
        assert_eq!(P::AIM2_GAMMA.len(), l * self.field_size);

        // Step 1: Generate affine layer from iv via SHAKE256 XOF
        // Produces l matrices (A_1, ..., A_l) each n×n over GF(2), plus bias b_iv
        let (matrices, b_iv) = self.generate_affine_layer(iv);

        // Step 2: t_star = b_iv
        let mut t_star = b_iv;

        // Step 3: Layer 1 — parallel inverse Mersenne S-boxes
        for j in 0..l {
            // Extract gamma_j
            let gamma_start = j * self.field_size;
            let gamma_j = &P::AIM2_GAMMA[gamma_start..gamma_start + self.field_size];

            // Compute sbox_input = pt + gamma_j (XOR in GF(2^n))
            let sbox_input = field::gf_add_alloc(pt, gamma_j);

            // Apply inverse Mersenne S-box: t_j = Mer[e_j]^{-1}(sbox_input)
            let e_j = P::AIM2_LAYER1_EXPONENTS[j];
            let t_j = field::gf_power_mersenne_inverse(&sbox_input, e_j, self.field_size);

            // Accumulate: t_star += A_j * t_j
            let a_j_times_t_j = field::binary_matrix_mul(&matrices[j], &t_j, self.field_size);
            let mut new_t_star = vec![0u8; self.field_size];
            field::gf_add(&t_star, &a_j_times_t_j, &mut new_t_star);
            t_star = new_t_star;
        }

        // Step 4: Layer 2 — forward Mersenne S-box + feed-forward
        let e_star = P::AIM2_LAYER2_EXPONENT;
        let mer_result = field::gf_power_mersenne(&t_star, e_star, self.field_size);

        // ct = Mer[e_*](t_*) + pt
        let mut ct = vec![0u8; self.field_size];
        field::gf_add(&mer_result, pt, &mut ct);

        Ok(ct)
    }

    /// Generate key-dependent affine layer (A_1, ..., A_l, b_iv) from iv.
    ///
    /// Spec: AIM2_GenerateLinear(iv) — Figure 3 of AIMer spec v260130.
    ///
    /// 1. tape ← SHAKE_λ(iv, ℓn² + n) — no domain separator
    /// 2. For each S-box j, build L_j (lower-triangular, 1s on diagonal) and
    ///    U_j (upper-triangular, 1s on diagonal) from consecutive tape bits.
    ///    Set A_j = L_j · U_j (guaranteed invertible: det = 1 over GF(2)).
    /// 3. Bias vector b from remaining n tape bits.
    /// Public accessor for signing/verification to obtain the affine layer.
    pub fn generate_affine_layer_public(&self, iv: &[u8]) -> (Vec<Vec<Vec<u8>>>, Vec<u8>) {
        self.generate_affine_layer(iv)
    }

    fn generate_affine_layer(&self, iv: &[u8]) -> (Vec<Vec<Vec<u8>>>, Vec<u8>) {
        let l = P::AIM2_NUM_SBOXES;
        let n = self.field_size * 8; // n bits = field size in bits
        let n_bytes = self.field_size;

        // Step 1: tape ← SHAKE_λ(iv, ℓn² + n)
        // Use SHAKE128 for λ=128, SHAKE256 for λ=192,256 (spec Section 4.1.2)
        let tape_bits = l * n * n + n;
        let tape_bytes_needed = (tape_bits + 7) / 8;

        let tape = if P::SECURITY_BITS == 128 {
            let mut shake = Shake128::new();
            let _ = shake.update(iv);
            let mut reader = shake.finalize_xof();
            reader.read(tape_bytes_needed)
        } else {
            let mut shake = Shake256::new();
            let _ = shake.update(iv);
            let mut reader = shake.finalize_xof();
            reader.read(tape_bytes_needed)
        };

        // Helper: access bit at position `pos` from tape (LSB-first within bytes)
        let get_bit = |pos: usize| -> u8 {
            (tape[pos / 8] >> (pos % 8)) & 1
        };

        // Step 2: For each S-box j, build A_j = L_j · U_j via LU decomposition
        let mut matrices = Vec::with_capacity(l);

        for j in 0..l {
            // Build U (upper-triangular, 1s on diagonal) row-major: n rows × n_bytes each
            let mut u_rows: Vec<Vec<u8>> = vec![vec![0u8; n_bytes]; n];
            for r in 0..n {
                // Diagonal entry: U[r][r] = 1
                u_rows[r][r / 8] |= 1 << (r % 8);
                // Upper triangle: U[r][c] for c > r
                // Reference uses column-major indexing: bit = j*n² + c*n + r
                for c in (r + 1)..n {
                    if get_bit(j * n * n + c * n + r) == 1 {
                        u_rows[r][c / 8] |= 1 << (c % 8);
                    }
                }
            }

            // Compute A = L · U row by row (without materializing L)
            // A_row[r] = U_row[r] ⊕ (⊕ over k < r where L[r][k]==1 of U_row[k])
            // Because L[r][r] = 1 (diagonal), A_row[r] starts as U_row[r].
            // L[r][k] for k < r: reference uses column-major bit = j*n² + k*n + r.
            let mut a_rows: Vec<Vec<u8>> = Vec::with_capacity(n);
            for r in 0..n {
                let mut a_row = u_rows[r].clone();
                for k in 0..r {
                    if get_bit(j * n * n + k * n + r) == 1 {
                        // XOR U_row[k] into a_row
                        for b in 0..n_bytes {
                            a_row[b] ^= u_rows[k][b];
                        }
                    }
                }
                a_rows.push(a_row);
            }

            matrices.push(a_rows);
        }

        // Step 3: Bias vector b[r] = tape_bit(ℓ·n² + r) for r in [n]
        let mut b_iv = vec![0u8; n_bytes];
        for r in 0..n {
            if get_bit(l * n * n + r) == 1 {
                b_iv[r / 8] |= 1 << (r % 8);
            }
        }

        (matrices, b_iv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{Aim2erI, Aim2erIII, Aim2erV};

    #[test]
    fn test_aim2_evaluate_deterministic() {
        let aim2 = Aim2::<Aim2erI>::new();
        let pt = vec![0x42u8; 16];
        let iv = vec![0x13u8; 16];

        let ct1 = aim2.evaluate(&iv, &pt).unwrap();
        let ct2 = aim2.evaluate(&iv, &pt).unwrap();
        assert_eq!(ct1, ct2, "AIM2 should be deterministic");
    }

    #[test]
    fn test_aim2_different_inputs() {
        let aim2 = Aim2::<Aim2erI>::new();
        let iv = vec![0u8; 16];
        let pt1 = vec![1u8; 16];
        let pt2 = vec![2u8; 16];

        let ct1 = aim2.evaluate(&iv, &pt1).unwrap();
        let ct2 = aim2.evaluate(&iv, &pt2).unwrap();
        assert_ne!(ct1, ct2, "Different inputs should produce different outputs");
    }

    #[test]
    fn test_aim2_different_ivs() {
        let aim2 = Aim2::<Aim2erI>::new();
        let pt = vec![0x42u8; 16];
        let iv1 = vec![1u8; 16];
        let iv2 = vec![2u8; 16];

        let ct1 = aim2.evaluate(&iv1, &pt).unwrap();
        let ct2 = aim2.evaluate(&iv2, &pt).unwrap();
        assert_ne!(ct1, ct2, "Different IVs should produce different outputs");
    }

    #[test]
    fn test_aim2_invalid_input_size() {
        let aim2 = Aim2::<Aim2erI>::new();
        let short = vec![0u8; 8];
        let iv = vec![0u8; 16];
        assert!(aim2.evaluate(&iv, &short).is_err());
    }

    #[test]
    fn test_aim2_l3_evaluate() {
        let aim2 = Aim2::<Aim2erIII>::new();
        let pt = vec![0x42u8; 24];
        let iv = vec![0x13u8; 24];
        let ct = aim2.evaluate(&iv, &pt).unwrap();
        assert_eq!(ct.len(), 24);
    }

    #[test]
    fn test_aim2_l5_evaluate() {
        let aim2 = Aim2::<Aim2erV>::new();
        let pt = vec![0x42u8; 32];
        let iv = vec![0x13u8; 32];
        let ct = aim2.evaluate(&iv, &pt).unwrap();
        assert_eq!(ct.len(), 32);
    }

    #[test]
    fn test_aim2_one_wayness_property() {
        // ct should not equal pt (overwhelmingly likely for random inputs)
        let aim2 = Aim2::<Aim2erI>::new();
        let pt = vec![0x42u8; 16];
        let iv = vec![0x13u8; 16];
        let ct = aim2.evaluate(&iv, &pt).unwrap();
        assert_ne!(ct, pt, "AIM2 output should differ from input");
    }
}
