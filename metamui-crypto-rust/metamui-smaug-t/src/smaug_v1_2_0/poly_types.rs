// SPDX-License-Identifier: MIT
//
// Polynomial and matrix types for SMAUG-T v1.2.0.
// Mirrors `include/poly.h` typedefs.

use super::params::N;

/// `poly` — polynomial of degree N=256 with i16 coefficients.
#[derive(Clone)]
pub struct Poly {
    pub coeffs: [i16; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0i16; N] }
    }
}

impl Poly {
    pub fn zero() -> Self { Self::default() }
}

/// `polyvec` — vector of k polynomials. k varies with mode (2/3/4), so
/// the underlying storage is a `Vec<Poly>`. The C `polyvec` is
/// `poly vec[SMAUGT_K]` — a fixed-size array determined by `-DSMAUGT_CONFIG_MODE`.
#[derive(Clone)]
pub struct PolyVec {
    pub vec: Vec<Poly>,
}

impl PolyVec {
    pub fn new(k: usize) -> Self {
        Self { vec: (0..k).map(|_| Poly::zero()).collect() }
    }
}

/// `polyvec[SMAUGT_K]` — square matrix of polynomials, dimension k × k.
/// Modeled as `Vec<PolyVec>` (row major: `A[i].vec[j]`).
pub type Matrix = Vec<PolyVec>;

/// `public_key` — (seed, A, b). The C reference stores both the seed and
/// the derived matrix A in memory; we keep A as a cache here too.
#[derive(Clone)]
pub struct PublicKey {
    pub seed: [u8; super::params::PKSEED_BYTES],
    pub a: Matrix,
    pub b: PolyVec,
}

impl PublicKey {
    pub fn new(k: usize) -> Self {
        Self {
            seed: [0u8; super::params::PKSEED_BYTES],
            a: (0..k).map(|_| PolyVec::new(k)).collect(),
            b: PolyVec::new(k),
        }
    }
}

/// `secret_key` — vector of k sparse-ternary polynomials (s_0, …, s_{k-1}).
pub type SecretKey = PolyVec;

/// `ciphertext` — (c1, c2) where c1 is a polyvec and c2 is a poly.
#[derive(Clone)]
pub struct Ciphertext {
    pub c1: PolyVec,
    pub c2: Poly,
}

impl Ciphertext {
    pub fn new(k: usize) -> Self {
        Self {
            c1: PolyVec::new(k),
            c2: Poly::zero(),
        }
    }
}
