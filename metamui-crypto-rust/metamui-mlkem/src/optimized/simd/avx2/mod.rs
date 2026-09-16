//! AVX2 SIMD backend for ML-KEM operations
//!
//! This module provides high-performance AVX2 implementations for ML-KEM-768
//! operations achieving 3-5x speedup over scalar implementations.

#![cfg(target_arch = "x86_64")]
#![cfg(feature = "avx2")]

use crate::{Result, Error};
use super::SimdBackend;
use core::arch::x86_64::*;

pub mod ntt;
pub mod poly_ops;
pub mod sampling;

use ntt::{ntt_avx2, inv_ntt_avx2};
use poly_ops::{
    poly_add_avx2, poly_sub_avx2, poly_basemul_avx2,
    poly_barrett_reduce_avx2, poly_montgomery_reduce_avx2,
    poly_compress_avx2, poly_decompress_avx2
};
use sampling::{cbd_eta2_avx2, uniform_sample_avx2};

/// AVX2 backend for ML-KEM operations with 256-bit SIMD
pub struct Avx2Backend;

impl Avx2Backend {
    /// Create new AVX2 backend
    pub fn new() -> Self {
        Self
    }
    
    /// Check if AVX2 is supported at runtime
    #[inline]
    pub fn is_supported() -> bool {
        is_x86_feature_detected!("avx2")
    }
}

impl SimdBackend for Avx2Backend {
    fn name(&self) -> &'static str {
        "avx2"
    }
    
    fn is_available(&self) -> bool {
        Self::is_supported()
    }
    
    #[target_feature(enable = "avx2")]
    unsafe fn ntt(&self, poly: &mut [i16; 256]) -> Result<()> {
        if !Self::is_supported() {
            return Err(Error::BackendNotAvailable);
        }
        ntt_avx2(poly)
    }
    
    #[target_feature(enable = "avx2")]
    unsafe fn inv_ntt(&self, poly: &mut [i16; 256]) -> Result<()> {
        if !Self::is_supported() {
            return Err(Error::BackendNotAvailable);
        }
        inv_ntt_avx2(poly)
    }
    
    #[target_feature(enable = "avx2")]
    unsafe fn poly_basemul(&self, r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
        if !Self::is_supported() {
            return Err(Error::BackendNotAvailable);
        }
        poly_basemul_avx2(r, a, b)
    }
    
    #[target_feature(enable = "avx2")]
    unsafe fn poly_add(&self, r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
        if !Self::is_supported() {
            return Err(Error::BackendNotAvailable);
        }
        poly_add_avx2(r, a, b)
    }
    
    #[target_feature(enable = "avx2")]
    unsafe fn poly_sub(&self, r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
        if !Self::is_supported() {
            return Err(Error::BackendNotAvailable);
        }
        poly_sub_avx2(r, a, b)
    }
    
    #[target_feature(enable = "avx2")]
    unsafe fn poly_barrett_reduce(&self, poly: &mut [i16; 256]) -> Result<()> {
        if !Self::is_supported() {
            return Err(Error::BackendNotAvailable);
        }
        poly_barrett_reduce_avx2(poly)
    }
    
    #[target_feature(enable = "avx2")]
    unsafe fn poly_montgomery_reduce(&self, poly: &mut [i16; 256]) -> Result<()> {
        if !Self::is_supported() {
            return Err(Error::BackendNotAvailable);
        }
        poly_montgomery_reduce_avx2(poly)
    }
    
    #[target_feature(enable = "avx2")]
    unsafe fn cbd_eta2(&self, poly: &mut [i16; 256], buf: &[u8]) -> Result<()> {
        if !Self::is_supported() {
            return Err(Error::BackendNotAvailable);
        }
        cbd_eta2_avx2(poly, buf)
    }
    
    #[target_feature(enable = "avx2")]
    unsafe fn uniform_sample(&self, poly: &mut [i16; 256], seed: &[u8], nonce: u8) -> Result<()> {
        if !Self::is_supported() {
            return Err(Error::BackendNotAvailable);
        }
        uniform_sample_avx2(poly, seed, nonce)
    }
    
    #[target_feature(enable = "avx2")]
    unsafe fn poly_compress(&self, r: &mut [u8], poly: &[i16; 256], bits: usize) -> Result<()> {
        if !Self::is_supported() {
            return Err(Error::BackendNotAvailable);
        }
        poly_compress_avx2(r, poly, bits)
    }
    
    #[target_feature(enable = "avx2")]
    unsafe fn poly_decompress(&self, poly: &mut [i16; 256], a: &[u8], bits: usize) -> Result<()> {
        if !Self::is_supported() {
            return Err(Error::BackendNotAvailable);
        }
        poly_decompress_avx2(poly, a, bits)
    }
}

/// Precomputed constants for AVX2 operations
pub mod constants {
    use super::*;
    
    /// ML-KEM modulus q = 3329
    pub const Q: i16 = 3329;
    pub const Q32: i32 = 3329;
    
    /// Montgomery constant R = 2^16 mod q
    pub const MONT_R: i32 = 2285;
    
    /// Inverse of q modulo 2^16 for Montgomery reduction
    pub const QINV: i16 = -3327; // q^(-1) mod 2^16
    
    /// Barrett constant v = floor(2^26/q)
    pub const BARRETT_V: i32 = 20159;
    
    /// Create AVX2 vector with all lanes set to same value
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn set1_epi16(val: i16) -> __m256i {
        _mm256_set1_epi16(val)
    }
    
    /// Create AVX2 vector with all lanes set to same value (32-bit)
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn set1_epi32(val: i32) -> __m256i {
        _mm256_set1_epi32(val)
    }
    
    /// Load Q as AVX2 vector
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn vq() -> __m256i {
        set1_epi16(Q)
    }
    
    /// Load QINV as AVX2 vector
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn vqinv() -> __m256i {
        set1_epi16(QINV)
    }
    
    /// Load Barrett constant as AVX2 vector
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn vbarrett() -> __m256i {
        set1_epi32(BARRETT_V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_avx2_detection() {
        if is_x86_feature_detected!("avx2") {
            let backend = Avx2Backend::new();
            assert!(backend.is_available());
            assert_eq!(backend.name(), "avx2");
        }
    }
    
    #[test]
    fn test_constants() {
        unsafe {
            if is_x86_feature_detected!("avx2") {
                let q_vec = constants::vq();
                let q_arr = core::mem::transmute::<__m256i, [i16; 16]>(q_vec);
                for val in q_arr {
                    assert_eq!(val, constants::Q);
                }
            }
        }
    }
}