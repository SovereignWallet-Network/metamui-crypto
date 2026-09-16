//! ARM NEON SIMD optimizations for ML-KEM
//!
//! This module provides highly optimized implementations using ARM NEON intrinsics
//! for ARMv8 (aarch64) processors.

#![cfg(target_arch = "aarch64")]

use crate::Result;
use super::SimdBackend;
use std::arch::aarch64::*;

pub mod ntt;
pub mod sampling;
pub mod poly_ops;

/// ARM NEON backend for ML-KEM operations
pub struct NeonBackend {
    /// Runtime detection flag (NEON is always available on AArch64)
    available: bool,
}

impl NeonBackend {
    /// Create new NEON backend
    pub fn new() -> Self {
        Self {
            // NEON is mandatory on AArch64, so always available
            available: true,
        }
    }
    
    /// Check if NEON is available at runtime
    #[inline]
    pub fn detect_features() -> bool {
        // On AArch64, NEON is always available
        // We could check for additional features like crypto extensions
        #[cfg(target_feature = "neon")]
        {
            return true;
        }
        #[cfg(not(target_feature = "neon"))]
        {
            // Runtime detection - NEON is mandatory on AArch64
            std::arch::is_aarch64_feature_detected!("neon")
        }
    }
}

impl SimdBackend for NeonBackend {
    fn name(&self) -> &'static str {
        "neon"
    }
    
    fn is_available(&self) -> bool {
        self.available
    }
    
    fn ntt(&self, poly: &mut [i16; 256]) -> Result<()> {
        unsafe { ntt::neon_ntt(poly) }
    }
    
    fn inv_ntt(&self, poly: &mut [i16; 256]) -> Result<()> {
        unsafe { ntt::neon_inv_ntt(poly) }
    }
    
    fn poly_basemul(&self, r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
        unsafe { poly_ops::neon_basemul(r, a, b) }
    }
    
    fn poly_add(&self, r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
        unsafe { poly_ops::neon_poly_add(r, a, b) }
    }
    
    fn poly_sub(&self, r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()> {
        unsafe { poly_ops::neon_poly_sub(r, a, b) }
    }
    
    fn poly_barrett_reduce(&self, poly: &mut [i16; 256]) -> Result<()> {
        unsafe { poly_ops::neon_barrett_reduce(poly) }
    }
    
    fn poly_montgomery_reduce(&self, poly: &mut [i16; 256]) -> Result<()> {
        unsafe { poly_ops::neon_montgomery_reduce(poly) }
    }
    
    fn cbd_eta2(&self, poly: &mut [i16; 256], buf: &[u8]) -> Result<()> {
        unsafe { sampling::neon_cbd_eta2(poly, buf) }
    }
    
    fn uniform_sample(&self, poly: &mut [i16; 256], seed: &[u8], nonce: u8) -> Result<()> {
        unsafe { sampling::neon_uniform_sample(poly, seed, nonce) }
    }
    
    fn poly_compress(&self, r: &mut [u8], poly: &[i16; 256], bits: usize) -> Result<()> {
        unsafe { poly_ops::neon_poly_compress(r, poly, bits) }
    }
    
    fn poly_decompress(&self, poly: &mut [i16; 256], a: &[u8], bits: usize) -> Result<()> {
        unsafe { poly_ops::neon_poly_decompress(poly, a, bits) }
    }
}

impl Default for NeonBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// NEON-specific constants for ML-KEM
pub mod constants {
    use super::*;
    
    /// ML-KEM modulus Q = 3329
    pub const Q: i16 = 3329;
    pub const QINV: i32 = 3327; // Q^(-1) mod 2^16
    
    /// Montgomery constant 2^16 mod Q
    pub const MONT: i16 = 2285;
    
    /// Barrett reduction constant
    pub const BARRETT_CONST: i32 = 20159; // floor(2^26 / Q)
    
    /// Create NEON vector with all lanes set to same value
    #[inline]
    pub unsafe fn vdup_n_i16(val: i16) -> int16x8_t {
        vdupq_n_s16(val)
    }
    
    /// Create NEON vector with all lanes set to same value (32-bit)
    #[inline]
    pub unsafe fn vdup_n_i32(val: i32) -> int32x4_t {
        vdupq_n_s32(val)
    }
}

/// Utility functions for NEON operations
pub mod utils {
    use super::*;
    
    /// Load 8 i16 values into NEON register
    #[inline(always)]
    pub unsafe fn load_i16x8(ptr: *const i16) -> int16x8_t {
        vld1q_s16(ptr)
    }
    
    /// Store 8 i16 values from NEON register
    #[inline(always)]
    pub unsafe fn store_i16x8(ptr: *mut i16, val: int16x8_t) {
        vst1q_s16(ptr, val);
    }
    
    /// Load 4 i32 values into NEON register
    #[inline(always)]
    pub unsafe fn load_i32x4(ptr: *const i32) -> int32x4_t {
        vld1q_s32(ptr)
    }
    
    /// Store 4 i32 values from NEON register
    #[inline(always)]
    pub unsafe fn store_i32x4(ptr: *mut i32, val: int32x4_t) {
        vst1q_s32(ptr, val);
    }
    
    /// Perform parallel Barrett reduction on 8 values
    #[inline]
    pub unsafe fn barrett_reduce_v8(a: int16x8_t) -> int16x8_t {
        let q = vdupq_n_s16(constants::Q);
        let barrett = vdupq_n_s32(constants::BARRETT_CONST);
        
        // Split into low and high parts
        let a_low = vmovl_s16(vget_low_s16(a));
        let a_high = vmovl_s16(vget_high_s16(a));
        
        // t = (a * BARRETT_CONST) >> 26
        let t_low = vshrq_n_s32(vmulq_s32(a_low, barrett), 26);
        let t_high = vshrq_n_s32(vmulq_s32(a_high, barrett), 26);
        
        // Combine back to 16-bit
        let t = vcombine_s16(vmovn_s32(t_low), vmovn_s32(t_high));
        
        // a - t * q
        vsubq_s16(a, vmulq_s16(t, q))
    }
    
    /// Perform parallel Montgomery reduction on 8 values
    #[inline]
    pub unsafe fn montgomery_reduce_v8(a: int32x4_t, b: int32x4_t) -> int16x8_t {
        let q = vdupq_n_s32(constants::Q as i32);
        let qinv = vdupq_n_s32(constants::QINV);
        
        // t = a * QINV
        let t_low = vmulq_s32(a, qinv);
        let t_high = vmulq_s32(b, qinv);
        
        // t = (t * Q) >> 16
        let u_low = vshrq_n_s32(vmulq_s32(t_low, q), 16);
        let u_high = vshrq_n_s32(vmulq_s32(t_high, q), 16);
        
        // (a - t * Q) >> 16
        let res_low = vshrq_n_s32(vsubq_s32(a, vmulq_s32(t_low, q)), 16);
        let res_high = vshrq_n_s32(vsubq_s32(b, vmulq_s32(t_high, q)), 16);
        
        // Combine results
        vcombine_s16(vmovn_s32(res_low), vmovn_s32(res_high))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_neon_available() {
        let backend = NeonBackend::new();
        assert!(backend.is_available());
        assert_eq!(backend.name(), "neon");
    }
    
    #[test]
    fn test_neon_detection() {
        assert!(NeonBackend::detect_features());
    }
}