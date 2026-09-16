//! SIMD optimizations for ML-KEM operations
//!
//! This module provides high-performance SIMD implementations for various
//! ML-KEM operations including NTT, sampling, and polynomial arithmetic.

#![allow(dead_code)]

use crate::Result;

#[cfg(target_arch = "x86_64")]
pub mod avx2;

#[cfg(target_arch = "x86_64")]
pub mod avx512;

#[cfg(target_arch = "aarch64")]
pub mod neon;

pub mod generic;

/// SIMD backend trait for ML-KEM operations
pub trait SimdBackend: Send + Sync {
    /// Backend name
    fn name(&self) -> &'static str;
    
    /// Check if the backend is available on current CPU
    fn is_available(&self) -> bool;
    
    /// Vectorized NTT forward transform
    fn ntt(&self, poly: &mut [i16; 256]) -> Result<()>;
    
    /// Vectorized inverse NTT transform
    fn inv_ntt(&self, poly: &mut [i16; 256]) -> Result<()>;
    
    /// Vectorized polynomial multiplication in NTT domain
    fn poly_basemul(&self, r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()>;
    
    /// Vectorized polynomial addition
    fn poly_add(&self, r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()>;
    
    /// Vectorized polynomial subtraction
    fn poly_sub(&self, r: &mut [i16; 256], a: &[i16; 256], b: &[i16; 256]) -> Result<()>;
    
    /// Vectorized Barrett reduction
    fn poly_barrett_reduce(&self, poly: &mut [i16; 256]) -> Result<()>;
    
    /// Vectorized Montgomery reduction
    fn poly_montgomery_reduce(&self, poly: &mut [i16; 256]) -> Result<()>;
    
    /// Vectorized CBD sampling
    fn cbd_eta2(&self, poly: &mut [i16; 256], buf: &[u8]) -> Result<()>;
    
    /// Vectorized uniform sampling
    fn uniform_sample(&self, poly: &mut [i16; 256], seed: &[u8], nonce: u8) -> Result<()>;
    
    /// Vectorized polynomial compression
    fn poly_compress(&self, r: &mut [u8], poly: &[i16; 256], bits: usize) -> Result<()>;
    
    /// Vectorized polynomial decompression
    fn poly_decompress(&self, poly: &mut [i16; 256], a: &[u8], bits: usize) -> Result<()>;
}

/// SIMD runtime detection and backend selection
pub struct SimdSelector {
    backends: Vec<Box<dyn SimdBackend>>,
}

impl SimdSelector {
    /// Create new SIMD selector with runtime detection
    pub fn new() -> Self {
        let mut backends: Vec<Box<dyn SimdBackend>> = vec![
            Box::new(generic::GenericBackend::new()),
        ];
        
        #[cfg(all(target_arch = "x86_64", feature = "avx2"))]
        {
            if is_x86_feature_detected!("avx2") {
                backends.push(Box::new(avx2::Avx2Backend::new()));
            }
        }
        
        #[cfg(all(target_arch = "x86_64", feature = "avx512"))]
        {
            if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512bw") {
                backends.push(Box::new(avx512::Avx512Backend::new()));
            }
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            // NEON is always available on AArch64
            backends.push(Box::new(neon::NeonBackend::new()));
        }
        
        Self { backends }
    }
    
    /// Select best available backend
    pub fn select_best(&self) -> &dyn SimdBackend {
        // Return the last backend (highest priority)
        self.backends.last().map(|b| b.as_ref()).unwrap()
    }
    
    /// Get all available backends
    pub fn available_backends(&self) -> Vec<&'static str> {
        self.backends.iter()
            .filter(|b| b.is_available())
            .map(|b| b.name())
            .collect()
    }
}

impl Default for SimdSelector {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper functions for SIMD operations
pub mod utils {
    
    
    /// Align data to cache line boundary (64 bytes)
    #[repr(align(64))]
    pub struct AlignedPoly {
        pub data: [i16; 256],
    }
    
    impl Default for AlignedPoly {
        fn default() -> Self {
            Self { data: [0; 256] }
        }
    }
    
    /// Check alignment of data
    #[inline]
    pub fn is_aligned<T>(ptr: *const T, align: usize) -> bool {
        (ptr as usize) & (align - 1) == 0
    }
    
    /// Load aligned i16 data
    #[inline]
    pub unsafe fn load_aligned_i16<const N: usize>(data: &[i16]) -> [i16; N] {
        assert!(data.len() >= N);
        let mut result = [0i16; N];
        result.copy_from_slice(&data[..N]);
        result
    }
    
    /// Store aligned i16 data
    #[inline]
    pub unsafe fn store_aligned_i16<const N: usize>(dst: &mut [i16], src: &[i16; N]) {
        assert!(dst.len() >= N);
        dst[..N].copy_from_slice(src);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simd_detection() {
        let selector = SimdSelector::new();
        let backends = selector.available_backends();
        
        println!("Available SIMD backends:");
        for backend in &backends {
            println!("  - {}", backend);
        }
        
        assert!(!backends.is_empty());
        assert!(backends.contains(&"generic"));
    }
    
    #[test]
    fn test_backend_selection() {
        let selector = SimdSelector::new();
        let backend = selector.select_best();
        
        println!("Selected backend: {}", backend.name());
        assert!(backend.is_available());
    }
}