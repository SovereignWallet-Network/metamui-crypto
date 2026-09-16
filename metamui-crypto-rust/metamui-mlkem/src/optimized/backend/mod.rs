//! Backend abstraction layer for ML-KEM-768
//!
//! This module provides a unified interface for different ML-KEM implementations,
//! allowing runtime selection of the optimal backend based on platform capabilities.

use crate::{Keypair, PublicKey, SecretKey, Ciphertext, SharedSecret, Result, MLKemError as Error};
use rand_core::{CryptoRng, RngCore};

pub mod traits;
pub mod selector;
pub mod reference;
pub mod backend_enum;

#[cfg(feature = "simd")]
pub mod simd_backend;

#[cfg(feature = "gpu")]
pub mod gpu_backend;

pub use traits::MlkemBackend;
pub use backend_enum::BackendEnum;

/// Main backend trait for ML-KEM operations
pub trait Backend: Send + Sync {
    /// Get the name of this backend
    fn name(&self) -> &str;
    
    /// Check if this backend supports batch operations
    fn supports_batch(&self) -> bool;
    
    /// Get performance hints for this backend
    fn performance_hints(&self) -> PerformanceHints;
    
    /// Generate a keypair
    fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Keypair>;
    
    /// Encapsulate a shared secret
    fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret)>;
    
    /// Decapsulate a shared secret
    fn decapsulate(
        &self,
        secret_key: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> Result<SharedSecret>;
    
    /// Batch key generation (default implementation)
    #[cfg(feature = "parallel")]
    fn batch_keygen<R: RngCore + CryptoRng>(
        &self,
        count: usize,
        rng: &mut R,
    ) -> Result<Vec<Keypair>> {
        let mut keypairs = Vec::with_capacity(count);
        for _ in 0..count {
            keypairs.push(self.keygen(rng)?);
        }
        Ok(keypairs)
    }
    
    /// Batch encapsulation (default implementation)
    #[cfg(feature = "parallel")]
    fn batch_encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_keys: &[PublicKey],
        rng: &mut R,
    ) -> Result<Vec<(Ciphertext, SharedSecret)>> {
        let mut results = Vec::with_capacity(public_keys.len());
        for pk in public_keys {
            results.push(self.encapsulate(pk, rng)?);
        }
        Ok(results)
    }
    
    /// Batch decapsulation (default implementation)
    #[cfg(feature = "parallel")]
    fn batch_decapsulate(
        &self,
        secret_keys: &[SecretKey],
        ciphertexts: &[Ciphertext],
    ) -> Result<Vec<SharedSecret>> {
        if secret_keys.len() != ciphertexts.len() {
            return Err(Error::BackendError("Mismatched array lengths".to_string()));
        }
        
        let mut results = Vec::with_capacity(secret_keys.len());
        for (sk, ct) in secret_keys.iter().zip(ciphertexts.iter()) {
            results.push(self.decapsulate(sk, ct)?);
        }
        Ok(results)
    }
    
    /// Estimate memory usage for operations
    fn memory_estimate(&self, operation: Operation) -> MemoryEstimate {
        // Default estimates
        match operation {
            Operation::Keygen => MemoryEstimate {
                heap: 32 * 1024,  // 32KB
                stack: 8 * 1024,   // 8KB
            },
            Operation::Encapsulate => MemoryEstimate {
                heap: 16 * 1024,  // 16KB
                stack: 4 * 1024,   // 4KB
            },
            Operation::Decapsulate => MemoryEstimate {
                heap: 16 * 1024,  // 16KB
                stack: 4 * 1024,   // 4KB
            },
        }
    }
}

/// Performance hints for backend selection
#[derive(Debug, Clone, Copy)]
pub struct PerformanceHints {
    /// Relative speed (1.0 = reference implementation)
    pub relative_speed: f32,
    /// Whether this backend uses SIMD instructions
    pub uses_simd: bool,
    /// Whether this backend uses GPU acceleration
    pub uses_gpu: bool,
    /// Optimal batch size for this backend
    pub optimal_batch_size: usize,
    /// Whether this backend is constant-time
    pub constant_time: bool,
}

impl Default for PerformanceHints {
    fn default() -> Self {
        Self {
            relative_speed: 1.0,
            uses_simd: false,
            uses_gpu: false,
            optimal_batch_size: 1,
            constant_time: true,
        }
    }
}

/// Operation type for memory estimation
#[derive(Debug, Clone, Copy)]
pub enum Operation {
    /// Key generation
    Keygen,
    /// Encapsulation
    Encapsulate,
    /// Decapsulation
    Decapsulate,
}

/// Memory usage estimate
#[derive(Debug, Clone, Copy)]
pub struct MemoryEstimate {
    /// Estimated heap allocation in bytes
    pub heap: usize,
    /// Estimated stack usage in bytes
    pub stack: usize,
}

/// Backend capabilities
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    /// CPU features
    pub cpu_features: CpuFeatures,
    /// Available memory in MB
    pub available_memory: usize,
    /// Number of CPU cores
    pub cpu_cores: usize,
    /// GPU availability
    pub has_gpu: bool,
}

/// CPU feature detection
#[derive(Debug, Clone, Copy)]
pub struct CpuFeatures {
    /// AVX2 support (x86_64)
    pub avx2: bool,
    /// AVX-512 support (x86_64)
    pub avx512: bool,
    /// NEON support (ARM)
    pub neon: bool,
    /// SHA-NI support
    pub sha_ni: bool,
    /// AES-NI support
    pub aes_ni: bool,
}

impl CpuFeatures {
    /// Detect CPU features at runtime
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self {
                avx2: is_x86_feature_detected!("avx2"),
                avx512: is_x86_feature_detected!("avx512f"),
                sha_ni: is_x86_feature_detected!("sha"),
                aes_ni: is_x86_feature_detected!("aes"),
                neon: false,
            }
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            Self {
                avx2: false,
                avx512: false,
                sha_ni: std::arch::is_aarch64_feature_detected!("sha2"),
                aes_ni: std::arch::is_aarch64_feature_detected!("aes"),
                neon: std::arch::is_aarch64_feature_detected!("neon"),
            }
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Self {
                avx2: false,
                avx512: false,
                sha_ni: false,
                aes_ni: false,
                neon: false,
            }
        }
    }
}

/// Backend priority for selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Lowest priority
    Low = 0,
    /// Normal priority
    Normal = 1,
    /// High priority
    High = 2,
    /// Highest priority
    Critical = 3,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cpu_feature_detection() {
        let features = CpuFeatures::detect();
        println!("CPU Features: {:?}", features);
        
        // At least one platform should be detected
        #[cfg(target_arch = "x86_64")]
        {
            // Modern x86_64 CPUs should have at least some features
            assert!(features.avx2 || features.aes_ni || !features.avx512);
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            // ARM64 should have NEON
            assert!(features.neon);
        }
    }
    
    #[test]
    fn test_performance_hints_default() {
        let hints = PerformanceHints::default();
        assert_eq!(hints.relative_speed, 1.0);
        assert!(!hints.uses_simd);
        assert!(!hints.uses_gpu);
        assert_eq!(hints.optimal_batch_size, 1);
        assert!(hints.constant_time);
    }
}