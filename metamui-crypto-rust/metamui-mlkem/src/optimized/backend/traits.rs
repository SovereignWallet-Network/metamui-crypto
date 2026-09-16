//! Backend trait definitions for ML-KEM-768
//!
//! This module defines the core traits that all backend implementations must satisfy.

use crate::{Keypair, PublicKey, SecretKey, Ciphertext, SharedSecret, Result};
use rand_core::{CryptoRng, RngCore};

/// Core ML-KEM backend trait
pub trait MlkemBackend: Send + Sync {
    /// Generate a new keypair
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
    
    /// Get backend name for identification
    fn name(&self) -> &'static str;
    
    /// Check if this backend supports batch operations
    fn supports_batch(&self) -> bool {
        false
    }
    
    /// Get performance characteristics
    fn performance_characteristics(&self) -> BackendCharacteristics {
        BackendCharacteristics::default()
    }
}

/// Batch operations trait for backends that support parallel processing
#[cfg(feature = "parallel")]
pub trait BatchMlkemBackend: MlkemBackend {
    /// Generate multiple keypairs in batch
    fn batch_keygen<R: RngCore + CryptoRng>(
        &self,
        count: usize,
        rng: &mut R,
    ) -> Result<Vec<Keypair>>;
    
    /// Encapsulate multiple shared secrets in batch
    fn batch_encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_keys: &[PublicKey],
        rng: &mut R,
    ) -> Result<Vec<(Ciphertext, SharedSecret)>>;
    
    /// Decapsulate multiple shared secrets in batch
    fn batch_decapsulate(
        &self,
        secret_keys: &[SecretKey],
        ciphertexts: &[Ciphertext],
    ) -> Result<Vec<SharedSecret>>;
    
    /// Get optimal batch size for this backend
    fn optimal_batch_size(&self) -> usize {
        match self.performance_characteristics().backend_type {
            BackendType::Gpu => 1024,
            BackendType::SimdAvx512 => 64,
            BackendType::SimdAvx2 => 32,
            BackendType::SimdNeon => 16,
            BackendType::Reference => 1,
        }
    }
}

/// Backend performance characteristics
#[derive(Debug, Clone, Copy)]
pub struct BackendCharacteristics {
    /// Backend type
    pub backend_type: BackendType,
    /// Relative performance (1.0 = reference)
    pub relative_performance: f32,
    /// Whether the backend is constant-time
    pub constant_time: bool,
    /// Memory usage profile
    pub memory_profile: MemoryProfile,
    /// Parallelization capability
    pub parallelization: ParallelizationCapability,
}

impl Default for BackendCharacteristics {
    fn default() -> Self {
        Self {
            backend_type: BackendType::Reference,
            relative_performance: 1.0,
            constant_time: true,
            memory_profile: MemoryProfile::Low,
            parallelization: ParallelizationCapability::None,
        }
    }
}

/// Backend type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    /// Reference implementation
    Reference,
    /// SIMD with AVX2
    SimdAvx2,
    /// SIMD with AVX-512
    SimdAvx512,
    /// SIMD with ARM NEON
    SimdNeon,
    /// GPU accelerated
    Gpu,
}

/// Memory usage profile
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProfile {
    /// Low memory usage (< 64KB)
    Low,
    /// Medium memory usage (64KB - 256KB)
    Medium,
    /// High memory usage (> 256KB)
    High,
}

/// Parallelization capability
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParallelizationCapability {
    /// No parallelization
    None,
    /// Thread-level parallelization
    Thread,
    /// SIMD-level parallelization
    Simd,
    /// GPU-level parallelization
    Gpu,
}

/// Performance metrics for backend operations
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// Average keygen time in microseconds
    pub keygen_us: f64,
    /// Average encapsulation time in microseconds
    pub encapsulate_us: f64,
    /// Average decapsulation time in microseconds
    pub decapsulate_us: f64,
    /// Throughput in operations per second
    pub throughput_ops: f64,
}

/// Backend capabilities query trait
pub trait BackendCapabilities {
    /// Check if AVX2 is supported
    fn has_avx2(&self) -> bool {
        #[cfg(all(target_arch = "x86_64", feature = "simd"))]
        {
            is_x86_feature_detected!("avx2")
        }
        #[cfg(not(all(target_arch = "x86_64", feature = "simd")))]
        {
            false
        }
    }
    
    /// Check if AVX-512 is supported
    fn has_avx512(&self) -> bool {
        #[cfg(all(target_arch = "x86_64", feature = "simd"))]
        {
            is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512bw")
        }
        #[cfg(not(all(target_arch = "x86_64", feature = "simd")))]
        {
            false
        }
    }
    
    /// Check if NEON is supported
    fn has_neon(&self) -> bool {
        #[cfg(all(target_arch = "aarch64", feature = "simd"))]
        {
            std::arch::is_aarch64_feature_detected!("neon")
        }
        #[cfg(not(all(target_arch = "aarch64", feature = "simd")))]
        {
            false
        }
    }
    
    /// Check if GPU acceleration is available
    fn has_gpu(&self) -> bool {
        #[cfg(feature = "gpu")]
        {
            // Check for GPU availability at runtime
            crate::gpu::is_gpu_available()
        }
        #[cfg(not(feature = "gpu"))]
        {
            false
        }
    }
    
    /// Get available memory in MB
    fn available_memory_mb(&self) -> usize {
        // Platform-specific memory detection
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines() {
                    if line.starts_with("MemAvailable:") {
                        if let Some(kb_str) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = kb_str.parse::<usize>() {
                                return kb / 1024;
                            }
                        }
                    }
                }
            }
        }
        
        // Default to conservative estimate
        1024 // 1GB
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    struct TestBackend;
    
    impl BackendCapabilities for TestBackend {}
    
    #[test]
    fn test_backend_capabilities() {
        let backend = TestBackend;
        
        // These tests just verify the methods exist and return valid values
        let _ = backend.has_avx2();
        let _ = backend.has_avx512();
        let _ = backend.has_neon();
        let _ = backend.has_gpu();
        let mem = backend.available_memory_mb();
        assert!(mem > 0);
    }
    
    #[test]
    fn test_backend_characteristics() {
        let chars = BackendCharacteristics::default();
        assert_eq!(chars.backend_type, BackendType::Reference);
        assert_eq!(chars.relative_performance, 1.0);
        assert!(chars.constant_time);
        assert_eq!(chars.memory_profile, MemoryProfile::Low);
        assert_eq!(chars.parallelization, ParallelizationCapability::None);
    }
}