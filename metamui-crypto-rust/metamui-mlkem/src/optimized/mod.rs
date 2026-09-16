#![allow(warnings)]
//! High-performance ML-KEM-768 implementation with SIMD and GPU acceleration
//!
//! This crate provides an optimized implementation of ML-KEM-768 (NIST FIPS 203)
//! with support for SIMD instructions (AVX2, AVX-512, NEON) and GPU acceleration.

// Allow common warnings during development
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(missing_docs)]
//!
//! # Features
//!
//! - **Reference Backend**: Pure Rust implementation, constant-time
//! - **AVX2 Backend**: Intel/AMD x86_64 SIMD acceleration
//! - **NEON Backend**: ARM SIMD acceleration
//! - **GPU Backend**: WebGPU-based acceleration for batch operations
//! - **Automatic Selection**: Runtime detection of best available backend
//!
//! # Example
//!
//! ```rust
//! use metamui_mlkem_optimized::MlkemOptimized;
//! use rand::thread_rng;
//!
//! let mlkem = MlkemOptimized::new();
//! let mut rng = thread_rng();
//!
//! // Generate keypair
//! let keypair = mlkem.keygen(&mut rng).unwrap();
//!
//! // Encapsulate
//! let (ciphertext, shared_secret1) = mlkem.encapsulate(&keypair.public_key, &mut rng).unwrap();
//!
//! // Decapsulate
//! let shared_secret2 = mlkem.decapsulate(&keypair.private_key, &ciphertext).unwrap();
//!
//! assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

use rand_core::{CryptoRng, RngCore};

// Re-export core ML-KEM types
pub use metamui_mlkem::{
    Ciphertext, KeyPair as Keypair, PublicKey, PrivateKey as SecretKey,
    SharedSecret,
};

// Use local error types
pub use error::{MLKemError, Result, MLKemError as Error};

// Import constants from metamui_mlkem::mlkem768
pub use metamui_mlkem::mlkem768::constants::{
    MLKEM_CIPHERTEXT_BYTES as CIPHERTEXT_SIZE,
    MLKEM_PUBLICKEY_BYTES as PUBLIC_KEY_SIZE,
    MLKEM_SECRETKEY_BYTES as SECRET_KEY_SIZE,
    MLKEM_SHAREDSECRET_BYTES as SHARED_SECRET_SIZE,
    MLKEM_K, MLKEM_N, MLKEM_Q,
};

// Error handling  
pub mod error;

// Backend abstraction
pub mod backend;
pub use backend::{Backend, BackendEnum, Capabilities, CpuFeatures, PerformanceHints};

// SIMD optimizations
#[cfg(feature = "simd")]
pub mod simd;

// GPU acceleration
#[cfg(feature = "gpu")]
pub mod gpu;

// Batch processing
#[cfg(feature = "parallel")]
pub mod batch;

// Memory management
pub mod memory;

/// Mathematical operations for ML-KEM
pub mod math;

/// Serialization and deserialization routines
pub mod serialization;

/// Utility functions and helpers
pub mod utils;

/// Assembly optimizations for x86_64 and ARM64
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod asm;

/// Optimized ML-KEM-768 implementation with automatic backend selection
pub struct MlkemOptimized {
    backend: BackendEnum,
}

impl MlkemOptimized {
    /// Create a new optimized ML-KEM instance with automatic backend selection
    ///
    /// This automatically detects and selects the best available backend
    /// based on CPU features and platform capabilities.
    pub fn new() -> Self {
        use backend::selector::BackendSelector;
        Self {
            backend: BackendSelector::select(),
        }
    }

    /// Create with a specific backend
    ///
    /// Use this when you want to explicitly control which backend is used.
    pub fn with_backend(backend: BackendEnum) -> Self {
        Self { backend }
    }

    /// Create with the reference backend
    ///
    /// This uses the pure Rust implementation without any platform-specific optimizations.
    pub fn with_reference() -> Self {
        use backend::reference::ReferenceBackend;
        Self {
            backend: BackendEnum::Reference(ReferenceBackend::new()),
        }
    }

    /// Create with AVX2 backend (x86_64 only)
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    pub fn with_avx2() -> Result<Self> {
        use backend::simd_backend::Avx2Backend;
        if !is_x86_feature_detected!("avx2") {
            return Err(Error::BackendError("Invalid input".to_string()));
        }
        Ok(Self {
            backend: Box::new(Avx2Backend::new()),
        })
    }

    /// Create with NEON backend (ARM only)
    #[cfg(all(feature = "neon", target_arch = "aarch64"))]
    pub fn with_neon() -> Result<Self> {
        use backend::simd_backend::NeonBackend;
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return Err(Error::BackendError("Invalid input".to_string()));
        }
        Ok(Self {
            backend: Box::new(NeonBackend::new()),
        })
    }

    /// Create with GPU backend
    #[cfg(feature = "gpu")]
    pub fn with_gpu() -> Result<Self> {
        use backend::gpu_backend::GpuBackend;
        match GpuBackend::new() {
            Ok(backend) => Ok(Self {
                backend: Box::new(backend),
            }),
            Err(_) => Err(Error::BackendError("Invalid input".to_string())),
        }
    }

    /// Generate a new keypair
    pub fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Keypair> {
        self.backend.keygen(rng)
    }

    /// Encapsulate a shared secret
    pub fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret)> {
        self.backend.encapsulate(public_key, rng)
    }

    /// Decapsulate a shared secret
    pub fn decapsulate(
        &self,
        secret_key: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> Result<SharedSecret> {
        self.backend.decapsulate(secret_key, ciphertext)
    }

    /// Get backend name
    pub fn backend_name(&self) -> &str {
        self.backend.name()
    }

    /// Get performance hints for the current backend
    pub fn performance_hints(&self) -> PerformanceHints {
        self.backend.performance_hints()
    }

    /// Check if batch operations are supported
    pub fn supports_batch(&self) -> bool {
        self.backend.supports_batch()
    }

    /// Get system capabilities
    pub fn capabilities() -> Capabilities {
        Capabilities {
            cpu_features: CpuFeatures::detect(),
            available_memory: memory::available_memory_mb(),
            cpu_cores: num_cpus(),
            #[cfg(feature = "gpu")]
            has_gpu: gpu::is_available(),
            #[cfg(not(feature = "gpu"))]
            has_gpu: false,
        }
    }

    /// Batch key generation
    #[cfg(feature = "parallel")]
    pub fn batch_keygen<R: RngCore + CryptoRng>(
        &self,
        count: usize,
        rng: &mut R,
    ) -> Result<Vec<Keypair>> {
        self.backend.batch_keygen(count, rng)
    }

    /// Batch encapsulation
    #[cfg(feature = "parallel")]
    pub fn batch_encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_keys: &[PublicKey],
        rng: &mut R,
    ) -> Result<Vec<(Ciphertext, SharedSecret)>> {
        self.backend.batch_encapsulate(public_keys, rng)
    }

    /// Batch decapsulation
    #[cfg(feature = "parallel")]
    pub fn batch_decapsulate(
        &self,
        secret_keys: &[SecretKey],
        ciphertexts: &[Ciphertext],
    ) -> Result<Vec<SharedSecret>> {
        if secret_keys.len() != ciphertexts.len() {
            return Err(Error::BackendError("Invalid input".to_string()));
        }
        self.backend.batch_decapsulate(secret_keys, ciphertexts)
    }

    /// Benchmark the current backend
    ///
    /// Returns the average time in microseconds for each operation
    pub fn benchmark(&self, iterations: usize) -> BenchmarkResult {
        use std::time::Instant;
        
        let mut rng = rand::thread_rng();
        
        // Benchmark keygen
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = self.keygen(&mut rng);
        }
        let keygen_us = start.elapsed().as_micros() as f64 / iterations as f64;
        
        // Generate a keypair for encap/decap benchmarks
        let keypair = self.keygen(&mut rng).unwrap();
        
        // Benchmark encapsulation
        let start = Instant::now();
        let mut ciphertexts = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let (ct, _) = self.encapsulate(&keypair.public_key, &mut rng).unwrap();
            ciphertexts.push(ct);
        }
        let encapsulate_us = start.elapsed().as_micros() as f64 / iterations as f64;
        
        // Benchmark decapsulation
        let start = Instant::now();
        for ct in &ciphertexts {
            let _ = self.decapsulate(&keypair.private_key, ct);
        }
        let decapsulate_us = start.elapsed().as_micros() as f64 / iterations as f64;
        
        BenchmarkResult {
            backend: self.backend_name().to_string(),
            keygen_us,
            encapsulate_us,
            decapsulate_us,
            iterations,
        }
    }
}

impl Default for MlkemOptimized {
    fn default() -> Self {
        Self::new()
    }
}



/// Benchmark results for a backend
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Backend name
    pub backend: String,
    /// Average key generation time in microseconds
    pub keygen_us: f64,
    /// Average encapsulation time in microseconds
    pub encapsulate_us: f64,
    /// Average decapsulation time in microseconds
    pub decapsulate_us: f64,
    /// Number of iterations
    pub iterations: usize,
}

impl BenchmarkResult {
    /// Calculate operations per second
    pub fn ops_per_second(&self) -> (f64, f64, f64) {
        let keygen_ops = 1_000_000.0 / self.keygen_us;
        let encap_ops = 1_000_000.0 / self.encapsulate_us;
        let decap_ops = 1_000_000.0 / self.decapsulate_us;
        (keygen_ops, encap_ops, decap_ops)
    }
    
    /// Format as a report string
    pub fn report(&self) -> String {
        let (keygen_ops, encap_ops, decap_ops) = self.ops_per_second();
        format!(
            "Backend: {}\n\
             Iterations: {}\n\
             Key Generation: {:.2} μs ({:.0} ops/sec)\n\
             Encapsulation: {:.2} μs ({:.0} ops/sec)\n\
             Decapsulation: {:.2} μs ({:.0} ops/sec)",
            self.backend,
            self.iterations,
            self.keygen_us, keygen_ops,
            self.encapsulate_us, encap_ops,
            self.decapsulate_us, decap_ops
        )
    }
}

/// Get the number of CPU cores
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_basic_kem_flow() {
        let mlkem = MlkemOptimized::new();
        let mut rng = thread_rng();

        // Generate keypair
        let keypair = mlkem.keygen(&mut rng).unwrap();

        // Encapsulate
        let (ct, ss1) = mlkem.encapsulate(&keypair.public_key, &mut rng).unwrap();

        // Decapsulate
        let ss2 = mlkem.decapsulate(&keypair.private_key, &ct).unwrap();

        // Verify shared secrets match
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_backend_selection() {
        let mlkem = MlkemOptimized::new();
        println!("Selected backend: {}", mlkem.backend_name());
        assert!(!mlkem.backend_name().is_empty());
    }

    #[test]
    fn test_capabilities() {
        let caps = MlkemOptimized::capabilities();
        println!("System capabilities: {:?}", caps);
        assert!(caps.cpu_cores > 0);
        assert!(caps.available_memory > 0);
    }

    #[test]
    fn test_reference_backend() {
        let mlkem = MlkemOptimized::with_reference();
        let mut rng = thread_rng();
        
        let keypair = mlkem.keygen(&mut rng).unwrap();
        let (ct, ss1) = mlkem.encapsulate(&keypair.public_key, &mut rng).unwrap();
        let ss2 = mlkem.decapsulate(&keypair.private_key, &ct).unwrap();
        
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
        assert_eq!(mlkem.backend_name(), "Reference");
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_batch_operations() {
        let mlkem = MlkemOptimized::new();
        let mut rng = thread_rng();

        // Generate multiple keypairs
        let keypairs = mlkem.batch_keygen(10, &mut rng).unwrap();
        assert_eq!(keypairs.len(), 10);

        // Extract public keys
        let public_keys: Vec<_> = keypairs.iter().map(|kp| kp.public_key.clone()).collect();

        // Batch encapsulate
        let encaps = mlkem.batch_encapsulate(&public_keys, &mut rng).unwrap();
        assert_eq!(encaps.len(), 10);

        // Extract secret keys and ciphertexts
        let secret_keys: Vec<_> = keypairs.iter().map(|kp| kp.private_key.clone()).collect();
        let ciphertexts: Vec<_> = encaps.iter().map(|(ct, _)| ct.clone()).collect();

        // Batch decapsulate
        let shared_secrets = mlkem.batch_decapsulate(&secret_keys, &ciphertexts).unwrap();
        assert_eq!(shared_secrets.len(), 10);

        // Verify all shared secrets match
        for (i, ss) in shared_secrets.iter().enumerate() {
            assert_eq!(ss.as_bytes(), encaps[i].1.as_bytes());
        }
    }
    
    #[test]
    fn test_benchmark() {
        let mlkem = MlkemOptimized::new();
        let result = mlkem.benchmark(10);
        println!("{}", result.report());
        
        assert!(result.keygen_us > 0.0);
        assert!(result.encapsulate_us > 0.0);
        assert!(result.decapsulate_us > 0.0);
    }
}