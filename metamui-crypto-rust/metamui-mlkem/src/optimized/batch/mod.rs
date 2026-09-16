//! Batch processing framework for ML-KEM-768
//!
//! This module provides high-performance batch processing with automatic
//! CPU/GPU scheduling, memory pooling, and parallel execution.

use crate::{
    backend::{Backend, BackendEnum},
    Keypair, PublicKey, SecretKey, Ciphertext, SharedSecret, Result, Error,
};
use rand_core::{CryptoRng, RngCore};
use std::sync::Arc;

pub mod executor;
pub mod memory_pool;
pub mod parallel;

pub use executor::{BatchExecutor, ExecutionStrategy, BatchConfig};
pub use memory_pool::{MemoryPool, PooledBuffer};
pub use parallel::{ParallelBatchProcessor, ProcessingMode};

/// Batch processing orchestrator with automatic backend selection
pub struct BatchProcessor {
    /// Batch executor for scheduling
    executor: BatchExecutor,
    /// Memory pool for efficient allocation
    memory_pool: Arc<MemoryPool>,
    /// Parallel processor for CPU batches
    parallel_processor: ParallelBatchProcessor,
    /// Current backend
    backend: Arc<BackendEnum>,
}

impl BatchProcessor {
    /// Create a new batch processor with default configuration
    pub fn new(backend: BackendEnum) -> Self {
        let config = BatchConfig::default();
        Self::with_config(backend, config)
    }

    /// Create a batch processor with custom configuration
    pub fn with_config(backend: BackendEnum, config: BatchConfig) -> Self {
        let backend = Arc::new(backend);
        let memory_pool = Arc::new(MemoryPool::new(config.memory_pool_size));
        
        Self {
            executor: BatchExecutor::new(backend.clone(), config.clone()),
            memory_pool: memory_pool.clone(),
            parallel_processor: ParallelBatchProcessor::new(
                backend.clone(),
                memory_pool.clone(),
                ProcessingMode::Auto
            ),
            backend,
        }
    }

    /// Process batch key generation
    pub fn batch_keygen<R: RngCore + CryptoRng>(
        &self,
        count: usize,
        rng: &mut R,
    ) -> Result<Vec<Keypair>> {
        // Determine execution strategy based on batch size
        let strategy = self.executor.determine_strategy(BatchOperation::Keygen, count);
        
        match strategy {
            ExecutionStrategy::Serial => {
                // Small batch, process serially
                self.serial_keygen(count, rng)
            }
            ExecutionStrategy::Parallel => {
                // Medium batch, use CPU parallelization
                // Generate seeds for parallel processing
                use rand_chacha::ChaCha20Rng;
                use rand::SeedableRng;
                
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                let mut seeded_rng = ChaCha20Rng::from_seed(seed);
                
                self.parallel_processor.parallel_keygen(count, &mut seeded_rng)
                    .map_err(|e| Error::ParallelError(e.to_string()))
            }
            ExecutionStrategy::Gpu => {
                // Large batch, offload to GPU if available
                self.gpu_keygen(count, rng)
            }
            ExecutionStrategy::Hybrid => {
                // Very large batch, use both CPU and GPU
                self.hybrid_keygen(count, rng)
            }
        }
    }

    /// Process batch encapsulation
    pub fn batch_encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_keys: &[PublicKey],
        rng: &mut R,
    ) -> Result<Vec<(Ciphertext, SharedSecret)>> {
        let count = public_keys.len();
        let strategy = self.executor.determine_strategy(BatchOperation::Encapsulate, count);
        
        match strategy {
            ExecutionStrategy::Serial => {
                self.serial_encapsulate(public_keys, rng)
            }
            ExecutionStrategy::Parallel => {
                self.parallel_processor.parallel_encapsulate(public_keys, rng)
                    .map_err(|e| Error::ParallelError(e.to_string()))
            }
            ExecutionStrategy::Gpu => {
                self.gpu_encapsulate(public_keys, rng)
            }
            ExecutionStrategy::Hybrid => {
                self.hybrid_encapsulate(public_keys, rng)
            }
        }
    }

    /// Process batch decapsulation
    pub fn batch_decapsulate(
        &self,
        secret_keys: &[SecretKey],
        ciphertexts: &[Ciphertext],
    ) -> Result<Vec<SharedSecret>> {
        if secret_keys.len() != ciphertexts.len() {
            return Err(Error::InvalidInput);
        }
        
        let count = secret_keys.len();
        let strategy = self.executor.determine_strategy(BatchOperation::Decapsulate, count);
        
        match strategy {
            ExecutionStrategy::Serial => {
                self.serial_decapsulate(secret_keys, ciphertexts)
            }
            ExecutionStrategy::Parallel => {
                self.parallel_processor.parallel_decapsulate(secret_keys, ciphertexts)
                    .map_err(|e| Error::ParallelError(e.to_string()))
            }
            ExecutionStrategy::Gpu => {
                self.gpu_decapsulate(secret_keys, ciphertexts)
            }
            ExecutionStrategy::Hybrid => {
                self.hybrid_decapsulate(secret_keys, ciphertexts)
            }
        }
    }

    /// Stream processing for large batches
    pub fn stream_process<R, F, T>(
        &self,
        items: impl Iterator<Item = T>,
        chunk_size: usize,
        mut processor: F,
        rng: &mut R,
    ) -> Result<Vec<Vec<T>>>
    where
        R: RngCore + CryptoRng,
        F: FnMut(&[T], &mut R) -> Result<Vec<T>>,
        T: Send + Sync,
    {
        let mut results = Vec::new();
        let mut chunk = Vec::with_capacity(chunk_size);
        
        for item in items {
            chunk.push(item);
            
            if chunk.len() >= chunk_size {
                let processed = processor(&chunk, rng)?;
                results.push(processed);
                chunk.clear();
            }
        }
        
        // Process remaining items
        if !chunk.is_empty() {
            let processed = processor(&chunk, rng)?;
            results.push(processed);
        }
        
        Ok(results)
    }

    // Private implementation methods

    fn serial_keygen<R: RngCore + CryptoRng>(
        &self,
        count: usize,
        rng: &mut R,
    ) -> Result<Vec<Keypair>> {
        let mut keypairs = Vec::with_capacity(count);
        for _ in 0..count {
            keypairs.push(self.backend.keygen(rng)?);
        }
        Ok(keypairs)
    }

    fn serial_encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_keys: &[PublicKey],
        rng: &mut R,
    ) -> Result<Vec<(Ciphertext, SharedSecret)>> {
        let mut results = Vec::with_capacity(public_keys.len());
        for pk in public_keys {
            results.push(self.backend.encapsulate(pk, rng)?);
        }
        Ok(results)
    }

    fn serial_decapsulate(
        &self,
        secret_keys: &[SecretKey],
        ciphertexts: &[Ciphertext],
    ) -> Result<Vec<SharedSecret>> {
        let mut results = Vec::with_capacity(secret_keys.len());
        for (sk, ct) in secret_keys.iter().zip(ciphertexts.iter()) {
            results.push(self.backend.decapsulate(sk, ct)?);
        }
        Ok(results)
    }

    fn gpu_keygen<R: RngCore + CryptoRng>(
        &self,
        count: usize,
        rng: &mut R,
    ) -> Result<Vec<Keypair>> {
        #[cfg(feature = "gpu")]
        {
            if let Some(gpu_backend) = self.executor.get_gpu_backend() {
                return gpu_backend.batch_keygen(count, rng);
            }
        }
        
        // Fallback to parallel processing
        self.parallel_processor.parallel_keygen(count, rng)
            .map_err(|e| Error::ParallelError(e.to_string()))
    }

    fn gpu_encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_keys: &[PublicKey],
        rng: &mut R,
    ) -> Result<Vec<(Ciphertext, SharedSecret)>> {
        #[cfg(feature = "gpu")]
        {
            if let Some(gpu_backend) = self.executor.get_gpu_backend() {
                return gpu_backend.batch_encapsulate(public_keys, rng);
            }
        }
        
        // Fallback to parallel processing
        self.parallel_processor.parallel_encapsulate(public_keys, rng)
            .map_err(|e| Error::ParallelError(e.to_string()))
    }

    fn gpu_decapsulate(
        &self,
        secret_keys: &[SecretKey],
        ciphertexts: &[Ciphertext],
    ) -> Result<Vec<SharedSecret>> {
        #[cfg(feature = "gpu")]
        {
            if let Some(gpu_backend) = self.executor.get_gpu_backend() {
                return gpu_backend.batch_decapsulate(secret_keys, ciphertexts);
            }
        }
        
        // Fallback to parallel processing
        self.parallel_processor.parallel_decapsulate(secret_keys, ciphertexts)
            .map_err(|e| Error::ParallelError(e.to_string()))
    }

    fn hybrid_keygen<R: RngCore + CryptoRng>(
        &self,
        count: usize,
        rng: &mut R,
    ) -> Result<Vec<Keypair>> {
        // Split workload between GPU and CPU
        let gpu_count = (count * 3) / 4; // 75% to GPU
        let cpu_count = count - gpu_count;
        
        let gpu_result = self.gpu_keygen(gpu_count, rng)?;
        let cpu_result = self.parallel_processor.parallel_keygen(cpu_count, rng)
            .map_err(|e| Error::ParallelError(e.to_string()))?;
        
        let mut results = gpu_result;
        results.extend(cpu_result);
        Ok(results)
    }

    fn hybrid_encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_keys: &[PublicKey],
        rng: &mut R,
    ) -> Result<Vec<(Ciphertext, SharedSecret)>> {
        let total = public_keys.len();
        let gpu_count = (total * 3) / 4;
        
        let gpu_keys = &public_keys[..gpu_count];
        let cpu_keys = &public_keys[gpu_count..];
        
        let gpu_result = self.gpu_encapsulate(gpu_keys, rng)?;
        let cpu_result = self.parallel_processor.parallel_encapsulate(cpu_keys, rng)
            .map_err(|e| Error::ParallelError(e.to_string()))?;
        
        let mut results = gpu_result;
        results.extend(cpu_result);
        Ok(results)
    }

    fn hybrid_decapsulate(
        &self,
        secret_keys: &[SecretKey],
        ciphertexts: &[Ciphertext],
    ) -> Result<Vec<SharedSecret>> {
        let total = secret_keys.len();
        let gpu_count = (total * 3) / 4;
        
        let gpu_sks = &secret_keys[..gpu_count];
        let gpu_cts = &ciphertexts[..gpu_count];
        let cpu_sks = &secret_keys[gpu_count..];
        let cpu_cts = &ciphertexts[gpu_count..];
        
        let gpu_result = self.gpu_decapsulate(gpu_sks, gpu_cts)?;
        let cpu_result = self.parallel_processor.parallel_decapsulate(cpu_sks, cpu_cts)?;
        
        let mut results = gpu_result;
        results.extend(cpu_result);
        Ok(results)
    }

    /// Get performance statistics
    pub fn get_stats(&self) -> BatchStats {
        BatchStats {
            total_operations: self.executor.total_operations(),
            gpu_operations: self.executor.gpu_operations(),
            cpu_operations: self.executor.cpu_operations(),
            memory_pool_hits: 0, // TODO: Implement memory pool statistics
            memory_pool_misses: 0, // TODO: Implement memory pool statistics
        }
    }

    /// Clear memory pool
    pub fn clear_memory_pool(&self) {
        self.memory_pool.clear();
    }

    /// Get optimal batch size for current backend
    pub fn optimal_batch_size(&self) -> usize {
        self.backend.performance_hints().optimal_batch_size
    }
}

/// Batch operation types
#[derive(Debug, Clone, Copy)]
pub enum BatchOperation {
    /// Key generation
    Keygen,
    /// Encapsulation
    Encapsulate,
    /// Decapsulation
    Decapsulate,
    /// Number theoretic transform
    NTT,
    /// Inverse number theoretic transform
    InverseNTT,
    /// Polynomial multiplication
    PolyMul,
    /// Polynomial addition
    PolyAdd,
    /// Polynomial subtraction
    PolySub,
    /// Matrix-vector multiplication
    MatrixVectorMul,
}

/// Batch processing statistics
#[derive(Debug, Clone)]
pub struct BatchStats {
    /// Total operations processed
    pub total_operations: usize,
    /// Operations processed on GPU
    pub gpu_operations: usize,
    /// Operations processed on CPU
    pub cpu_operations: usize,
    /// Memory pool cache hits
    pub memory_pool_hits: usize,
    /// Memory pool cache misses
    pub memory_pool_misses: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::reference::ReferenceBackend;
    use rand_chacha::ChaCha20Rng;
    use rand::SeedableRng;

    #[test]
    fn test_batch_processor_creation() {
        let backend = BackendEnum::Reference(ReferenceBackend::new());
        let processor = BatchProcessor::new(backend);
        assert!(processor.optimal_batch_size() > 0);
    }

    #[test]
    fn test_batch_keygen() {
        let backend = BackendEnum::Reference(ReferenceBackend::new());
        let processor = BatchProcessor::new(backend);
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        
        let keypairs = processor.batch_keygen(10, &mut rng).unwrap();
        assert_eq!(keypairs.len(), 10);
    }

    #[test]
    fn test_batch_encapsulate() {
        let backend = BackendEnum::Reference(ReferenceBackend::new());
        let processor = BatchProcessor::new(backend);
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        
        // Generate test keys
        let keypairs = processor.batch_keygen(5, &mut rng).unwrap();
        let public_keys: Vec<_> = keypairs.iter().map(|kp| kp.public_key.clone()).collect();
        
        let results = processor.batch_encapsulate(&public_keys, &mut rng).unwrap();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_batch_decapsulate() {
        let backend = BackendEnum::Reference(ReferenceBackend::new());
        let processor = BatchProcessor::new(backend);
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        
        // Generate test data
        let keypairs = processor.batch_keygen(5, &mut rng).unwrap();
        let public_keys: Vec<_> = keypairs.iter().map(|kp| kp.public_key.clone()).collect();
        let encaps = processor.batch_encapsulate(&public_keys, &mut rng).unwrap();
        
        let secret_keys: Vec<_> = keypairs.iter().map(|kp| kp.private_key.clone()).collect();
        let ciphertexts: Vec<_> = encaps.iter().map(|(ct, _)| ct.clone()).collect();
        
        let shared_secrets = processor.batch_decapsulate(&secret_keys, &ciphertexts).unwrap();
        assert_eq!(shared_secrets.len(), 5);
        
        // Verify shared secrets match
        for (i, ss) in shared_secrets.iter().enumerate() {
            assert_eq!(ss.as_bytes(), encaps[i].1.as_bytes());
        }
    }

    #[test]
    fn test_get_stats() {
        let backend = BackendEnum::Reference(ReferenceBackend::new());
        let processor = BatchProcessor::new(backend);
        
        let stats = processor.get_stats();
        assert_eq!(stats.total_operations, 0);
        assert_eq!(stats.gpu_operations, 0);
        assert_eq!(stats.cpu_operations, 0);
    }
}