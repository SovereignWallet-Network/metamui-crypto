//! Parallel batch processor implementation with work-stealing and CPU/GPU scheduling

use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::Duration;
use thiserror::Error;
use rayon::prelude::*;

use super::memory_pool::MemoryPool;
use crate::backend::{Backend, BackendEnum};
use crate::{Keypair, PublicKey, SecretKey, Ciphertext, SharedSecret};
use crate::{RngCore, CryptoRng};

/// Error types for parallel processing
#[derive(Debug, Error)]
pub enum ParallelError {
    #[error("Thread pool error: {0}")]
    ThreadPoolError(String),
    
    #[error("Scheduling error: {0}")]
    SchedulingError(String),
    
    #[error("Work item execution failed: {0}")]
    ExecutionError(String),
    
    #[error("Hardware acceleration unavailable")]
    HardwareUnavailable,
    
    #[error("Operation cancelled")]
    Cancelled,
    
    #[error("Backend error: {0}")]
    BackendError(String),
}

/// Result type for parallel operations
pub type Result<T> = std::result::Result<T, ParallelError>;

/// Processing mode for batch operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessingMode {
    /// Use CPU only
    CpuOnly,
    /// Use GPU only (if available)
    GpuOnly,
    /// Automatically choose best mode
    Auto,
    /// Use both CPU and GPU in parallel
    Hybrid {
        /// Percentage of work for GPU (0-100)
        gpu_percentage: u8,
    },
}

/// Batch statistics for performance monitoring
#[derive(Debug, Default, Clone)]
pub struct BatchStatistics {
    /// Total operations performed
    pub total_operations: usize,
    /// Operations executed on CPU
    pub cpu_operations: usize,
    /// Operations executed on GPU
    pub gpu_operations: usize,
    /// Average CPU operation time (microseconds)
    pub avg_cpu_time_us: f64,
    /// Average GPU operation time (microseconds)
    pub avg_gpu_time_us: f64,
    /// Total processing time
    pub total_time: Duration,
}

/// Parallel batch processor with work-stealing scheduler
pub struct ParallelBatchProcessor {
    /// Number of worker threads
    num_threads: usize,
    /// Memory pool for efficient allocation
    memory_pool: Arc<MemoryPool>,
    /// Processing mode
    mode: ProcessingMode,
    /// Backend for operations
    backend: Arc<BackendEnum>,
    /// Statistics
    stats: Arc<Mutex<BatchStatistics>>,
    /// Cancellation flag
    cancel_flag: Arc<AtomicBool>,
}

impl ParallelBatchProcessor {
    /// Create a new parallel batch processor
    pub fn new(
        backend: Arc<BackendEnum>,
        memory_pool: Arc<MemoryPool>,
        mode: ProcessingMode,
    ) -> Self {
        let num_threads = num_cpus::get();
        
        Self {
            num_threads,
            memory_pool,
            mode,
            backend,
            stats: Arc::new(Mutex::new(BatchStatistics::default())),
            cancel_flag: Arc::new(AtomicBool::new(false)),
        }
    }
    
    /// Set processing mode
    pub fn set_mode(&mut self, mode: ProcessingMode) {
        self.mode = mode;
    }
    
    /// Cancel ongoing operations
    pub fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::Relaxed);
    }
    
    /// Reset cancellation flag
    pub fn reset_cancel(&self) {
        self.cancel_flag.store(false, Ordering::Relaxed);
    }
    
    /// Check if operations are cancelled
    pub fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(Ordering::Relaxed)
    }
    
    /// Get current statistics
    pub fn statistics(&self) -> BatchStatistics {
        self.stats.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    
    /// Clear statistics
    pub fn clear_statistics(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            *stats = BatchStatistics::default();
        }
    }
    
    /// Parallel keygen operation
    pub fn parallel_keygen<R>(&self, count: usize, rng: &mut R) -> Result<Vec<Keypair>>
    where
        R: RngCore + CryptoRng,
    {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        
        // Generate seeds for each thread
        let mut seeds = Vec::with_capacity(count);
        for _ in 0..count {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            seeds.push(seed);
        }
        
        // Clone backend for parallel use
        let backend = self.backend.clone();
        
        // Parallel generation
        let results: std::result::Result<Vec<_>, _> = seeds
            .par_iter()
            .map(|seed| {
                let mut local_rng = ChaCha20Rng::from_seed(*seed);
                Backend::keygen(&*backend, &mut local_rng)
                    .map_err(|e| ParallelError::BackendError(e.to_string()))
            })
            .collect();
        
        results
    }
    
    /// Parallel encapsulate operation  
    pub fn parallel_encapsulate<R>(
        &self,
        public_keys: &[PublicKey],
        rng: &mut R,
    ) -> Result<Vec<(Ciphertext, SharedSecret)>>
    where
        R: RngCore + CryptoRng,
    {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        
        // Generate seeds for each operation
        let mut seeds = Vec::with_capacity(public_keys.len());
        for _ in 0..public_keys.len() {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            seeds.push(seed);
        }
        
        // Clone backend for parallel use
        let backend = self.backend.clone();
        
        // Parallel encapsulation
        let results: std::result::Result<Vec<_>, _> = public_keys
            .par_iter()
            .zip(seeds.par_iter())
            .map(|(pk, seed)| {
                let mut local_rng = ChaCha20Rng::from_seed(*seed);
                Backend::encapsulate(&*backend, pk, &mut local_rng)
                    .map_err(|e| ParallelError::BackendError(e.to_string()))
            })
            .collect();
        
        results
    }
    
    /// Parallel decapsulate operation
    pub fn parallel_decapsulate(
        &self,
        secret_keys: &[SecretKey],
        ciphertexts: &[Ciphertext],
    ) -> Result<Vec<SharedSecret>> {
        if secret_keys.len() != ciphertexts.len() {
            return Err(ParallelError::ExecutionError(
                "Mismatched number of secret keys and ciphertexts".into()
            ));
        }
        
        // Clone backend for parallel use
        let backend = self.backend.clone();
        
        // Parallel decapsulation
        let results: std::result::Result<Vec<_>, _> = secret_keys
            .par_iter()
            .zip(ciphertexts.par_iter())
            .map(|(sk, ct)| {
                Backend::decapsulate(&*backend, sk, ct)
                    .map_err(|e| ParallelError::BackendError(e.to_string()))
            })
            .collect();
        
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    
    #[test]
    fn test_processing_modes() {
        let mode = ProcessingMode::Hybrid { gpu_percentage: 30 };
        
        match mode {
            ProcessingMode::Hybrid { gpu_percentage } => {
                assert_eq!(gpu_percentage, 30);
            }
            _ => panic!("Wrong mode"),
        }
    }
    
    #[test]
    fn test_parallel_processor_creation() {
        let backend = Arc::new(BackendEnum::Reference(
            crate::backend::reference::ReferenceBackend::new()
        ));
        let memory_pool = Arc::new(MemoryPool::default());
        let processor = ParallelBatchProcessor::new(
            backend,
            memory_pool,
            ProcessingMode::CpuOnly,
        );
        
        assert_eq!(processor.num_threads, num_cpus::get());
        assert!(!processor.is_cancelled());
    }
}