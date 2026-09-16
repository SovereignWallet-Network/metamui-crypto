//! Batch executor with intelligent CPU/GPU scheduling
//!
//! This module implements automatic workload distribution based on batch size
//! and available hardware capabilities.

use crate::backend::BackendEnum;
use super::BatchOperation;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

/// Execution strategy for batch operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStrategy {
    /// Process serially on CPU (small batches)
    Serial,
    /// Process in parallel on CPU (medium batches)
    Parallel,
    /// Offload to GPU (large batches)
    Gpu,
    /// Use both CPU and GPU (very large batches)
    Hybrid,
}

/// Batch processing configuration
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Threshold for switching to parallel processing
    pub parallel_threshold: usize,
    /// Threshold for switching to GPU processing
    pub gpu_threshold: usize,
    /// Threshold for hybrid CPU+GPU processing
    pub hybrid_threshold: usize,
    /// Maximum chunk size for parallel processing
    pub max_chunk_size: usize,
    /// Memory pool size in MB
    pub memory_pool_size: usize,
    /// Enable adaptive scheduling
    pub adaptive_scheduling: bool,
    /// GPU memory limit in MB
    pub gpu_memory_limit: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            parallel_threshold: 10,
            gpu_threshold: 100,
            hybrid_threshold: 1000,
            max_chunk_size: 64,
            memory_pool_size: 256,
            adaptive_scheduling: true,
            gpu_memory_limit: 2048,
        }
    }
}

/// Batch executor with automatic scheduling
pub struct BatchExecutor {
    backend: Arc<BackendEnum>,
    config: BatchConfig,
    stats: ExecutorStats,
    #[cfg(feature = "gpu")]
    gpu_backend: Option<Arc<BackendEnum>>,
}

impl BatchExecutor {
    /// Create a new batch executor
    pub fn new(backend: Arc<BackendEnum>, config: BatchConfig) -> Self {
        let gpu_backend = Self::initialize_gpu_backend(&config);
        
        Self {
            backend,
            config,
            stats: ExecutorStats::default(),
            #[cfg(feature = "gpu")]
            gpu_backend,
        }
    }

    /// Determine the best execution strategy for a batch operation
    pub fn determine_strategy(&self, operation: BatchOperation, batch_size: usize) -> ExecutionStrategy {
        // Check available resources
        let has_gpu = self.has_gpu_available();
        let cpu_cores = num_cpus::get();
        
        // Adaptive scheduling based on operation type and size
        if self.config.adaptive_scheduling {
            self.adaptive_strategy(operation, batch_size, has_gpu, cpu_cores)
        } else {
            self.fixed_strategy(batch_size, has_gpu)
        }
    }

    /// Adaptive strategy selection based on runtime metrics
    fn adaptive_strategy(
        &self,
        operation: BatchOperation,
        batch_size: usize,
        has_gpu: bool,
        cpu_cores: usize,
    ) -> ExecutionStrategy {
        // Calculate operation cost
        let op_cost = self.estimate_operation_cost(operation);
        let total_cost = op_cost * batch_size;
        
        // Memory requirements
        let memory_required = self.estimate_memory_requirement(operation, batch_size);
        
        // Decision logic
        if batch_size < self.config.parallel_threshold {
            ExecutionStrategy::Serial
        } else if !has_gpu || memory_required > self.config.gpu_memory_limit * 1024 * 1024 {
            // No GPU or would exceed GPU memory
            if batch_size < self.config.gpu_threshold || cpu_cores >= 8 {
                ExecutionStrategy::Parallel
            } else {
                ExecutionStrategy::Serial
            }
        } else if batch_size >= self.config.hybrid_threshold && cpu_cores >= 4 {
            // Very large batch and enough CPU cores for hybrid
            ExecutionStrategy::Hybrid
        } else if batch_size >= self.config.gpu_threshold {
            // Large batch, use GPU
            ExecutionStrategy::Gpu
        } else if cpu_cores >= 2 {
            // Medium batch with multiple cores
            ExecutionStrategy::Parallel
        } else {
            ExecutionStrategy::Serial
        }
    }

    /// Fixed strategy based on thresholds
    fn fixed_strategy(&self, batch_size: usize, has_gpu: bool) -> ExecutionStrategy {
        if batch_size >= self.config.hybrid_threshold && has_gpu {
            ExecutionStrategy::Hybrid
        } else if batch_size >= self.config.gpu_threshold && has_gpu {
            ExecutionStrategy::Gpu
        } else if batch_size >= self.config.parallel_threshold {
            ExecutionStrategy::Parallel
        } else {
            ExecutionStrategy::Serial
        }
    }

    /// Estimate operation cost in arbitrary units
    fn estimate_operation_cost(&self, operation: BatchOperation) -> usize {
        match operation {
            BatchOperation::Keygen => 1000,      // High cost
            BatchOperation::Encapsulate => 500,  // Medium cost
            BatchOperation::Decapsulate => 400,  // Medium cost
            BatchOperation::NTT => 100,          // Low cost
            BatchOperation::InverseNTT => 100,   // Low cost
            BatchOperation::PolyMul => 150,      // Low-medium cost
            BatchOperation::PolyAdd => 50,       // Very low cost
            BatchOperation::PolySub => 50,       // Very low cost
            BatchOperation::MatrixVectorMul => 300, // Medium cost
        }
    }

    /// Estimate memory requirement in bytes
    fn estimate_memory_requirement(&self, operation: BatchOperation, batch_size: usize) -> usize {
        let per_operation = match operation {
            BatchOperation::Keygen => 32 * 1024,      // 32KB per keygen
            BatchOperation::Encapsulate => 16 * 1024, // 16KB per encap
            BatchOperation::Decapsulate => 16 * 1024, // 16KB per decap
            BatchOperation::NTT => 4 * 1024,          // 4KB per NTT
            BatchOperation::InverseNTT => 4 * 1024,   // 4KB per INTT
            BatchOperation::PolyMul => 8 * 1024,      // 8KB per poly mul
            BatchOperation::PolyAdd => 4 * 1024,      // 4KB per poly add
            BatchOperation::PolySub => 4 * 1024,      // 4KB per poly sub
            BatchOperation::MatrixVectorMul => 12 * 1024, // 12KB per matrix-vec mul
        };
        
        per_operation * batch_size
    }

    /// Check if GPU is available
    fn has_gpu_available(&self) -> bool {
        #[cfg(feature = "gpu")]
        {
            self.gpu_backend.is_some()
        }
        #[cfg(not(feature = "gpu"))]
        {
            false
        }
    }

    /// Initialize GPU backend if available
    fn initialize_gpu_backend(_config: &BatchConfig) -> Option<Arc<BackendEnum>> {
        #[cfg(feature = "gpu")]
        {
            // Try to create GPU backend
            if let Ok(gpu_backend) = crate::gpu::create_gpu_backend() {
                return Some(Arc::new(gpu_backend));
            }
        }
        None
    }

    /// Get GPU backend if available
    #[cfg(feature = "gpu")]
    pub fn get_gpu_backend(&self) -> Option<&Arc<BackendEnum>> {
        self.gpu_backend.as_ref()
    }

    /// Update execution statistics
    pub fn record_execution(&self, strategy: ExecutionStrategy, duration_ms: u64) {
        match strategy {
            ExecutionStrategy::Serial | ExecutionStrategy::Parallel => {
                self.stats.cpu_operations.fetch_add(1, Ordering::Relaxed);
            }
            ExecutionStrategy::Gpu => {
                self.stats.gpu_operations.fetch_add(1, Ordering::Relaxed);
            }
            ExecutionStrategy::Hybrid => {
                self.stats.cpu_operations.fetch_add(1, Ordering::Relaxed);
                self.stats.gpu_operations.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        self.stats.total_operations.fetch_add(1, Ordering::Relaxed);
        self.stats.total_time_ms.fetch_add(duration_ms as usize, Ordering::Relaxed);
    }

    /// Get total operations count
    pub fn total_operations(&self) -> usize {
        self.stats.total_operations.load(Ordering::Relaxed)
    }

    /// Get GPU operations count
    pub fn gpu_operations(&self) -> usize {
        self.stats.gpu_operations.load(Ordering::Relaxed)
    }

    /// Get CPU operations count
    pub fn cpu_operations(&self) -> usize {
        self.stats.cpu_operations.load(Ordering::Relaxed)
    }

    /// Calculate optimal chunk size for parallel processing
    pub fn optimal_chunk_size(&self, total_size: usize) -> usize {
        let cpu_cores = num_cpus::get();
        let base_chunk = total_size / cpu_cores;
        
        // Ensure chunk size is within reasonable bounds
        base_chunk.max(1).min(self.config.max_chunk_size)
    }

    /// Split batch for hybrid processing
    pub fn split_for_hybrid(&self, total_size: usize) -> (usize, usize) {
        // Default split: 75% GPU, 25% CPU
        let gpu_portion = (total_size * 3) / 4;
        let cpu_portion = total_size - gpu_portion;
        
        (gpu_portion, cpu_portion)
    }
}

/// Executor statistics
#[derive(Debug, Default)]
struct ExecutorStats {
    total_operations: AtomicUsize,
    gpu_operations: AtomicUsize,
    cpu_operations: AtomicUsize,
    total_time_ms: AtomicUsize,
    cache_hits: AtomicUsize,
    cache_misses: AtomicUsize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendEnum;

    #[test]
    fn test_strategy_selection() {
        let backend = crate::backend::reference::ReferenceBackend::new();
        let config = BatchConfig::default();
        let executor = BatchExecutor::new(Arc::new(BackendEnum::Reference(backend)), config);
        
        // Test small batch -> Serial
        let strategy = executor.determine_strategy(BatchOperation::Keygen, 5);
        assert_eq!(strategy, ExecutionStrategy::Serial);
        
        // Test medium batch -> Parallel
        let strategy = executor.determine_strategy(BatchOperation::Keygen, 50);
        assert_eq!(strategy, ExecutionStrategy::Parallel);
        
        // Test large batch -> GPU (if available) or Parallel
        let strategy = executor.determine_strategy(BatchOperation::Keygen, 500);
        assert!(matches!(strategy, ExecutionStrategy::Gpu | ExecutionStrategy::Parallel));
    }

    #[test]
    fn test_memory_estimation() {
        let backend = crate::backend::reference::ReferenceBackend::new();
        let config = BatchConfig::default();
        let executor = BatchExecutor::new(Arc::new(BackendEnum::Reference(backend)), config);
        
        let mem = executor.estimate_memory_requirement(BatchOperation::Keygen, 100);
        assert_eq!(mem, 32 * 1024 * 100);
        
        let mem = executor.estimate_memory_requirement(BatchOperation::Encapsulate, 100);
        assert_eq!(mem, 16 * 1024 * 100);
    }

    #[test]
    fn test_optimal_chunk_size() {
        let backend = crate::backend::reference::ReferenceBackend::new();
        let config = BatchConfig::default();
        let executor = BatchExecutor::new(Arc::new(BackendEnum::Reference(backend)), config);
        
        let chunk_size = executor.optimal_chunk_size(1000);
        assert!(chunk_size > 0);
        assert!(chunk_size <= config.max_chunk_size);
    }

    #[test]
    fn test_hybrid_split() {
        let backend = crate::backend::reference::ReferenceBackend::new();
        let config = BatchConfig::default();
        let executor = BatchExecutor::new(Arc::new(BackendEnum::Reference(backend)), config);
        
        let (gpu, cpu) = executor.split_for_hybrid(1000);
        assert_eq!(gpu, 750);
        assert_eq!(cpu, 250);
        assert_eq!(gpu + cpu, 1000);
    }
}