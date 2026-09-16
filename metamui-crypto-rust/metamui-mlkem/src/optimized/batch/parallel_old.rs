//! Parallel batch processor implementation with work-stealing and CPU/GPU scheduling
//!
//! This module provides high-performance parallel processing for batch cryptographic
//! operations with intelligent work distribution and hardware acceleration support.

use std::sync::{Arc, Mutex, Condvar, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::collections::VecDeque;
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use crossbeam_channel::{bounded, unbounded, Sender, Receiver, Select};
use rayon::prelude::*;

use super::memory_pool::{MemoryPool, PooledBuffer};
use crate::backend::{Backend, BackendEnum};
use crate::error::MLKemError;

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
        /// Percentage of work to assign to GPU (0-100)
        gpu_percentage: u8,
    },
}

impl Default for ProcessingMode {
    fn default() -> Self {
        Self::Auto
    }
}

/// Work item for the thread pool
struct WorkItem {
    id: usize,
    priority: u8,
    task: Box<dyn FnOnce() -> std::result::Result<(), MLKemError> + Send>,
    result_sender: Sender<WorkResult>,
}

/// Result of a work item execution
struct WorkResult {
    id: usize,
    result: std::result::Result<(), MLKemError>,
    execution_time: Duration,
}

/// Statistics for batch processing
#[derive(Debug, Clone, Default)]
pub struct BatchStatistics {
    /// Total items processed
    pub items_processed: usize,
    /// Items processed on CPU
    pub cpu_items: usize,
    /// Items processed on GPU
    pub gpu_items: usize,
    /// Total processing time
    pub total_time: Duration,
    /// Average time per item
    pub avg_time_per_item: Duration,
    /// Memory pool hits
    pub memory_pool_hits: usize,
    /// Memory pool misses
    pub memory_pool_misses: usize,
}

/// Work-stealing thread pool for parallel execution
struct ThreadPool {
    workers: Vec<Worker>,
    sender: Sender<WorkItem>,
    shutdown: Arc<AtomicBool>,
}

impl ThreadPool {
    /// Create a new thread pool with specified number of workers
    fn new(num_workers: usize) -> Self {
        let (sender, receiver) = unbounded();
        let receiver = Arc::new(Mutex::new(receiver));
        let shutdown = Arc::new(AtomicBool::new(false));
        
        let mut workers = Vec::with_capacity(num_workers);
        
        for id in 0..num_workers {
            workers.push(Worker::new(
                id,
                Arc::clone(&receiver),
                Arc::clone(&shutdown),
            ));
        }
        
        Self {
            workers,
            sender,
            shutdown,
        }
    }
    
    /// Submit work to the pool
    fn submit(&self, item: WorkItem) -> Result<()> {
        self.sender
            .send(item)
            .map_err(|e| ParallelError::ThreadPoolError(format!("Failed to submit work: {}", e)))
    }
    
    /// Shutdown the thread pool
    fn shutdown(self) {
        self.shutdown.store(true, Ordering::Release);
        drop(self.sender);
        
        for worker in self.workers {
            if let Some(thread) = worker.thread {
                let _ = thread.join();
            }
        }
    }
}

/// Worker thread in the pool
struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    fn new(
        id: usize,
        receiver: Arc<Mutex<Receiver<WorkItem>>>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let thread = thread::spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                let item = {
                    let rx = receiver.lock().unwrap();
                    rx.recv_timeout(Duration::from_millis(100))
                };
                
                if let Ok(item) = item {
                    let start = Instant::now();
                    let result = (item.task)();
                    let execution_time = start.elapsed();
                    
                    let _ = item.result_sender.send(WorkResult {
                        id: item.id,
                        result,
                        execution_time,
                    });
                }
            }
        });
        
        Self {
            id,
            thread: Some(thread),
        }
    }
}

/// Parallel batch processor for ML-KEM operations
pub struct ParallelBatchProcessor {
    mode: ProcessingMode,
    memory_pool: Arc<MemoryPool>,
    thread_pool: Option<ThreadPool>,
    backend: BackendEnum,
    stats: Arc<Mutex<BatchStatistics>>,
    max_parallel_items: usize,
}

impl ParallelBatchProcessor {
    /// Create a new parallel batch processor
    pub fn new(mode: ProcessingMode) -> Self {
        let num_threads = match mode {
            ProcessingMode::CpuOnly | ProcessingMode::Auto => {
                num_cpus::get()
            }
            ProcessingMode::GpuOnly => 1,
            ProcessingMode::Hybrid { .. } => num_cpus::get(),
        };
        
        Self {
            mode,
            memory_pool: Arc::new(MemoryPool::default()),
            thread_pool: Some(ThreadPool::new(num_threads)),
            backend: BackendEnum::Reference(crate::backend::reference::ReferenceBackend::new()),
            stats: Arc::new(Mutex::new(BatchStatistics::default())),
            max_parallel_items: 1000,
        }
    }
    
    /// Create with specific configuration
    pub fn with_config(
        mode: ProcessingMode,
        max_memory: usize,
        num_threads: Option<usize>,
    ) -> Self {
        let num_threads = num_threads.unwrap_or_else(num_cpus::get);
        
        Self {
            mode,
            memory_pool: Arc::new(MemoryPool::new(max_memory)),
            thread_pool: Some(ThreadPool::new(num_threads)),
            backend: BackendEnum::Reference(crate::backend::reference::ReferenceBackend::new()),
            stats: Arc::new(Mutex::new(BatchStatistics::default())),
            max_parallel_items: 1000,
        }
    }
    
    /// Set processing mode
    pub fn set_mode(&mut self, mode: ProcessingMode) {
        self.mode = mode;
    }
    
    /// Get current processing mode
    pub fn mode(&self) -> ProcessingMode {
        self.mode
    }
    
    /// Process items in parallel using Rayon
    pub fn process_batch<T, F>(
        &self,
        items: Vec<T>,
        processor: F,
    ) -> Result<Vec<std::result::Result<(), MLKemError>>>
    where
        T: Send + Sync,
        F: Fn(&T) -> std::result::Result<(), MLKemError> + Send + Sync,
    {
        let start = Instant::now();
        
        // Determine processing strategy based on mode
        let (cpu_items, gpu_items) = self.split_work(&items);
        
        // Process CPU items in parallel using Rayon
        let cpu_results: Vec<_> = cpu_items
            .par_iter()
            .map(|item| {
                let _buffer = self.memory_pool.acquire(4096).ok();
                processor(item)
            })
            .collect();
        
        // Process GPU items if applicable
        let gpu_results = if !gpu_items.is_empty() {
            #[cfg(feature = "gpu")]
            {
                self.process_gpu_batch(gpu_items, &processor)?
            }
            #[cfg(not(feature = "gpu"))]
            {
                gpu_items
                    .par_iter()
                    .map(|item| processor(item))
                    .collect()
            }
        } else {
            Vec::new()
        };
        
        // Combine results
        let mut all_results = cpu_results;
        all_results.extend(gpu_results);
        
        // Update statistics
        if let Ok(mut stats) = self.stats.lock() {
            stats.items_processed += items.len();
            stats.cpu_items += cpu_items.len();
            stats.gpu_items += gpu_items.len();
            stats.total_time += start.elapsed();
            if stats.items_processed > 0 {
                stats.avg_time_per_item = stats.total_time / stats.items_processed as u32;
            }
        }
        
        Ok(all_results)
    }
    
    /// Process batch with custom thread pool
    pub fn process_batch_custom<T, F>(
        &self,
        items: Vec<T>,
        processor: F,
    ) -> Result<Vec<std::result::Result<(), MLKemError>>>
    where
        T: Send + 'static,
        F: Fn(T) -> std::result::Result<(), MLKemError> + Send + Sync + Clone + 'static,
    {
        let pool = self.thread_pool.as_ref()
            .ok_or_else(|| ParallelError::ThreadPoolError("Thread pool not initialized".into()))?;
            
        let (result_sender, result_receiver) = bounded(items.len());
        let num_items = items.len();
        
        // Submit work items
        for (id, item) in items.into_iter().enumerate() {
            let processor = processor.clone();
            let sender = result_sender.clone();
            
            pool.submit(WorkItem {
                id,
                priority: 0,
                task: Box::new(move || processor(item)),
                result_sender: sender,
            })?;
        }
        
        // Collect results
        let mut results = vec![Ok(()); num_items];
        for _ in 0..num_items {
            let work_result = result_receiver
                .recv_timeout(Duration::from_secs(30))
                .map_err(|e| ParallelError::ExecutionError(format!("Timeout waiting for result: {}", e)))?;
                
            results[work_result.id] = work_result.result;
        }
        
        Ok(results)
    }
    
    /// Split work between CPU and GPU based on mode
    fn split_work<'a, T>(&self, items: &'a [T]) -> (&'a [T], &'a [T]) {
        match self.mode {
            ProcessingMode::CpuOnly => (items, &[]),
            ProcessingMode::GpuOnly => (&[], items),
            ProcessingMode::Auto => {
                // Simple heuristic: use GPU for large batches
                if items.len() > 100 {
                    let split_point = items.len() / 2;
                    items.split_at(split_point)
                } else {
                    (items, &[])
                }
            }
            ProcessingMode::Hybrid { gpu_percentage } => {
                let gpu_count = (items.len() * gpu_percentage as usize) / 100;
                let (gpu_items, cpu_items) = items.split_at(gpu_count.min(items.len()));
                (cpu_items, gpu_items)
            }
        }
    }
    
    /// Process items on GPU (placeholder for actual GPU implementation)
    #[cfg(feature = "gpu")]
    fn process_gpu_batch<T, F>(
        &self,
        items: &[T],
        processor: &F,
    ) -> Result<Vec<std::result::Result<(), MLKemError>>>
    where
        T: Send + Sync,
        F: Fn(&T) -> std::result::Result<(), MLKemError> + Send + Sync,
    {
        // This would contain actual GPU processing logic
        // For now, fall back to CPU processing
        Ok(items
            .par_iter()
            .map(|item| processor(item))
            .collect())
    }
    
    /// Get processing statistics
    pub fn statistics(&self) -> BatchStatistics {
        self.stats.lock().unwrap().clone()
    }
    
    /// Clear statistics
    pub fn clear_statistics(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            *stats = BatchStatistics::default();
        }
    }
    
    /// Parallel keygen operation
    pub fn parallel_keygen<R>(&self, count: usize, rng: &mut R) -> Result<Vec<Keypair>, ParallelError>
    where
        R: RngCore + CryptoRng + Send + Sync,
    {
        use rayon::prelude::*;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        
        // Generate seeds for each thread
        let mut seeds = Vec::with_capacity(count);
        for _ in 0..count {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            seeds.push(seed);
        }
        
        // Parallel generation
        let results: Result<Vec<_>, _> = seeds
            .par_iter()
            .map(|seed| {
                let mut local_rng = ChaCha20Rng::from_seed(*seed);
                self.backend.keygen(&mut local_rng)
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
    ) -> Result<Vec<(Ciphertext, SharedSecret)>, ParallelError>
    where
        R: RngCore + CryptoRng + Send + Sync,
    {
        use rayon::prelude::*;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        
        // Generate seeds for each operation
        let mut seeds = Vec::with_capacity(public_keys.len());
        for _ in 0..public_keys.len() {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            seeds.push(seed);
        }
        
        // Parallel encapsulation
        let results: Result<Vec<_>, _> = public_keys
            .par_iter()
            .zip(seeds.par_iter())
            .map(|(pk, seed)| {
                let mut local_rng = ChaCha20Rng::from_seed(*seed);
                self.backend.encapsulate(pk, &mut local_rng)
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
    ) -> Result<Vec<SharedSecret>, ParallelError> {
        use rayon::prelude::*;
        
        if secret_keys.len() != ciphertexts.len() {
            return Err(ParallelError::BackendError("Mismatched input lengths".to_string()));
        }
        
        // Parallel decapsulation
        let results: Result<Vec<_>, _> = secret_keys
            .par_iter()
            .zip(ciphertexts.par_iter())
            .map(|(sk, ct)| {
                self.backend.decapsulate(sk, ct)
                    .map_err(|e| ParallelError::BackendError(e.to_string()))
            })
            .collect();
        
        results
    }
    
    /// Shutdown the processor
    pub fn shutdown(mut self) {
        if let Some(pool) = self.thread_pool.take() {
            pool.shutdown();
        }
    }
}

impl Drop for ParallelBatchProcessor {
    fn drop(&mut self) {
        if let Some(pool) = self.thread_pool.take() {
            pool.shutdown();
        }
    }
}

/// Adaptive scheduler that dynamically adjusts processing strategy
pub struct AdaptiveScheduler {
    processor: ParallelBatchProcessor,
    performance_history: VecDeque<(ProcessingMode, f64)>,
    current_mode: ProcessingMode,
}

impl AdaptiveScheduler {
    /// Create a new adaptive scheduler
    pub fn new() -> Self {
        Self {
            processor: ParallelBatchProcessor::new(ProcessingMode::Auto),
            performance_history: VecDeque::with_capacity(10),
            current_mode: ProcessingMode::Auto,
        }
    }
    
    /// Process batch with adaptive mode selection
    pub fn process_adaptive<T, F>(
        &mut self,
        items: Vec<T>,
        processor: F,
    ) -> Result<Vec<std::result::Result<(), MLKemError>>>
    where
        T: Send + Sync + Clone,
        F: Fn(&T) -> std::result::Result<(), MLKemError> + Send + Sync,
    {
        // Try different modes and measure performance
        if self.performance_history.len() < 3 {
            self.benchmark_modes(&items[..items.len().min(10)], &processor);
        }
        
        // Select best mode based on history
        self.current_mode = self.select_best_mode();
        self.processor.set_mode(self.current_mode);
        
        // Process with selected mode
        let start = Instant::now();
        let results = self.processor.process_batch(items, processor)?;
        let throughput = results.len() as f64 / start.elapsed().as_secs_f64();
        
        // Update history
        self.performance_history.push_back((self.current_mode, throughput));
        if self.performance_history.len() > 10 {
            self.performance_history.pop_front();
        }
        
        Ok(results)
    }
    
    /// Benchmark different processing modes
    fn benchmark_modes<T, F>(&mut self, sample_items: &[T], processor: &F)
    where
        T: Send + Sync + Clone,
        F: Fn(&T) -> std::result::Result<(), MLKemError> + Send + Sync,
    {
        for mode in &[ProcessingMode::CpuOnly, ProcessingMode::Auto] {
            self.processor.set_mode(*mode);
            
            let start = Instant::now();
            if let Ok(results) = self.processor.process_batch(sample_items.to_vec(), processor) {
                let throughput = results.len() as f64 / start.elapsed().as_secs_f64();
                self.performance_history.push_back((*mode, throughput));
            }
        }
    }
    
    /// Select best mode based on performance history
    fn select_best_mode(&self) -> ProcessingMode {
        let mut mode_performance: std::collections::HashMap<ProcessingMode, Vec<f64>> = 
            std::collections::HashMap::new();
            
        for (mode, throughput) in &self.performance_history {
            mode_performance
                .entry(*mode)
                .or_default()
                .push(*throughput);
        }
        
        mode_performance
            .into_iter()
            .max_by(|(_, a), (_, b)| {
                let avg_a: f64 = a.iter().sum::<f64>() / a.len() as f64;
                let avg_b: f64 = b.iter().sum::<f64>() / b.len() as f64;
                avg_a.partial_cmp(&avg_b).unwrap()
            })
            .map(|(mode, _)| mode)
            .unwrap_or(ProcessingMode::Auto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_processing_mode_default() {
        assert_eq!(ProcessingMode::default(), ProcessingMode::Auto);
    }
    
    #[test]
    fn test_parallel_processor_creation() {
        let processor = ParallelBatchProcessor::new(ProcessingMode::CpuOnly);
        assert_eq!(processor.mode(), ProcessingMode::CpuOnly);
    }
    
    #[test]
    fn test_batch_processing() {
        let processor = ParallelBatchProcessor::new(ProcessingMode::CpuOnly);
        let items: Vec<i32> = (0..100).collect();
        
        let results = processor.process_batch(items, |_item| {
            Ok(())
        }).unwrap();
        
        assert_eq!(results.len(), 100);
        for result in results {
            assert!(result.is_ok());
        }
    }
    
    #[test]
    fn test_work_splitting() {
        let processor = ParallelBatchProcessor::new(ProcessingMode::Hybrid { gpu_percentage: 30 });
        let items: Vec<i32> = (0..100).collect();
        
        let (cpu_items, gpu_items) = processor.split_work(&items);
        assert_eq!(cpu_items.len(), 70);
        assert_eq!(gpu_items.len(), 30);
    }
    
    #[test]
    fn test_statistics() {
        let processor = ParallelBatchProcessor::new(ProcessingMode::CpuOnly);
        let items: Vec<i32> = (0..50).collect();
        
        let _ = processor.process_batch(items, |_| Ok(())).unwrap();
        
        let stats = processor.statistics();
        assert_eq!(stats.items_processed, 50);
        assert_eq!(stats.cpu_items, 50);
        assert_eq!(stats.gpu_items, 0);
    }
    
    #[test]
    fn test_adaptive_scheduler() {
        let mut scheduler = AdaptiveScheduler::new();
        let items: Vec<i32> = (0..100).collect();
        
        let results = scheduler.process_adaptive(items, |_item| {
            Ok(())
        }).unwrap();
        
        assert_eq!(results.len(), 100);
    }
}