//! Memory pool management for efficient allocation
//!
//! Thread-safe and thread-local memory pools optimized for ML-KEM polynomial operations.
//! Provides zero-copy operations, cache-aligned allocations, and batch processing support.

use std::sync::Arc;
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::{Mutex, RwLock};
use once_cell::sync::Lazy;

/// ML-KEM polynomial size (256 coefficients)
pub const POLY_SIZE: usize = 256;

/// Cache line size for alignment
pub const CACHE_LINE_SIZE: usize = 64;

/// Maximum pool size per thread
const MAX_POOL_SIZE: usize = 64;

/// Statistics for memory pool usage
#[derive(Debug, Default, Clone)]
pub struct PoolStats {
    pub total_allocations: usize,
    pub total_deallocations: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub current_pool_size: usize,
    pub peak_pool_size: usize,
}

/// Global pool statistics
static GLOBAL_STATS: Lazy<RwLock<PoolStats>> = Lazy::new(|| RwLock::new(PoolStats::default()));

/// Aligned buffer for polynomial coefficients
#[repr(C, align(64))]
pub struct AlignedPolyBuffer {
    coeffs: [i16; POLY_SIZE],
}

impl AlignedPolyBuffer {
    /// Create a new zero-initialized buffer
    #[inline]
    pub fn new() -> Self {
        Self { coeffs: [0; POLY_SIZE] }
    }
    
    /// Get coefficients as slice
    #[inline]
    pub fn as_slice(&self) -> &[i16] {
        &self.coeffs
    }
    
    /// Get coefficients as mutable slice
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [i16] {
        &mut self.coeffs
    }
}

/// Buffer handle for RAII memory management
pub struct BufferHandle {
    ptr: NonNull<AlignedPolyBuffer>,
    pool: Arc<MemoryPool>,
}

impl BufferHandle {
    /// Get the buffer
    #[inline]
    pub fn get(&self) -> &AlignedPolyBuffer {
        unsafe { self.ptr.as_ref() }
    }
    
    /// Get the buffer mutably
    #[inline]
    pub fn get_mut(&mut self) -> &mut AlignedPolyBuffer {
        unsafe { self.ptr.as_mut() }
    }
    
    /// Convert to raw pointer (ownership transfer)
    #[inline]
    pub fn into_raw(self) -> *mut AlignedPolyBuffer {
        let ptr = self.ptr.as_ptr();
        std::mem::forget(self);
        ptr
    }
}

impl Drop for BufferHandle {
    fn drop(&mut self) {
        self.pool.release_raw(self.ptr);
    }
}

impl std::ops::Deref for BufferHandle {
    type Target = AlignedPolyBuffer;
    
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl std::ops::DerefMut for BufferHandle {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

/// Thread-safe memory pool for polynomial buffers
pub struct MemoryPool {
    buffers: Mutex<VecDeque<NonNull<AlignedPolyBuffer>>>,
    buffer_size: usize,
    max_capacity: usize,
    allocated_count: AtomicUsize,
    stats: RwLock<PoolStats>,
}

impl MemoryPool {
    /// Create a new memory pool
    pub fn new(buffer_size: usize, initial_capacity: usize, max_capacity: usize) -> Arc<Self> {
        let pool = Arc::new(Self {
            buffers: Mutex::new(VecDeque::with_capacity(initial_capacity)),
            buffer_size,
            max_capacity,
            allocated_count: AtomicUsize::new(0),
            stats: RwLock::new(PoolStats::default()),
        });
        
        // Pre-allocate initial buffers
        {
            let mut buffers = pool.buffers.lock();
            for _ in 0..initial_capacity {
                let buffer = Self::allocate_aligned_buffer();
                buffers.push_back(buffer);
            }
        }
        pool.allocated_count.store(initial_capacity, Ordering::Relaxed);
        
        pool
    }
    
    /// Allocate an aligned buffer
    fn allocate_aligned_buffer() -> NonNull<AlignedPolyBuffer> {
        unsafe {
            let layout = Layout::from_size_align(
                std::mem::size_of::<AlignedPolyBuffer>(),
                CACHE_LINE_SIZE
            ).unwrap();
            
            let ptr = alloc(layout) as *mut AlignedPolyBuffer;
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            
            // Zero-initialize
            ptr::write_bytes(ptr, 0, 1);
            
            NonNull::new_unchecked(ptr)
        }
    }
    
    /// Deallocate an aligned buffer
    unsafe fn deallocate_aligned_buffer(ptr: NonNull<AlignedPolyBuffer>) {
        let layout = Layout::from_size_align(
            std::mem::size_of::<AlignedPolyBuffer>(),
            CACHE_LINE_SIZE
        ).unwrap();
        
        dealloc(ptr.as_ptr() as *mut u8, layout);
    }
    
    /// Acquire a buffer from the pool
    pub fn acquire(self: &Arc<Self>) -> BufferHandle {
        let mut stats = self.stats.write();
        stats.total_allocations += 1;
        
        let ptr = {
            let mut buffers = self.buffers.lock();
            if let Some(buffer) = buffers.pop_front() {
                stats.cache_hits += 1;
                buffer
            } else {
                stats.cache_misses += 1;
                drop(buffers);
                
                // Allocate new buffer
                self.allocated_count.fetch_add(1, Ordering::Relaxed);
                Self::allocate_aligned_buffer()
            }
        };
        
        // Update global stats
        GLOBAL_STATS.write().total_allocations += 1;
        
        BufferHandle {
            ptr,
            pool: Arc::clone(self),
        }
    }
    
    /// Release a raw buffer back to the pool
    fn release_raw(&self, ptr: NonNull<AlignedPolyBuffer>) {
        let mut stats = self.stats.write();
        stats.total_deallocations += 1;
        
        // Clear the buffer (security consideration for crypto)
        unsafe {
            ptr::write_bytes(ptr.as_ptr(), 0, 1);
        }
        
        let mut buffers = self.buffers.lock();
        
        // Check if we should return to pool or deallocate
        if buffers.len() < self.max_capacity {
            buffers.push_back(ptr);
            stats.current_pool_size = buffers.len();
            if stats.current_pool_size > stats.peak_pool_size {
                stats.peak_pool_size = stats.current_pool_size;
            }
        } else {
            // Pool is full, deallocate
            drop(buffers);
            unsafe {
                Self::deallocate_aligned_buffer(ptr);
            }
            self.allocated_count.fetch_sub(1, Ordering::Relaxed);
        }
        
        GLOBAL_STATS.write().total_deallocations += 1;
    }
    
    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        self.stats.read().clone()
    }
    
    /// Clear the pool
    pub fn clear(&self) {
        let mut buffers = self.buffers.lock();
        while let Some(ptr) = buffers.pop_front() {
            unsafe {
                Self::deallocate_aligned_buffer(ptr);
            }
        }
        self.allocated_count.store(0, Ordering::Relaxed);
    }
}

impl Drop for MemoryPool {
    fn drop(&mut self) {
        self.clear();
    }
}

unsafe impl Send for MemoryPool {}
unsafe impl Sync for MemoryPool {}

/// Thread-local memory pool for zero-contention access
pub struct ThreadLocalPool {
    buffers: RefCell<VecDeque<Box<AlignedPolyBuffer>>>,
    max_capacity: usize,
    stats: RefCell<PoolStats>,
}

thread_local! {
    /// Thread-local pool instance
    static LOCAL_POOL: RefCell<ThreadLocalPool> = RefCell::new(ThreadLocalPool::new(MAX_POOL_SIZE));
}

impl ThreadLocalPool {
    /// Create a new thread-local pool
    pub fn new(max_capacity: usize) -> Self {
        Self {
            buffers: RefCell::new(VecDeque::with_capacity(max_capacity)),
            max_capacity,
            stats: RefCell::new(PoolStats::default()),
        }
    }
    
    /// Acquire a buffer from the thread-local pool
    pub fn acquire() -> Box<AlignedPolyBuffer> {
        LOCAL_POOL.with(|pool| {
            let pool = pool.borrow();
            let mut stats = pool.stats.borrow_mut();
            stats.total_allocations += 1;
            
            let mut buffers = pool.buffers.borrow_mut();
            if let Some(mut buffer) = buffers.pop_front() {
                stats.cache_hits += 1;
                // Clear buffer for security
                buffer.coeffs.fill(0);
                buffer
            } else {
                stats.cache_misses += 1;
                Box::new(AlignedPolyBuffer::new())
            }
        })
    }
    
    /// Release a buffer back to the thread-local pool
    pub fn release(mut buffer: Box<AlignedPolyBuffer>) {
        LOCAL_POOL.with(|pool| {
            let pool = pool.borrow();
            let mut stats = pool.stats.borrow_mut();
            stats.total_deallocations += 1;
            
            // Clear buffer for security
            buffer.coeffs.fill(0);
            
            let mut buffers = pool.buffers.borrow_mut();
            if buffers.len() < pool.max_capacity {
                buffers.push_back(buffer);
                stats.current_pool_size = buffers.len();
                if stats.current_pool_size > stats.peak_pool_size {
                    stats.peak_pool_size = stats.current_pool_size;
                }
            }
            // If pool is full, buffer is dropped
        })
    }
    
    /// Get thread-local statistics
    pub fn stats() -> PoolStats {
        LOCAL_POOL.with(|pool| pool.borrow().stats.borrow().clone())
    }
    
    /// Clear the thread-local pool
    pub fn clear() {
        LOCAL_POOL.with(|pool| {
            pool.borrow().buffers.borrow_mut().clear();
            *pool.borrow().stats.borrow_mut() = PoolStats::default();
        })
    }
}

/// Batch buffer allocation for vectorized operations
pub struct BatchBufferPool {
    pool: Arc<MemoryPool>,
    batch_size: usize,
}

impl BatchBufferPool {
    /// Create a new batch buffer pool
    pub fn new(batch_size: usize) -> Self {
        let pool = MemoryPool::new(
            POLY_SIZE * std::mem::size_of::<i16>(),
            batch_size * 2,
            batch_size * 4,
        );
        
        Self { pool, batch_size }
    }
    
    /// Acquire a batch of buffers
    pub fn acquire_batch(&self, count: usize) -> Vec<BufferHandle> {
        (0..count).map(|_| self.pool.acquire()).collect()
    }
    
    /// Process buffers in parallel batches
    pub fn process_batch<F>(&self, count: usize, mut f: F)
    where
        F: FnMut(&mut [BufferHandle]),
    {
        let mut handles = self.acquire_batch(count);
        f(&mut handles);
        // Handles are automatically released when dropped
    }
}

/// Get available system memory in MB
pub fn available_memory_mb() -> usize {
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
    
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("vm_stat").output() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                let mut free_pages = 0usize;
                for line in text.lines() {
                    if line.contains("Pages free:") {
                        if let Some(pages) = line.split(':').nth(1) {
                            if let Ok(n) = pages.trim().trim_end_matches('.').parse::<usize>() {
                                free_pages = n;
                                // Each page is 4096 bytes on macOS
                                return (free_pages * 4096) / (1024 * 1024);
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Default fallback
    512
}

/// Get global pool statistics
pub fn get_global_stats() -> PoolStats {
    GLOBAL_STATS.read().clone()
}

/// Reset global pool statistics
pub fn reset_global_stats() {
    *GLOBAL_STATS.write() = PoolStats::default();
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_pool() {
        let pool = MemoryPool::new(POLY_SIZE * 2, 4, 16);
        
        // Acquire and release buffers
        let mut handles = Vec::new();
        for _ in 0..10 {
            handles.push(pool.acquire());
        }
        
        // Check stats
        let stats = pool.stats();
        assert_eq!(stats.total_allocations, 10);
        
        // Release by dropping
        handles.clear();
        
        // Acquire again should hit cache
        let handle = pool.acquire();
        let stats = pool.stats();
        assert!(stats.cache_hits > 0);
    }
    
    #[test]
    fn test_thread_local_pool() {
        // Clear pool first
        ThreadLocalPool::clear();
        
        // Acquire buffers
        let mut buffers = Vec::new();
        for _ in 0..5 {
            buffers.push(ThreadLocalPool::acquire());
        }
        
        // Release buffers
        for buffer in buffers {
            ThreadLocalPool::release(buffer);
        }
        
        // Check stats
        let stats = ThreadLocalPool::stats();
        assert_eq!(stats.total_allocations, 5);
        assert_eq!(stats.total_deallocations, 5);
    }
    
    #[test]
    fn test_batch_pool() {
        let batch_pool = BatchBufferPool::new(8);
        
        batch_pool.process_batch(4, |handles| {
            assert_eq!(handles.len(), 4);
            for handle in handles {
                // Verify alignment
                let ptr = handle.get() as *const _ as usize;
                assert_eq!(ptr % CACHE_LINE_SIZE, 0);
            }
        });
    }
    
    #[test]
    fn test_buffer_alignment() {
        let buffer = AlignedPolyBuffer::new();
        let ptr = &buffer as *const _ as usize;
        assert_eq!(ptr % CACHE_LINE_SIZE, 0, "Buffer should be cache-aligned");
    }
}