//! Thread-safe memory pool implementation for efficient buffer management
//!
//! This module provides a high-performance memory pool for managing reusable buffers
//! in batch cryptographic operations, reducing allocation overhead and improving cache locality.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};
use std::sync::atomic::{AtomicUsize, Ordering};
use thiserror::Error;

/// Error types for memory pool operations
#[derive(Debug, Error)]
pub enum MemoryPoolError {
    #[error("Memory pool exhausted: requested {requested} bytes, available {available} bytes")]
    PoolExhausted { requested: usize, available: usize },
    
    #[error("Invalid buffer size: {0} bytes")]
    InvalidSize(usize),
    
    #[error("Pool already shutdown")]
    PoolShutdown,
}

/// Result type for memory pool operations
pub type Result<T> = std::result::Result<T, MemoryPoolError>;

/// Buffer size categories for the memory pool
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BufferSize {
    /// Small buffers (4KB)
    Small,
    /// Medium buffers (64KB)
    Medium,
    /// Large buffers (1MB)
    Large,
    /// Custom size
    Custom(usize),
}

impl BufferSize {
    /// Get the actual size in bytes
    pub fn bytes(&self) -> usize {
        match self {
            Self::Small => 4 * 1024,
            Self::Medium => 64 * 1024,
            Self::Large => 1024 * 1024,
            Self::Custom(size) => *size,
        }
    }
    
    /// Determine appropriate buffer size for requested bytes
    pub fn from_bytes(bytes: usize) -> Self {
        match bytes {
            0..=4096 => Self::Small,
            4097..=65536 => Self::Medium,
            65537..=1048576 => Self::Large,
            _ => Self::Custom(bytes),
        }
    }
}

/// Internal buffer representation
struct Buffer {
    data: Vec<u8>,
    size: usize,
    pool: Weak<Mutex<PoolState>>,
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // Return buffer to pool if pool still exists
        if let Some(pool) = self.pool.upgrade() {
            if let Ok(mut state) = pool.lock() {
                self.data.clear();
                state.return_buffer(std::mem::take(&mut self.data), self.size);
            }
        }
    }
}

/// A pooled buffer that automatically returns to the pool when dropped
pub struct PooledBuffer {
    buffer: Option<Buffer>,
}

impl PooledBuffer {
    /// Create a new pooled buffer
    fn new(data: Vec<u8>, size: usize, pool: Weak<Mutex<PoolState>>) -> Self {
        Self {
            buffer: Some(Buffer { data, size, pool }),
        }
    }
    
    /// Get the buffer data as a slice
    pub fn as_slice(&self) -> &[u8] {
        self.buffer
            .as_ref()
            .map(|b| b.data.as_slice())
            .unwrap_or(&[])
    }
    
    /// Get the buffer data as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer
            .as_mut()
            .map(|b| b.data.as_mut_slice())
            .unwrap_or(&mut [])
    }
    
    /// Get the buffer size
    pub fn len(&self) -> usize {
        self.buffer.as_ref().map(|b| b.size).unwrap_or(0)
    }
    
    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    /// Take ownership of the underlying data
    pub fn into_vec(mut self) -> Vec<u8> {
        self.buffer
            .take()
            .map(|mut b| std::mem::take(&mut b.data))
            .unwrap_or_default()
    }
}

/// Internal pool state
struct PoolState {
    small_buffers: VecDeque<Vec<u8>>,
    medium_buffers: VecDeque<Vec<u8>>,
    large_buffers: VecDeque<Vec<u8>>,
    custom_buffers: Vec<(usize, VecDeque<Vec<u8>>)>,
    total_memory: AtomicUsize,
    max_memory: usize,
    shutdown: bool,
}

impl PoolState {
    fn new(max_memory: usize) -> Self {
        Self {
            small_buffers: VecDeque::new(),
            medium_buffers: VecDeque::new(),
            large_buffers: VecDeque::new(),
            custom_buffers: Vec::new(),
            total_memory: AtomicUsize::new(0),
            max_memory,
            shutdown: false,
        }
    }
    
    fn get_buffer_queue(&mut self, size: BufferSize) -> Option<&mut VecDeque<Vec<u8>>> {
        match size {
            BufferSize::Small => Some(&mut self.small_buffers),
            BufferSize::Medium => Some(&mut self.medium_buffers),
            BufferSize::Large => Some(&mut self.large_buffers),
            BufferSize::Custom(bytes) => {
                // Find or create custom buffer queue
                let idx = self.custom_buffers
                    .iter()
                    .position(|(s, _)| *s == bytes);
                    
                match idx {
                    Some(i) => Some(&mut self.custom_buffers[i].1),
                    None => {
                        self.custom_buffers.push((bytes, VecDeque::new()));
                        self.custom_buffers
                            .last_mut()
                            .map(|(_, queue)| queue)
                    }
                }
            }
        }
    }
    
    fn return_buffer(&mut self, mut buffer: Vec<u8>, size: usize) {
        if self.shutdown {
            return;
        }
        
        buffer.clear();
        let buffer_size = BufferSize::from_bytes(size);
        
        if let Some(queue) = self.get_buffer_queue(buffer_size) {
            queue.push_back(buffer);
        }
    }
}

/// Thread-safe memory pool for efficient buffer management
pub struct MemoryPool {
    state: Arc<Mutex<PoolState>>,
    stats: PoolStatistics,
}

impl MemoryPool {
    /// Create a new memory pool with specified maximum memory
    pub fn new(max_memory: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(PoolState::new(max_memory))),
            stats: PoolStatistics::default(),
        }
    }
    
    /// Create a memory pool with default settings (256MB max)
    pub fn default() -> Self {
        Self::new(256 * 1024 * 1024)
    }
    
    /// Acquire a buffer of specified size
    pub fn acquire(&self, size: usize) -> Result<PooledBuffer> {
        if size == 0 {
            return Err(MemoryPoolError::InvalidSize(0));
        }
        
        let mut state = self.state.lock()
            .map_err(|_| MemoryPoolError::PoolShutdown)?;
            
        if state.shutdown {
            return Err(MemoryPoolError::PoolShutdown);
        }
        
        let buffer_size = BufferSize::from_bytes(size);
        let actual_size = buffer_size.bytes();
        
        // Try to get buffer from pool
        let buffer = state
            .get_buffer_queue(buffer_size)
            .and_then(|queue| queue.pop_front());
            
        let buffer = match buffer {
            Some(mut buf) => {
                // Reuse existing buffer
                buf.resize(actual_size, 0);
                self.stats.reuses.fetch_add(1, Ordering::Relaxed);
                buf
            }
            None => {
                // Check if we can allocate new buffer
                let current_memory = state.total_memory.load(Ordering::Relaxed);
                if current_memory + actual_size > state.max_memory {
                    return Err(MemoryPoolError::PoolExhausted {
                        requested: actual_size,
                        available: state.max_memory.saturating_sub(current_memory),
                    });
                }
                
                // Allocate new buffer
                state.total_memory.fetch_add(actual_size, Ordering::Relaxed);
                self.stats.allocations.fetch_add(1, Ordering::Relaxed);
                vec![0u8; actual_size]
            }
        };
        
        Ok(PooledBuffer::new(
            buffer,
            actual_size,
            Arc::downgrade(&self.state),
        ))
    }
    
    /// Acquire multiple buffers at once
    pub fn acquire_batch(&self, count: usize, size: usize) -> Result<Vec<PooledBuffer>> {
        let mut buffers = Vec::with_capacity(count);
        
        for _ in 0..count {
            buffers.push(self.acquire(size)?);
        }
        
        Ok(buffers)
    }
    
    /// Pre-allocate buffers for better performance
    pub fn preallocate(&self, size: BufferSize, count: usize) -> Result<()> {
        let mut state = self.state.lock()
            .map_err(|_| MemoryPoolError::PoolShutdown)?;
            
        if state.shutdown {
            return Err(MemoryPoolError::PoolShutdown);
        }
        
        let actual_size = size.bytes();
        let total_size = actual_size * count;
        
        let current_memory = state.total_memory.load(Ordering::Relaxed);
        if current_memory + total_size > state.max_memory {
            return Err(MemoryPoolError::PoolExhausted {
                requested: total_size,
                available: state.max_memory.saturating_sub(current_memory),
            });
        }
        
        // Add memory to total before allocating 
        state.total_memory.fetch_add(actual_size * count, Ordering::Relaxed);
        
        if let Some(queue) = state.get_buffer_queue(size) {
            for _ in 0..count {
                queue.push_back(vec![0u8; actual_size]);
            }
        }
        
        Ok(())
    }
    
    /// Clear all buffers from the pool
    pub fn clear(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.small_buffers.clear();
            state.medium_buffers.clear();
            state.large_buffers.clear();
            state.custom_buffers.clear();
            state.total_memory.store(0, Ordering::Relaxed);
        }
    }
    
    /// Shutdown the pool (prevents new acquisitions)
    pub fn shutdown(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.shutdown = true;
            self.clear();
        }
    }
    
    /// Get pool statistics
    pub fn statistics(&self) -> PoolStatistics {
        PoolStatistics {
            allocations: AtomicUsize::new(self.stats.allocations.load(Ordering::Relaxed)),
            reuses: AtomicUsize::new(self.stats.reuses.load(Ordering::Relaxed)),
            current_memory: AtomicUsize::new(
                self.state
                    .lock()
                    .map(|s| s.total_memory.load(Ordering::Relaxed))
                    .unwrap_or(0)
            ),
        }
    }
    
    /// Get current memory usage
    pub fn memory_usage(&self) -> usize {
        self.state
            .lock()
            .map(|s| s.total_memory.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// Statistics for memory pool operations
#[derive(Debug, Default)]
pub struct PoolStatistics {
    /// Number of new allocations
    pub allocations: AtomicUsize,
    /// Number of buffer reuses
    pub reuses: AtomicUsize,
    /// Current memory usage
    pub current_memory: AtomicUsize,
}

impl PoolStatistics {
    /// Calculate reuse ratio
    pub fn reuse_ratio(&self) -> f64 {
        let reuses = self.reuses.load(Ordering::Relaxed) as f64;
        let total = (self.allocations.load(Ordering::Relaxed) 
                    + self.reuses.load(Ordering::Relaxed)) as f64;
        
        if total > 0.0 {
            reuses / total
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_buffer_size_selection() {
        assert_eq!(BufferSize::from_bytes(1024), BufferSize::Small);
        assert_eq!(BufferSize::from_bytes(32768), BufferSize::Medium);
        assert_eq!(BufferSize::from_bytes(524288), BufferSize::Large);
        assert_eq!(BufferSize::from_bytes(2097152), BufferSize::Custom(2097152));
    }
    
    #[test]
    fn test_pool_acquire_and_return() {
        let pool = MemoryPool::new(1024 * 1024);
        
        // Acquire buffer
        let buffer = pool.acquire(1024).unwrap();
        assert_eq!(buffer.len(), 4096); // Rounded up to Small size
        
        // Buffer should be returned when dropped
        drop(buffer);
        
        // Statistics should reflect the allocation
        let stats = pool.statistics();
        assert_eq!(stats.allocations.load(Ordering::Relaxed), 1);
    }
    
    #[test]
    fn test_pool_reuse() {
        let pool = MemoryPool::new(1024 * 1024);
        
        // First acquisition
        let buffer1 = pool.acquire(1024).unwrap();
        drop(buffer1);
        
        // Second acquisition should reuse
        let buffer2 = pool.acquire(1024).unwrap();
        drop(buffer2);
        
        let stats = pool.statistics();
        assert_eq!(stats.allocations.load(Ordering::Relaxed), 1);
        assert_eq!(stats.reuses.load(Ordering::Relaxed), 1);
    }
    
    #[test]
    fn test_pool_exhaustion() {
        let pool = MemoryPool::new(1024); // Very small pool
        
        // This should fail as it exceeds pool capacity
        let result = pool.acquire(2048);
        assert!(matches!(result, Err(MemoryPoolError::PoolExhausted { .. })));
    }
    
    #[test]
    fn test_batch_acquire() {
        let pool = MemoryPool::new(1024 * 1024);
        
        let buffers = pool.acquire_batch(10, 1024).unwrap();
        assert_eq!(buffers.len(), 10);
        
        for buffer in buffers {
            assert_eq!(buffer.len(), 4096);
        }
    }
}