/// Memory pool for efficient allocation and reuse of cryptographic buffers
///
/// This module provides a thread-safe memory pool that reduces allocation overhead
/// by reusing buffers for cryptographic operations.

use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use metamui_security_utils::Zeroize;

#[cfg(feature = "std")]
use std::vec::Vec;

/// A memory pool for reusing byte buffers
pub struct MemoryPool {
    /// Pool of available buffers
    pool: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Size of each buffer in the pool
    buffer_size: usize,
    /// Maximum number of buffers to keep in the pool
    max_buffers: usize,
}

impl MemoryPool {
    /// Create a new memory pool
    ///
    /// # Arguments
    /// * `buffer_size` - Size of each buffer in bytes
    /// * `max_buffers` - Maximum number of buffers to keep in the pool
    pub fn new(buffer_size: usize, max_buffers: usize) -> Self {
        Self {
            pool: Arc::new(Mutex::new(VecDeque::with_capacity(max_buffers))),
            buffer_size,
            max_buffers,
        }
    }

    /// Create a memory pool with pre-allocated buffers
    ///
    /// # Arguments
    /// * `buffer_size` - Size of each buffer in bytes
    /// * `initial_buffers` - Number of buffers to pre-allocate
    /// * `max_buffers` - Maximum number of buffers to keep in the pool
    pub fn with_capacity(buffer_size: usize, initial_buffers: usize, max_buffers: usize) -> Self {
        let pool = Self::new(buffer_size, max_buffers);
        
        // Pre-allocate buffers
        if let Ok(mut pool_guard) = pool.pool.lock() {
            for _ in 0..initial_buffers.min(max_buffers) {
                pool_guard.push_back(vec![0u8; buffer_size]);
            }
        }
        
        pool
    }

    /// Acquire a buffer from the pool
    ///
    /// Returns a buffer guard that automatically returns the buffer to the pool when dropped
    pub fn acquire(&self) -> PooledBuffer {
        let buffer = if let Ok(mut pool) = self.pool.lock() {
            pool.pop_front()
        } else {
            None
        };

        let buffer = buffer.unwrap_or_else(|| vec![0u8; self.buffer_size]);

        PooledBuffer {
            buffer: Some(buffer),
            pool: Arc::clone(&self.pool),
            max_buffers: self.max_buffers,
        }
    }

    /// Get the number of available buffers in the pool
    pub fn available(&self) -> usize {
        self.pool.lock().map(|p| p.len()).unwrap_or(0)
    }

    /// Clear all buffers from the pool
    pub fn clear(&self) {
        if let Ok(mut pool) = self.pool.lock() {
            // Zeroize all buffers before clearing
            for mut buffer in pool.drain(..) {
                buffer.zeroize();
            }
        }
    }
}

/// A buffer acquired from the memory pool
///
/// Automatically returns the buffer to the pool when dropped
pub struct PooledBuffer {
    buffer: Option<Vec<u8>>,
    pool: Arc<Mutex<VecDeque<Vec<u8>>>>,
    max_buffers: usize,
}

impl PooledBuffer {
    /// Get a reference to the buffer
    pub fn as_slice(&self) -> &[u8] {
        self.buffer.as_ref().unwrap()
    }

    /// Get a mutable reference to the buffer
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut().unwrap()
    }

    /// Get the buffer length
    pub fn len(&self) -> usize {
        self.buffer.as_ref().map(|b| b.len()).unwrap_or(0)
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(mut buffer) = self.buffer.take() {
            // Clear the buffer before returning to pool
            buffer.fill(0);
            
            // Return to pool if there's space
            if let Ok(mut pool) = self.pool.lock() {
                if pool.len() < self.max_buffers {
                    pool.push_back(buffer);
                } else {
                    // Pool is full, let the buffer be dropped
                    buffer.zeroize();
                }
            }
        }
    }
}

/// Global memory pools for common buffer sizes
pub mod global_pools {
    use super::*;
    use once_cell::sync::Lazy;

    /// Pool for 32-byte buffers (common for hashes and keys)
    pub static POOL_32: Lazy<MemoryPool> = Lazy::new(|| {
        MemoryPool::with_capacity(32, 16, 64)
    });

    /// Pool for 64-byte buffers (SHA-512, signatures)
    pub static POOL_64: Lazy<MemoryPool> = Lazy::new(|| {
        MemoryPool::with_capacity(64, 16, 64)
    });

    /// Pool for 128-byte buffers (block ciphers)
    pub static POOL_128: Lazy<MemoryPool> = Lazy::new(|| {
        MemoryPool::with_capacity(128, 8, 32)
    });

    /// Pool for 256-byte buffers
    pub static POOL_256: Lazy<MemoryPool> = Lazy::new(|| {
        MemoryPool::with_capacity(256, 8, 32)
    });

    /// Pool for 1KB buffers
    pub static POOL_1K: Lazy<MemoryPool> = Lazy::new(|| {
        MemoryPool::with_capacity(1024, 4, 16)
    });

    /// Pool for 4KB buffers
    pub static POOL_4K: Lazy<MemoryPool> = Lazy::new(|| {
        MemoryPool::with_capacity(4096, 2, 8)
    });

    /// Get a pool for the specified size
    pub fn get_pool(size: usize) -> Option<&'static MemoryPool> {
        match size {
            32 => Some(&POOL_32),
            64 => Some(&POOL_64),
            128 => Some(&POOL_128),
            256 => Some(&POOL_256),
            1024 => Some(&POOL_1K),
            4096 => Some(&POOL_4K),
            _ => None,
        }
    }
}

/// Scoped memory pool for temporary allocations
pub struct ScopedPool {
    buffers: Vec<Vec<u8>>,
}

impl ScopedPool {
    /// Create a new scoped pool
    pub fn new() -> Self {
        Self {
            buffers: Vec::new(),
        }
    }

    /// Allocate a buffer of the specified size
    pub fn allocate(&mut self, size: usize) -> &mut [u8] {
        self.buffers.push(vec![0u8; size]);
        self.buffers.last_mut().unwrap()
    }

    /// Clear all buffers
    pub fn clear(&mut self) {
        for buffer in &mut self.buffers {
            buffer.zeroize();
        }
        self.buffers.clear();
    }
}

impl Drop for ScopedPool {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pool_basic() {
        let pool = MemoryPool::new(32, 10);
        
        // Acquire a buffer
        let mut buffer = pool.acquire();
        assert_eq!(buffer.len(), 32);
        
        // Write to buffer
        buffer.as_mut_slice()[0] = 42;
        assert_eq!(buffer.as_slice()[0], 42);
        
        // Drop buffer (returns to pool)
        drop(buffer);
        
        // Pool should have one buffer
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn test_memory_pool_reuse() {
        let pool = MemoryPool::new(64, 5);

        // Acquire multiple buffers, holding them all simultaneously
        let b1 = pool.acquire();
        let b2 = pool.acquire();
        let b3 = pool.acquire();
        assert_eq!(b1.len(), 64);
        assert_eq!(b2.len(), 64);
        assert_eq!(b3.len(), 64);

        // Drop all buffers so they return to pool
        drop(b1);
        drop(b2);
        drop(b3);

        // All buffers should be returned to pool
        assert_eq!(pool.available(), 3);
    }

    #[test]
    fn test_memory_pool_max_buffers() {
        let pool = MemoryPool::new(32, 2);
        
        // Create more buffers than max
        let _b1 = pool.acquire();
        let _b2 = pool.acquire();
        let _b3 = pool.acquire();
        
        drop(_b1);
        drop(_b2);
        drop(_b3);
        
        // Pool should only keep max_buffers
        assert!(pool.available() <= 2);
    }

    #[test]
    fn test_global_pools() {
        use global_pools::*;
        
        let buffer32 = POOL_32.acquire();
        assert_eq!(buffer32.len(), 32);
        
        let buffer64 = POOL_64.acquire();
        assert_eq!(buffer64.len(), 64);
        
        let pool = get_pool(128);
        assert!(pool.is_some());
    }

    #[test]
    fn test_scoped_pool() {
        let mut pool = ScopedPool::new();
        
        // Test first allocation
        {
            let buf1 = pool.allocate(32);
            buf1[0] = 1;
            assert_eq!(buf1[0], 1);
        }
        
        // Test second allocation
        {
            let buf2 = pool.allocate(64);
            buf2[0] = 2;
            assert_eq!(buf2[0], 2);
        }
        
        pool.clear();
    }
}