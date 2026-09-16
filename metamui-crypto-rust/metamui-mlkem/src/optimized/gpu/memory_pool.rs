//! GPU memory pool for efficient buffer allocation
//!
//! Provides a memory pool for reusing GPU buffers to minimize allocation overhead.

use super::device::GpuDevice;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use wgpu::{Buffer, BufferUsages};

/// Memory buffer wrapper
pub struct MemoryBuffer {
    pub buffer: Arc<Buffer>,
    pub size: usize,
    pool: Arc<Mutex<VecDeque<Arc<Buffer>>>>,
}

impl Drop for MemoryBuffer {
    fn drop(&mut self) {
        // Return buffer to pool when dropped
        if let Ok(mut pool) = self.pool.lock() {
            pool.push_back(Arc::clone(&self.buffer));
        }
    }
}

/// Memory pool for GPU buffers
pub struct MemoryPool {
    device: Arc<wgpu::Device>,
    pools: Arc<Mutex<Vec<VecDeque<Arc<Buffer>>>>>,
    sizes: Vec<usize>,
    max_pool_size: usize,
}

impl MemoryPool {
    /// Create a new memory pool
    pub fn new(device: &GpuDevice, max_memory: usize) -> Result<Self, super::device::GpuError> {
        // Define standard buffer sizes for ML-KEM operations
        let sizes = vec![
            256 * 4,         // Single polynomial
            256 * 4 * 3,     // k=3 polynomials
            256 * 4 * 9,     // k×k matrix
            256 * 4 * 100,   // Small batch
            256 * 4 * 1000,  // Medium batch
            256 * 4 * 10000, // Large batch
        ];
        
        let pools = sizes.iter().map(|_| VecDeque::new()).collect();
        
        Ok(Self {
            device: Arc::new(device.device().clone()),
            pools: Arc::new(Mutex::new(pools)),
            sizes,
            max_pool_size: max_memory / sizes.len(),
        })
    }
    
    /// Allocate a buffer from the pool
    pub fn allocate(&self, size: usize, usage: BufferUsages) -> MemoryBuffer {
        // Find appropriate pool for this size
        let pool_idx = self.sizes.iter()
            .position(|&s| s >= size)
            .unwrap_or(self.sizes.len() - 1);
        
        let actual_size = if pool_idx < self.sizes.len() {
            self.sizes[pool_idx]
        } else {
            size
        };
        
        // Try to get buffer from pool
        let buffer = {
            if let Ok(mut pools) = self.pools.lock() {
                if pool_idx < pools.len() {
                    pools[pool_idx].pop_front()
                } else {
                    None
                }
            } else {
                None
            }
        };
        
        // Create new buffer if pool is empty
        let buffer = buffer.unwrap_or_else(|| {
            Arc::new(self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("Pooled Buffer"),
                size: actual_size as u64,
                usage,
                mapped_at_creation: false,
            }))
        });
        
        let pool = if pool_idx < self.sizes.len() {
            if let Ok(pools) = self.pools.lock() {
                Arc::new(Mutex::new(pools[pool_idx].clone()))
            } else {
                Arc::new(Mutex::new(VecDeque::new()))
            }
        } else {
            Arc::new(Mutex::new(VecDeque::new()))
        };
        
        MemoryBuffer {
            buffer,
            size: actual_size,
            pool,
        }
    }
    
    /// Clear all buffers from the pool
    pub fn clear(&self) {
        if let Ok(mut pools) = self.pools.lock() {
            for pool in pools.iter_mut() {
                pool.clear();
            }
        }
    }
    
    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        if let Ok(pools) = self.pools.lock() {
            let total_buffers: usize = pools.iter().map(|p| p.len()).sum();
            let total_memory: usize = pools.iter()
                .zip(self.sizes.iter())
                .map(|(p, &s)| p.len() * s)
                .sum();
            
            PoolStats {
                total_buffers,
                total_memory,
                pools_count: pools.len(),
            }
        } else {
            PoolStats {
                total_buffers: 0,
                total_memory: 0,
                pools_count: 0,
            }
        }
    }
}

/// Memory pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_buffers: usize,
    pub total_memory: usize,
    pub pools_count: usize,
}