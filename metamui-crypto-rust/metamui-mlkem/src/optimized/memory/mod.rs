//! Memory management optimizations for ML-KEM
//!
//! This module provides various memory optimization strategies:
//! - Arena allocators for temporary allocations
//! - Stack-based polynomials for small operations
//! - Thread-local memory pools for parallel operations
//! - Zero-copy operations where possible

pub mod arena;
pub mod cache_aligned;
pub mod pool;
pub mod prefetch;
pub mod stack_poly;

pub use arena::{Arena, ArenaAllocator, ArenaScope, TypedArena};
pub use cache_aligned::{
    AlignedArray, CacheAligned, CacheLayoutOptimizer, CacheOptimizedRingBuffer,
    CachePadded, DoubleBuffer, StripedArray, CACHE_LINE_SIZE, L2_CACHE_LINE_SIZE,
};
pub use pool::{
    AlignedPolyBuffer, BatchBufferPool, BufferHandle, MemoryPool, PoolStats,
    ThreadLocalPool, available_memory_mb, get_global_stats, reset_global_stats,
};
pub use prefetch::{
    AdaptivePrefetcher, MatrixPrefetcher, NTTPrefetcher, PrefetchConfig, PrefetchHint,
    SequentialPrefetcher, StridedPrefetcher, helpers, prefetch, prefetch_range,
};
pub use stack_poly::{
    DualStackPoly, MLKem768PolyVec, SmallPoly, StackBuffer, StackPoly, StackPolyVec,
};

use core::mem::{self, MaybeUninit};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "std")]
use once_cell::sync::Lazy;

/// Memory statistics for profiling
#[derive(Debug, Clone, Default)]
pub struct MemoryStats {
    /// Total allocations
    pub allocations: usize,
    /// Total deallocations
    pub deallocations: usize,
    /// Current memory usage in bytes
    pub current_usage: usize,
    /// Peak memory usage in bytes
    pub peak_usage: usize,
    /// Arena allocations
    pub arena_allocations: usize,
    /// Stack allocations
    pub stack_allocations: usize,
    /// Pool allocations
    pub pool_allocations: usize,
}

/// Global memory statistics
#[cfg(feature = "std")]
pub static MEMORY_STATS: Lazy<RwLock<MemoryStats>> = Lazy::new(|| RwLock::new(MemoryStats::default()));

/// Atomic counter for tracking allocations
static ALLOCATION_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Memory alignment for SIMD operations
pub const SIMD_ALIGN: usize = 64;

/// Maximum size for stack allocation
pub const MAX_STACK_SIZE: usize = 4096;

/// Memory profiling guard
pub struct ProfileGuard {
    size: usize,
    start_time: Option<std::time::Instant>,
}

impl ProfileGuard {
    /// Create a new profiling guard
    #[inline]
    pub fn new(size: usize) -> Self {
        #[cfg(feature = "std")]
        {
            let mut stats = MEMORY_STATS.write();
            stats.allocations += 1;
            stats.current_usage += size;
            if stats.current_usage > stats.peak_usage {
                stats.peak_usage = stats.current_usage;
            }
        }
        
        ALLOCATION_COUNTER.fetch_add(1, Ordering::Relaxed);
        
        Self {
            size,
            #[cfg(feature = "std")]
            start_time: Some(std::time::Instant::now()),
            #[cfg(not(feature = "std"))]
            start_time: None,
        }
    }
}

impl Drop for ProfileGuard {
    fn drop(&mut self) {
        #[cfg(feature = "std")]
        {
            let mut stats = MEMORY_STATS.write();
            stats.deallocations += 1;
            stats.current_usage = stats.current_usage.saturating_sub(self.size);
            
            if let Some(start) = self.start_time {
                let duration = start.elapsed();
                log::trace!("Memory operation took {:?} for {} bytes", duration, self.size);
            }
        }
    }
}

/// Aligned memory buffer
#[repr(align(64))]
pub struct AlignedBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> AlignedBuffer<N> {
    /// Create a new aligned buffer
    #[inline]
    pub const fn new() -> Self {
        Self { data: [0; N] }
    }
    
    /// Get a mutable slice to the buffer
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    
    /// Get a slice to the buffer
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

/// Zero-copy wrapper for avoiding unnecessary copies
pub struct ZeroCopy<T> {
    data: T,
    borrowed: bool,
}

impl<T> ZeroCopy<T> {
    /// Create a new zero-copy wrapper
    #[inline]
    pub fn new(data: T) -> Self {
        Self { data, borrowed: false }
    }
    
    /// Borrow the data
    #[inline]
    pub fn borrow(&mut self) -> &T {
        self.borrowed = true;
        &self.data
    }
    
    /// Borrow the data mutably
    #[inline]
    pub fn borrow_mut(&mut self) -> &mut T {
        self.borrowed = true;
        &mut self.data
    }
    
    /// Take ownership of the data
    #[inline]
    pub fn into_inner(self) -> T {
        self.data
    }
    
    /// Check if data has been borrowed
    #[inline]
    pub fn is_borrowed(&self) -> bool {
        self.borrowed
    }
}

/// Memory layout optimizer for cache efficiency
pub struct LayoutOptimizer;

impl LayoutOptimizer {
    /// Calculate optimal memory layout for given data structures
    pub fn optimize_layout(sizes: &[usize]) -> Vec<usize> {
        let mut indexed_sizes: Vec<(usize, usize)> = sizes.iter()
            .enumerate()
            .map(|(i, &s)| (i, s))
            .collect();
        
        // Sort by size descending for better packing
        indexed_sizes.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Calculate offsets with proper alignment
        let mut offsets = vec![0; sizes.len()];
        let mut current_offset = 0;
        
        for &(idx, size) in &indexed_sizes {
            // Align to cache line if beneficial
            if size >= 64 {
                current_offset = (current_offset + 63) & !63;
            } else if size >= 16 {
                current_offset = (current_offset + 15) & !15;
            } else if size >= 8 {
                current_offset = (current_offset + 7) & !7;
            }
            
            offsets[idx] = current_offset;
            current_offset += size;
        }
        
        offsets
    }
    
    /// Check if a pointer is aligned
    #[inline]
    pub fn is_aligned<T>(ptr: *const T, align: usize) -> bool {
        (ptr as usize) % align == 0
    }
    
    /// Align a value to the specified alignment
    #[inline]
    pub fn align_up(value: usize, align: usize) -> usize {
        (value + align - 1) & !(align - 1)
    }
}

/// Fast memory operations optimized for specific sizes
pub mod fast_ops {
    use super::*;
    
    /// Fast memcpy for small fixed sizes
    #[inline]
    pub unsafe fn fast_copy<const N: usize>(dst: *mut u8, src: *const u8) {
        match N {
            8 => {
                ptr::write_unaligned(dst as *mut u64, ptr::read_unaligned(src as *const u64));
            }
            16 => {
                ptr::write_unaligned(dst as *mut [u64; 2], ptr::read_unaligned(src as *const [u64; 2]));
            }
            32 => {
                ptr::write_unaligned(dst as *mut [u64; 4], ptr::read_unaligned(src as *const [u64; 4]));
            }
            64 => {
                ptr::write_unaligned(dst as *mut [u64; 8], ptr::read_unaligned(src as *const [u64; 8]));
            }
            _ => {
                ptr::copy_nonoverlapping(src, dst, N);
            }
        }
    }
    
    /// Fast memset for small fixed sizes
    #[inline]
    pub unsafe fn fast_zero<const N: usize>(dst: *mut u8) {
        match N {
            8 => {
                ptr::write_unaligned(dst as *mut u64, 0);
            }
            16 => {
                ptr::write_unaligned(dst as *mut [u64; 2], [0; 2]);
            }
            32 => {
                ptr::write_unaligned(dst as *mut [u64; 4], [0; 4]);
            }
            64 => {
                ptr::write_unaligned(dst as *mut [u64; 8], [0; 8]);
            }
            _ => {
                ptr::write_bytes(dst, 0, N);
            }
        }
    }
    
    /// Compare memory regions
    #[inline]
    pub unsafe fn fast_compare<const N: usize>(a: *const u8, b: *const u8) -> bool {
        match N {
            8 => {
                ptr::read_unaligned(a as *const u64) == ptr::read_unaligned(b as *const u64)
            }
            16 => {
                ptr::read_unaligned(a as *const [u64; 2]) == ptr::read_unaligned(b as *const [u64; 2])
            }
            32 => {
                ptr::read_unaligned(a as *const [u64; 4]) == ptr::read_unaligned(b as *const [u64; 4])
            }
            _ => {
                core::slice::from_raw_parts(a, N) == core::slice::from_raw_parts(b, N)
            }
        }
    }
}

/// Uninitialized memory utilities
pub mod uninit {
    use super::*;
    
    /// Create an uninitialized array
    #[inline]
    pub fn uninit_array<T, const N: usize>() -> [MaybeUninit<T>; N] {
        unsafe { MaybeUninit::uninit().assume_init() }
    }
    
    /// Initialize an array from uninitialized memory
    #[inline]
    pub unsafe fn assume_init_array<T, const N: usize>(arr: [MaybeUninit<T>; N]) -> [T; N] {
        mem::transmute_copy(&arr)
    }
    
    /// Zero-initialize memory
    #[inline]
    pub fn zeroed_array<T: Default, const N: usize>() -> [T; N] {
        [(); N].map(|_| T::default())
    }
}

/// Get current memory statistics
#[cfg(feature = "std")]
pub fn get_memory_stats() -> MemoryStats {
    MEMORY_STATS.read().clone()
}

/// Reset memory statistics
#[cfg(feature = "std")]
pub fn reset_memory_stats() {
    let mut stats = MEMORY_STATS.write();
    *stats = MemoryStats::default();
    ALLOCATION_COUNTER.store(0, Ordering::Relaxed);
}

/// Get total allocation count
pub fn get_allocation_count() -> usize {
    ALLOCATION_COUNTER.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_aligned_buffer() {
        let mut buffer = AlignedBuffer::<1024>::new();
        assert_eq!(buffer.as_slice().len(), 1024);
        assert!(LayoutOptimizer::is_aligned(buffer.as_slice().as_ptr(), 64));
    }
    
    #[test]
    fn test_layout_optimizer() {
        let sizes = vec![8, 64, 16, 128, 32];
        let offsets = LayoutOptimizer::optimize_layout(&sizes);
        
        // Check that larger sizes are placed first for better cache usage
        for i in 1..offsets.len() {
            if sizes[i] > 64 {
                // Large allocations should be cache-line aligned
                assert_eq!(offsets[i] % 64, 0);
            }
        }
    }
    
    #[test]
    fn test_zero_copy() {
        let mut wrapper = ZeroCopy::new(vec![1, 2, 3, 4]);
        assert!(!wrapper.is_borrowed());
        
        {
            let borrowed = wrapper.borrow();
            assert_eq!(borrowed, &vec![1, 2, 3, 4]);
        }
        
        assert!(wrapper.is_borrowed());
    }
    
    #[test]
    fn test_fast_ops() {
        unsafe {
            let src = [1u8; 64];
            let mut dst = [0u8; 64];
            
            fast_ops::fast_copy::<64>(dst.as_mut_ptr(), src.as_ptr());
            assert_eq!(src, dst);
            
            fast_ops::fast_zero::<64>(dst.as_mut_ptr());
            assert!(dst.iter().all(|&x| x == 0));
            
            let a = [1u8; 32];
            let b = [1u8; 32];
            assert!(fast_ops::fast_compare::<32>(a.as_ptr(), b.as_ptr()));
        }
    }
}