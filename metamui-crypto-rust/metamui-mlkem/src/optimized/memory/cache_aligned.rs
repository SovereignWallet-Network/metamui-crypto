//! Cache-aligned data structures for optimal memory access patterns
//!
//! Provides cache-line aligned data structures and utilities to minimize
//! cache misses and false sharing in multi-threaded scenarios.

use core::alloc::Layout;
use core::mem;
use core::ptr::{self};
use core::marker::PhantomData;
use std::alloc::{alloc, dealloc, handle_alloc_error};

/// Standard cache line size (64 bytes on most modern CPUs)
pub const CACHE_LINE_SIZE: usize = 64;

/// L2 cache line size (typically larger)
pub const L2_CACHE_LINE_SIZE: usize = 128;

/// Prefetch distance for streaming operations
pub const PREFETCH_DISTANCE: usize = 8;

/// Cache-aligned wrapper for any type
#[repr(C)]
pub struct CacheAligned<T> {
    _padding_front: [u8; 0],
    data: T,
    _padding_back: [u8; 0],
    _phantom: PhantomData<T>,
}

impl<T> CacheAligned<T> {
    /// Create a new cache-aligned value
    pub fn new(data: T) -> Box<Self> {
        unsafe {
            let layout = Self::layout();
            let ptr = alloc(layout);
            
            if ptr.is_null() {
                handle_alloc_error(layout);
            }
            
            let aligned_ptr = ptr as *mut Self;
            ptr::write(&mut (*aligned_ptr).data, data);
            
            Box::from_raw(aligned_ptr)
        }
    }
    
    /// Get the layout for this type
    fn layout() -> Layout {
        let size = mem::size_of::<T>() + CACHE_LINE_SIZE - 1;
        let size = (size / CACHE_LINE_SIZE) * CACHE_LINE_SIZE;
        
        Layout::from_size_align(size, CACHE_LINE_SIZE)
            .expect("Invalid layout")
    }
    
    /// Get reference to inner data
    #[inline]
    pub fn get(&self) -> &T {
        &self.data
    }
    
    /// Get mutable reference to inner data
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.data
    }
    
    /// Into inner value
    #[inline]
    pub fn into_inner(self: Box<Self>) -> T {
        unsafe {
            let raw = Box::into_raw(self);
            let data = ptr::read(&(*raw).data);
            dealloc(raw as *mut u8, Self::layout());
            data
        }
    }
}

impl<T> AsRef<T> for CacheAligned<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        self.get()
    }
}

impl<T> AsMut<T> for CacheAligned<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        self.get_mut()
    }
}

/// Cache-padded value to prevent false sharing
/// Uses repr(align) to ensure cache-line alignment without explicit padding
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct CachePadded<T> {
    data: T,
}

impl<T> CachePadded<T> {
    /// Create new cache-padded value
    #[inline]
    pub const fn new(data: T) -> Self {
        Self {
            data,
        }
    }
    
    /// Get inner value
    #[inline]
    pub fn get(&self) -> &T {
        &self.data
    }
    
    /// Get mutable inner value
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.data
    }
    
    /// Into inner value
    #[inline]
    pub fn into_inner(self) -> T {
        self.data
    }
}

impl<T: Default> Default for CachePadded<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> From<T> for CachePadded<T> {
    fn from(data: T) -> Self {
        Self::new(data)
    }
}

impl<T> core::ops::Deref for CachePadded<T> {
    type Target = T;
    
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> core::ops::DerefMut for CachePadded<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/// Cache-aligned array for SIMD operations
#[repr(C, align(64))]
pub struct AlignedArray<T, const N: usize> {
    data: [T; N],
}

impl<T, const N: usize> AlignedArray<T, N> {
    /// Create new aligned array
    #[inline]
    pub fn new(data: [T; N]) -> Self {
        Self { data }
    }
    
    /// Get as slice
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }
    
    /// Get as mutable slice
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.data
    }
    
    /// Get pointer
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.data.as_ptr()
    }
    
    /// Get mutable pointer
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.data.as_mut_ptr()
    }
}

impl<T: Default + Copy, const N: usize> Default for AlignedArray<T, N> {
    fn default() -> Self {
        Self { data: [T::default(); N] }
    }
}

impl<T: Copy, const N: usize> Clone for AlignedArray<T, N> {
    fn clone(&self) -> Self {
        Self { data: self.data }
    }
}

/// Double-buffered cache-aligned storage for pipelining
/// Uses CachePadded internally to ensure each buffer is cache-aligned
pub struct DoubleBuffer<T> {
    buffer_a: CachePadded<T>,
    buffer_b: CachePadded<T>,
    active: CachePadded<bool>,
}

impl<T: Default> DoubleBuffer<T> {
    /// Create new double buffer
    #[inline]
    pub fn new() -> Self {
        Self {
            buffer_a: CachePadded::new(T::default()),
            buffer_b: CachePadded::new(T::default()),
            active: CachePadded::new(false),
        }
    }
    
    /// Get active buffer
    #[inline]
    pub fn active(&self) -> &T {
        if *self.active {
            &self.buffer_b.data
        } else {
            &self.buffer_a.data
        }
    }
    
    /// Get active buffer mutably
    #[inline]
    pub fn active_mut(&mut self) -> &mut T {
        if *self.active {
            &mut self.buffer_b.data
        } else {
            &mut self.buffer_a.data
        }
    }
    
    /// Get inactive buffer
    #[inline]
    pub fn inactive(&self) -> &T {
        if *self.active {
            &self.buffer_a.data
        } else {
            &self.buffer_b.data
        }
    }
    
    /// Get inactive buffer mutably
    #[inline]
    pub fn inactive_mut(&mut self) -> &mut T {
        if *self.active {
            &mut self.buffer_a.data
        } else {
            &mut self.buffer_b.data
        }
    }
    
    /// Swap buffers
    #[inline]
    pub fn swap(&mut self) {
        *self.active = !*self.active;
    }
}

/// Striped array for avoiding cache conflicts
pub struct StripedArray<T, const N: usize, const STRIPE: usize> {
    data: Box<[CachePadded<[T; STRIPE]>]>,
    len: usize,
}

impl<T: Default + Copy, const N: usize, const STRIPE: usize> StripedArray<T, N, STRIPE> {
    /// Create new striped array
    pub fn new() -> Self {
        let num_stripes = (N + STRIPE - 1) / STRIPE;
        let mut data = Vec::with_capacity(num_stripes);
        
        for _ in 0..num_stripes {
            data.push(CachePadded::new([T::default(); STRIPE]));
        }
        
        Self {
            data: data.into_boxed_slice(),
            len: N,
        }
    }
    
    /// Get element at index
    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len {
            return None;
        }
        
        let stripe = index / STRIPE;
        let offset = index % STRIPE;
        Some(&self.data[stripe].data[offset])
    }
    
    /// Get mutable element at index
    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.len {
            return None;
        }
        
        let stripe = index / STRIPE;
        let offset = index % STRIPE;
        Some(&mut self.data[stripe].data[offset])
    }
    
    /// Set element at index
    #[inline]
    pub fn set(&mut self, index: usize, value: T) {
        if index < self.len {
            let stripe = index / STRIPE;
            let offset = index % STRIPE;
            self.data[stripe].data[offset] = value;
        }
    }
}

/// Cache-optimized ring buffer
#[repr(C, align(64))]
pub struct CacheOptimizedRingBuffer<T, const N: usize> {
    data: [T; N],
    read_pos: CachePadded<usize>,
    write_pos: CachePadded<usize>,
}

impl<T: Default + Copy, const N: usize> CacheOptimizedRingBuffer<T, N> {
    /// Create new ring buffer
    pub fn new() -> Self {
        Self {
            data: [T::default(); N],
            read_pos: CachePadded::new(0),
            write_pos: CachePadded::new(0),
        }
    }
    
    /// Push element to buffer
    #[inline]
    pub fn push(&mut self, value: T) -> bool {
        let next_write = (*self.write_pos + 1) % N;
        if next_write == *self.read_pos {
            return false; // Buffer full
        }
        
        self.data[*self.write_pos] = value;
        *self.write_pos = next_write;
        true
    }
    
    /// Pop element from buffer
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if *self.read_pos == *self.write_pos {
            return None; // Buffer empty
        }
        
        let value = self.data[*self.read_pos];
        *self.read_pos = (*self.read_pos + 1) % N;
        Some(value)
    }
    
    /// Check if empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        *self.read_pos == *self.write_pos
    }
    
    /// Check if full
    #[inline]
    pub fn is_full(&self) -> bool {
        (*self.write_pos + 1) % N == *self.read_pos
    }
    
    /// Get number of elements
    #[inline]
    pub fn len(&self) -> usize {
        if *self.write_pos >= *self.read_pos {
            *self.write_pos - *self.read_pos
        } else {
            N - *self.read_pos + *self.write_pos
        }
    }
}

/// Memory layout optimizer for cache efficiency
pub struct CacheLayoutOptimizer;

impl CacheLayoutOptimizer {
    /// Calculate optimal padding for a type
    pub fn optimal_padding<T>() -> usize {
        let size = mem::size_of::<T>();
        if size >= CACHE_LINE_SIZE {
            0
        } else {
            CACHE_LINE_SIZE - (size % CACHE_LINE_SIZE)
        }
    }
    
    /// Check if pointer is cache-aligned
    #[inline]
    pub fn is_cache_aligned<T>(ptr: *const T) -> bool {
        (ptr as usize) % CACHE_LINE_SIZE == 0
    }
    
    /// Round up to cache line
    #[inline]
    pub fn round_to_cache_line(size: usize) -> usize {
        (size + CACHE_LINE_SIZE - 1) & !(CACHE_LINE_SIZE - 1)
    }
    
    /// Calculate cache line offset
    #[inline]
    pub fn cache_line_offset<T>(ptr: *const T) -> usize {
        (ptr as usize) % CACHE_LINE_SIZE
    }
    
    /// Estimate cache misses for strided access
    pub fn estimate_cache_misses(
        array_size: usize,
        element_size: usize,
        stride: usize,
        cache_size: usize,
    ) -> usize {
        let elements_per_line = CACHE_LINE_SIZE / element_size;
        let lines_per_stride = (stride + elements_per_line - 1) / elements_per_line;
        let total_accesses = array_size / stride;
        let cache_lines = cache_size / CACHE_LINE_SIZE;
        
        if lines_per_stride * total_accesses <= cache_lines {
            // All fits in cache
            lines_per_stride * total_accesses
        } else {
            // Cache thrashing
            total_accesses * lines_per_stride
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cache_aligned() {
        let aligned = CacheAligned::new(42u64);
        assert_eq!(*aligned.get(), 42);
        
        let ptr = aligned.get() as *const _ as usize;
        assert_eq!(ptr % CACHE_LINE_SIZE, 0, "Data should be cache-aligned");
    }
    
    #[test]
    fn test_cache_padded() {
        let padded = CachePadded::new(100u32);
        assert_eq!(*padded.get(), 100);
        
        // Check size is rounded up to cache line
        assert!(mem::size_of::<CachePadded<u32>>() >= CACHE_LINE_SIZE);
    }
    
    #[test]
    fn test_aligned_array() {
        let array = AlignedArray::<i32, 16>::default();
        let ptr = array.as_ptr() as usize;
        assert_eq!(ptr % CACHE_LINE_SIZE, 0, "Array should be cache-aligned");
    }
    
    #[test]
    fn test_double_buffer() {
        let mut buffer = DoubleBuffer::<Vec<u8>>::new();
        
        buffer.active_mut().push(1);
        buffer.swap();
        buffer.active_mut().push(2);
        
        assert_eq!(buffer.inactive().len(), 1);
        assert_eq!(buffer.active().len(), 1);
    }
    
    #[test]
    fn test_striped_array() {
        let mut array = StripedArray::<i32, 100, 8>::new();
        
        array.set(0, 10);
        array.set(50, 20);
        array.set(99, 30);
        
        assert_eq!(array.get(0), Some(&10));
        assert_eq!(array.get(50), Some(&20));
        assert_eq!(array.get(99), Some(&30));
        assert_eq!(array.get(100), None);
    }
    
    #[test]
    fn test_ring_buffer() {
        let mut ring = CacheOptimizedRingBuffer::<i32, 8>::new();
        
        assert!(ring.is_empty());
        assert!(ring.push(1));
        assert!(ring.push(2));
        assert!(ring.push(3));
        
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.pop(), Some(1));
        assert_eq!(ring.pop(), Some(2));
        assert_eq!(ring.len(), 1);
        
        // Fill buffer
        for i in 0..6 {
            assert!(ring.push(i));
        }
        assert!(ring.is_full());
        assert!(!ring.push(100));
    }
    
    #[test]
    fn test_layout_optimizer() {
        assert_eq!(CacheLayoutOptimizer::optimal_padding::<u8>(), 63);
        assert_eq!(CacheLayoutOptimizer::optimal_padding::<u64>(), 56);
        
        assert_eq!(CacheLayoutOptimizer::round_to_cache_line(1), 64);
        assert_eq!(CacheLayoutOptimizer::round_to_cache_line(64), 64);
        assert_eq!(CacheLayoutOptimizer::round_to_cache_line(65), 128);
    }
}