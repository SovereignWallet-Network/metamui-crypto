//! Arena allocator for temporary allocations
//!
//! Provides fast bump allocation for temporary data structures
//! with batch deallocation.

use core::alloc::Layout;
use core::cell::{Cell, RefCell};
use core::mem;
use core::ptr::{self, NonNull};
use core::slice;

#[cfg(feature = "std")]
use std::alloc;

/// Arena allocator for fast temporary allocations
pub struct Arena {
    chunks: RefCell<Vec<ArenaChunk>>,
    current_chunk: RefCell<usize>,
    position: Cell<usize>,
    total_allocated: Cell<usize>,
    allocation_count: Cell<usize>,
}

struct ArenaChunk {
    data: NonNull<u8>,
    capacity: usize,
    layout: Layout,
}

impl Arena {
    /// Default chunk size (64KB)
    const DEFAULT_CHUNK_SIZE: usize = 65536;
    
    /// Minimum alignment for all allocations
    const MIN_ALIGN: usize = 16;
    
    /// Create a new arena with default chunk size
    pub fn new() -> Self {
        Self::with_chunk_size(Self::DEFAULT_CHUNK_SIZE)
    }
    
    /// Create a new arena with specified chunk size
    pub fn with_chunk_size(chunk_size: usize) -> Self {
        let chunk = ArenaChunk::new(chunk_size);
        Arena {
            chunks: RefCell::new(vec![chunk]),
            current_chunk: RefCell::new(0),
            position: Cell::new(0),
            total_allocated: Cell::new(0),
            allocation_count: Cell::new(0),
        }
    }
    
    /// Allocate memory from the arena
    pub fn alloc<T>(&self, value: T) -> &mut T {
        let size = mem::size_of::<T>();
        let align = mem::align_of::<T>().max(Self::MIN_ALIGN);
        
        unsafe {
            let ptr = self.alloc_raw(size, align) as *mut T;
            ptr::write(ptr, value);
            &mut *ptr
        }
    }
    
    /// Allocate a slice from the arena
    pub fn alloc_slice<T: Copy>(&self, slice: &[T]) -> &mut [T] {
        let size = mem::size_of::<T>() * slice.len();
        let align = mem::align_of::<T>().max(Self::MIN_ALIGN);
        
        if slice.is_empty() {
            return &mut [];
        }
        
        unsafe {
            let ptr = self.alloc_raw(size, align) as *mut T;
            ptr::copy_nonoverlapping(slice.as_ptr(), ptr, slice.len());
            slice::from_raw_parts_mut(ptr, slice.len())
        }
    }
    
    /// Allocate uninitialized memory
    pub fn alloc_uninit<T>(&self) -> &mut mem::MaybeUninit<T> {
        let size = mem::size_of::<T>();
        let align = mem::align_of::<T>().max(Self::MIN_ALIGN);
        
        unsafe {
            let ptr = self.alloc_raw(size, align) as *mut mem::MaybeUninit<T>;
            &mut *ptr
        }
    }
    
    /// Allocate an array of uninitialized values
    pub fn alloc_array_uninit<T, const N: usize>(&self) -> &mut [mem::MaybeUninit<T>; N] {
        let size = mem::size_of::<T>() * N;
        let align = mem::align_of::<T>().max(Self::MIN_ALIGN);
        
        unsafe {
            let ptr = self.alloc_raw(size, align) as *mut [mem::MaybeUninit<T>; N];
            &mut *ptr
        }
    }
    
    /// Allocate raw memory
    unsafe fn alloc_raw(&self, size: usize, align: usize) -> *mut u8 {
        let align = align.max(Self::MIN_ALIGN);
        let chunks = self.chunks.borrow();
        let current = *self.current_chunk.borrow();
        let chunk = &chunks[current];
        
        // Align the position
        let pos = self.position.get();
        let aligned_pos = (pos + align - 1) & !(align - 1);
        let needed = aligned_pos - pos + size;
        
        // Check if we need a new chunk
        if aligned_pos + size > chunk.capacity {
            drop(chunks);
            self.allocate_new_chunk(size.max(Self::DEFAULT_CHUNK_SIZE));
            return self.alloc_raw(size, align);
        }
        
        // Update position and statistics
        self.position.set(aligned_pos + size);
        self.total_allocated.set(self.total_allocated.get() + size);
        self.allocation_count.set(self.allocation_count.get() + 1);
        
        chunk.data.as_ptr().add(aligned_pos)
    }
    
    /// Allocate a new chunk
    fn allocate_new_chunk(&self, min_size: usize) {
        let size = min_size.max(Self::DEFAULT_CHUNK_SIZE);
        let chunk = ArenaChunk::new(size);
        
        let mut chunks = self.chunks.borrow_mut();
        chunks.push(chunk);
        
        let new_index = chunks.len() - 1;
        *self.current_chunk.borrow_mut() = new_index;
        self.position.set(0);
    }
    
    /// Reset the arena, keeping allocated memory
    pub fn reset(&self) {
        *self.current_chunk.borrow_mut() = 0;
        self.position.set(0);
        self.allocation_count.set(0);
        
        #[cfg(feature = "std")]
        {
            super::MEMORY_STATS.write().arena_allocations += self.allocation_count.get();
        }
    }
    
    /// Get total allocated bytes
    pub fn allocated_bytes(&self) -> usize {
        self.total_allocated.get()
    }
    
    /// Get number of allocations
    pub fn allocation_count(&self) -> usize {
        self.allocation_count.get()
    }
    
    /// Get number of chunks
    pub fn chunk_count(&self) -> usize {
        self.chunks.borrow().len()
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        // Chunks will be dropped automatically
    }
}

impl ArenaChunk {
    fn new(capacity: usize) -> Self {
        let align = Arena::MIN_ALIGN;
        let layout = Layout::from_size_align(capacity, align)
            .expect("Invalid layout");
        
        #[cfg(feature = "std")]
        let data = unsafe {
            let ptr = alloc::alloc(layout);
            if ptr.is_null() {
                alloc::handle_alloc_error(layout);
            }
            NonNull::new_unchecked(ptr)
        };
        
        #[cfg(not(feature = "std"))]
        let data = {
            // For no_std, we would need a custom allocator
            panic!("Arena allocator requires std feature");
        };
        
        ArenaChunk {
            data,
            capacity,
            layout,
        }
    }
}

impl Drop for ArenaChunk {
    fn drop(&mut self) {
        #[cfg(feature = "std")]
        unsafe {
            alloc::dealloc(self.data.as_ptr(), self.layout);
        }
    }
}

unsafe impl Send for Arena {}
unsafe impl Sync for Arena {}

/// Scoped arena allocator that automatically resets
pub struct ArenaScope<'a> {
    arena: &'a Arena,
    initial_position: usize,
    initial_chunk: usize,
}

impl<'a> ArenaScope<'a> {
    /// Create a new arena scope
    pub fn new(arena: &'a Arena) -> Self {
        ArenaScope {
            arena,
            initial_position: arena.position.get(),
            initial_chunk: *arena.current_chunk.borrow(),
        }
    }
    
    /// Get the underlying arena
    pub fn arena(&self) -> &Arena {
        self.arena
    }
}

impl<'a> Drop for ArenaScope<'a> {
    fn drop(&mut self) {
        // Reset to initial state
        *self.arena.current_chunk.borrow_mut() = self.initial_chunk;
        self.arena.position.set(self.initial_position);
    }
}

/// Arena allocator with type-specific pools
pub struct TypedArena<T> {
    chunks: RefCell<Vec<TypedChunk<T>>>,
    current: RefCell<Option<NonNull<T>>>,
    end: Cell<*mut T>,
}

struct TypedChunk<T> {
    storage: Box<[mem::MaybeUninit<T>]>,
    #[allow(dead_code)]
    capacity: usize,
}

impl<T> TypedArena<T> {
    const DEFAULT_CAPACITY: usize = 128;
    
    /// Create a new typed arena
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }
    
    /// Create with specific capacity
    pub fn with_capacity(capacity: usize) -> Self {
        TypedArena {
            chunks: RefCell::new(Vec::new()),
            current: RefCell::new(None),
            end: Cell::new(ptr::null_mut()),
        }
    }
    
    /// Allocate a value in the arena
    pub fn alloc(&self, value: T) -> &mut T {
        unsafe {
            let ptr = self.alloc_raw();
            ptr::write(ptr, value);
            &mut *ptr
        }
    }
    
    /// Allocate uninitialized space
    unsafe fn alloc_raw(&self) -> *mut T {
        let current = self.current.borrow();
        let end = self.end.get();
        
        if let Some(mut ptr) = *current {
            let p = ptr.as_ptr();
            if p < end {
                ptr = NonNull::new_unchecked(p.add(1));
                self.current.borrow_mut().replace(ptr);
                return p;
            }
        }
        
        self.grow();
        self.alloc_raw()
    }
    
    /// Grow the arena by adding a new chunk
    fn grow(&self) {
        let capacity = self.chunks.borrow()
            .last()
            .map(|c| c.capacity * 2)
            .unwrap_or(Self::DEFAULT_CAPACITY);
        
        let storage = (0..capacity)
            .map(|_| mem::MaybeUninit::uninit())
            .collect::<Box<[_]>>();
        
        let chunk = TypedChunk {
            capacity,
            storage,
        };
        
        let mut chunks = self.chunks.borrow_mut();
        let storage_ptr = chunk.storage.as_ptr() as *mut T;
        let end = unsafe { storage_ptr.add(capacity) };
        
        chunks.push(chunk);
        
        self.current.borrow_mut().replace(unsafe { NonNull::new_unchecked(storage_ptr) });
        self.end.set(end);
    }
}

impl<T> Default for TypedArena<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Global arena allocator for common operations
pub struct ArenaAllocator {
    arenas: RefCell<Vec<Arena>>,
    current: Cell<usize>,
}

impl ArenaAllocator {
    /// Create a new arena allocator
    pub fn new() -> Self {
        ArenaAllocator {
            arenas: RefCell::new(vec![Arena::new()]),
            current: Cell::new(0),
        }
    }
    
    /// Get the current arena
    pub fn current(&self) -> &Arena {
        let arenas = unsafe { &*self.arenas.as_ptr() };
        &arenas[self.current.get()]
    }
    
    /// Push a new arena scope
    pub fn push_scope(&self) -> ArenaGuard {
        let current = self.current.get();
        let arenas = self.arenas.borrow();
        
        if current + 1 >= arenas.len() {
            drop(arenas);
            self.arenas.borrow_mut().push(Arena::new());
        }
        
        self.current.set(current + 1);
        ArenaGuard { allocator: self }
    }
}

/// Guard for arena scope
pub struct ArenaGuard<'a> {
    allocator: &'a ArenaAllocator,
}

impl<'a> Drop for ArenaGuard<'a> {
    fn drop(&mut self) {
        let current = self.allocator.current.get();
        self.allocator.arenas.borrow()[current].reset();
        if current > 0 {
            self.allocator.current.set(current - 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_arena_basic() {
        let arena = Arena::new();
        
        let x = arena.alloc(42i32);
        assert_eq!(*x, 42);
        
        let y = arena.alloc(100i32);
        assert_eq!(*y, 100);
        
        *x = 50;
        assert_eq!(*x, 50);
    }
    
    #[test]
    fn test_arena_slice() {
        let arena = Arena::new();
        let data = vec![1, 2, 3, 4, 5];
        
        let slice = arena.alloc_slice(&data);
        assert_eq!(slice, &data[..]);
        
        slice[0] = 10;
        assert_eq!(slice[0], 10);
    }
    
    #[test]
    fn test_arena_scope() {
        let arena = Arena::new();
        let initial_allocs = arena.allocation_count();
        
        {
            let _scope = ArenaScope::new(&arena);
            arena.alloc(42i32);
            arena.alloc(100i32);
            assert!(arena.allocation_count() > initial_allocs);
        }
        
        // After scope, position is reset but memory is retained
        assert_eq!(arena.allocation_count(), initial_allocs);
    }
    
    #[test]
    fn test_typed_arena() {
        let arena = TypedArena::<i32>::new();
        
        let x = arena.alloc(42);
        let y = arena.alloc(100);
        
        assert_eq!(*x, 42);
        assert_eq!(*y, 100);
        
        *x = 50;
        assert_eq!(*x, 50);
    }
    
    #[test]
    fn test_arena_alignment() {
        #[repr(align(64))]
        struct Aligned {
            data: [u8; 64],
        }
        
        let arena = Arena::new();
        let aligned = arena.alloc(Aligned { data: [0; 64] });
        
        let addr = aligned as *const _ as usize;
        assert_eq!(addr % 64, 0, "Should be 64-byte aligned");
    }
}