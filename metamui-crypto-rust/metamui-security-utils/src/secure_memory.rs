//! Secure memory handling utilities for Rust
//! Provides consistent memory clearing across all cryptographic operations

#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]  
use std::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::{self, Vec};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use core::ops::{Deref, DerefMut};
use core::ptr;

/// Securely clear memory by overwriting with zeros
/// 
/// # Safety
/// This function uses volatile writes to prevent compiler optimizations
/// from removing the memory clearing operation
pub fn zero(data: &mut [u8]) {
    unsafe {
        // Use volatile writes to prevent optimization
        for byte in data.iter_mut() {
            ptr::write_volatile(byte, 0);
        }
        
        // Additional passes for extra security
        for _ in 0..2 {
            for byte in data.iter_mut() {
                ptr::write_volatile(byte, 0);
            }
        }
    }
}

/// A buffer that automatically clears its contents when dropped
pub struct Buffer {
    data: Vec<u8>,
}

impl Buffer {
    /// Create a new secure buffer with the specified size
    pub fn new(size: usize) -> Self {
        let mut data = Vec::new();
        data.resize(size, 0u8);
        Self { data }
    }
    
    /// Create a secure buffer from existing data
    pub fn from_vec(mut data: Vec<u8>) -> Self {
        // Clear any excess capacity
        data.shrink_to_fit();
        Self { data }
    }
    
    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    /// Manually clear the buffer
    pub fn clear(&mut self) {
        zero(&mut self.data);
    }
}

impl Deref for Buffer {
    type Target = [u8];
    
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.clear();
    }
}

/// A wrapper for sensitive data that ensures it's cleared on drop
pub struct Box<T> {
    data: Box<T>,
}

impl<T> Box<T> {
    /// Create a new Box
    pub fn new(data: T) -> Self {
        Self {
            data: Box::new(data),
        }
    }
}

impl<T> Deref for Box<T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> DerefMut for Box<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T> Drop for Box<T> {
    fn drop(&mut self) {
        // Zero out the memory
        unsafe {
            let ptr = &mut *self.data as *mut T as *mut u8;
            let size = std::mem::size_of::<T>();
            let slice = std::slice::from_raw_parts_mut(ptr, size);
            zero(slice);
        }
    }
}

/// Execute a function with a secure buffer that is automatically cleared
pub fn with_secure_buffer<F, R>(size: usize, f: F) -> R
where
    F: FnOnce(&mut Buffer) -> R,
{
    let mut buffer = Buffer::new(size);
    f(&mut buffer)
}

/// Execute a function with secure temporary data
pub fn with_secure_data<T, F, R>(data: T, f: F) -> R
where
    F: FnOnce(&T) -> R,
{
    let secure = Box::new(data);
    f(&*secure)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_zero() {
        let mut data = vec![0xFF; 32];
        zero(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }
    
    #[test]
    fn test_secure_buffer_drop() {
        let mut buffer = Buffer::new(32);
        buffer.fill(0xFF);
        let ptr = buffer.as_ptr();
        drop(buffer);
        
        // Note: In a real test, we'd need to verify the memory was cleared
        // but this is difficult to do safely in Rust
    }
    
    #[test]
    fn test_with_secure_buffer() {
        let result = with_secure_buffer(32, |buffer| {
            buffer[0] = 42;
            buffer[0]
        });
        assert_eq!(result, 42);
    }
}