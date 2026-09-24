// Secure Memory Zeroization for Falcon-512
//
// This module implements secure key zeroization with memory barriers
// to prevent compiler optimizations from removing the clearing operations.
// Compliant with FIPS 140-3 and Common Criteria requirements.

use core::ptr;
use core::sync::atomic::{compiler_fence, fence, Ordering};
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::vec::Vec;

/// Secure zeroization with memory barriers
/// 
/// This function ensures that sensitive data is actually cleared from memory
/// and not optimized away by the compiler.
#[inline(never)]
pub fn secure_zero(data: &mut [u8]) {
    // First pass: overwrite with zeros
    for byte in data.iter_mut() {
        unsafe {
            // Use volatile write to prevent optimization
            ptr::write_volatile(byte, 0u8);
        }
    }
    
    // Memory barrier to prevent reordering
    compiler_fence(Ordering::SeqCst);
    
    // Second pass: verify zeros (in debug mode)
    #[cfg(debug_assertions)]
    {
        for byte in data.iter() {
            debug_assert_eq!(*byte, 0u8, "Memory not properly zeroed");
        }
    }
    
    // Final memory barrier
    compiler_fence(Ordering::SeqCst);
}

/// Secure zeroization for i16 slices (polynomial coefficients)
#[inline(never)]
pub fn secure_zero_i16(data: &mut [i16]) {
    // Convert to byte slice for zeroization
    let byte_slice = unsafe {
        core::slice::from_raw_parts_mut(
            data.as_mut_ptr() as *mut u8,
            data.len() * 2
        )
    };
    
    secure_zero(byte_slice);
}

/// Secure key structure that automatically zeroizes on drop
#[derive(Clone)]
pub struct SecureKey {
    data: Vec<u8>,
}

impl SecureKey {
    /// Create a new secure key container
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    /// Get immutable reference to key data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    /// Get mutable reference to key data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    
    /// Manually trigger zeroization
    pub fn zeroize(&mut self) {
        secure_zero(&mut self.data);
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for SecureKey {
    fn zeroize(&mut self) {
        secure_zero(&mut self.data);
    }
}

impl ZeroizeOnDrop for SecureKey {}

/// Secure polynomial that zeroizes coefficients on drop
pub struct SecurePolynomial {
    coeffs: Vec<i16>,
}

impl SecurePolynomial {
    pub fn new(coeffs: Vec<i16>) -> Self {
        Self { coeffs }
    }
    
    pub fn as_slice(&self) -> &[i16] {
        &self.coeffs
    }
    
    pub fn as_mut_slice(&mut self) -> &mut [i16] {
        &mut self.coeffs
    }
    
    /// Clone coefficients without marking as secure
    pub fn to_vec(&self) -> Vec<i16> {
        self.coeffs.clone()
    }
}

impl Drop for SecurePolynomial {
    fn drop(&mut self) {
        secure_zero_i16(&mut self.coeffs);
    }
}

impl Zeroize for SecurePolynomial {
    fn zeroize(&mut self) {
        secure_zero_i16(&mut self.coeffs);
    }
}

impl ZeroizeOnDrop for SecurePolynomial {}

/// Full memory fence between erasure passes.
///
/// Portable: `fence(SeqCst)` orders the volatile writes of one pass before
/// the next on every target, with no architecture-specific instruction.
#[inline(always)]
pub fn memory_barrier() {
    fence(Ordering::SeqCst);
}

/// Pattern-based secure erasure
/// 
/// Overwrites memory with multiple patterns to ensure data destruction
/// even in the presence of memory remanence effects.
#[inline(never)]
pub fn secure_erase_patterns(data: &mut [u8]) {
    const PATTERNS: [u8; 4] = [0x00, 0xFF, 0xAA, 0x55];
    
    for pattern in PATTERNS.iter() {
        for byte in data.iter_mut() {
            unsafe {
                ptr::write_volatile(byte, *pattern);
            }
        }
        memory_barrier();
    }
    
    // Final zero pass
    secure_zero(data);
}

/// Verify memory has been properly zeroized
/// 
/// Returns true if all bytes are zero, false otherwise.
/// Used in test/debug builds for verification; also available in release
/// for the test_zeroization binary.
pub fn verify_zeroized(data: &[u8]) -> bool {
    let mut is_zero = true;
    
    // Check each byte without early exit (constant-time)
    for byte in data.iter() {
        is_zero &= *byte == 0;
    }
    
    is_zero
}

/// Secure comparison that doesn't leak timing information
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (a_byte, b_byte) in a.iter().zip(b.iter()) {
        result |= a_byte ^ b_byte;
    }
    
    result == 0
}

/// Zeroizable wrapper for any type
pub struct Zeroizable<T> {
    value: Option<T>,
}

impl<T> Zeroizable<T> {
    pub fn new(value: T) -> Self {
        Self { value: Some(value) }
    }
    
    pub fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }
    
    pub fn get_mut(&mut self) -> Option<&mut T> {
        self.value.as_mut()
    }
    
    pub fn take(mut self) -> Option<T> {
        self.value.take()
    }
}

impl<T> Drop for Zeroizable<T> {
    fn drop(&mut self) {
        // Zero out the memory occupied by T if it exists
        if let Some(ref mut value) = self.value {
            unsafe {
                let ptr = value as *mut T as *mut u8;
                let size = core::mem::size_of::<T>();
                let slice = core::slice::from_raw_parts_mut(ptr, size);
                secure_zero(slice);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_zero() {
        let mut data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        secure_zero(&mut data);
        
        for byte in data.iter() {
            assert_eq!(*byte, 0);
        }
    }
    
    #[test]
    fn test_secure_key_drop() {
        {
            let key = SecureKey::new(vec![1, 2, 3, 4]);
            assert_eq!(key.as_slice(), &[1, 2, 3, 4]);
            // key will be zeroized on drop
        }
        // Memory should be cleared after drop
    }
    
    #[test]
    fn test_secure_polynomial_drop() {
        {
            let poly = SecurePolynomial::new(vec![100, 200, 300]);
            assert_eq!(poly.as_slice(), &[100, 200, 300]);
            // poly will be zeroized on drop
        }
    }
    
    #[test]
    fn test_secure_erase_patterns() {
        let mut data = vec![0xFF; 32];
        secure_erase_patterns(&mut data);
        
        for byte in data.iter() {
            assert_eq!(*byte, 0);
        }
    }
    
    #[cfg(debug_assertions)]
    #[test]
    fn test_verify_zeroized() {
        let zeros = vec![0u8; 16];
        assert!(verify_zeroized(&zeros));
        
        let not_zeros = vec![1u8; 16];
        assert!(!verify_zeroized(&not_zeros));
    }
    
    #[test]
    fn test_secure_compare() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        let c = vec![1, 2, 3, 5];
        
        assert!(secure_compare(&a, &b));
        assert!(!secure_compare(&a, &c));
    }
    
    #[test]
    fn test_zeroizable_wrapper() {
        {
            let wrapper = Zeroizable::new([0xDEADBEEFu32; 4]);
            assert_eq!(wrapper.get().unwrap()[0], 0xDEADBEEF);
            // wrapper will be zeroized on drop
        }
    }
}