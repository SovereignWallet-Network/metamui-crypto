//! Memory security utilities for Dilithium
//!
//! Provides secure memory operations including clearing and constant-time
//! operations. Several primitives are kept here for completeness even when
//! the current signing path only exercises a subset — they're part of the
//! documented CT surface. Module-level allow stops the lint churn.

#![allow(dead_code)]

use metamui_security_utils::Zeroize;

/// Securely clear a byte array
pub fn secure_clear(data: &mut [u8]) {
    data.zeroize();
}

/// Securely clear a u32 array
pub fn secure_clear_u32(data: &mut [u32]) {
    for item in data.iter_mut() {
        unsafe {
            std::ptr::write_volatile(item, 0);
        }
    }
}

/// Securely clear an i32 array
pub fn secure_clear_i32(data: &mut [i32]) {
    for item in data.iter_mut() {
        unsafe {
            std::ptr::write_volatile(item, 0);
        }
    }
}

/// Memory barrier to prevent compiler optimizations
#[inline(always)]
pub fn memory_barrier() {
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Constant-time memory comparison
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    
    diff == 0
}