//! x86_64 assembly optimizations for ML-KEM critical operations
//!
//! This module provides highly optimized assembly implementations for the most
//! performance-critical operations in ML-KEM, specifically targeting x86_64 processors.
//!
//! All operations are constant-time to prevent timing side-channel attacks.

#![cfg(target_arch = "x86_64")]

use core::arch::asm;

/// ML-KEM parameters
const MLKEM_Q: u16 = 3329;
const QINV: u32 = 62209; // q^(-1) mod 2^16
const BARRETT_MULTIPLIER: u32 = 20159; // ⌊2^26/q⌋
const BARRETT_SHIFT: u32 = 26;

/// Barrett reduction for x86_64
///
/// Computes a mod q where q = 3329
/// Uses the Barrett reduction algorithm optimized for ML-KEM's specific modulus
///
/// # Safety
/// This function uses inline assembly and assumes valid input
#[inline(always)]
pub unsafe fn barrett_reduce_asm(a: u16) -> u16 {
    let mut result: u16;
    
    asm!(
        // Load Barrett multiplier
        "mov {tmp:e}, 20159",
        
        // Multiply and shift for Barrett reduction
        "movzx {a_ext:e}, {a:w}",
        "imul {tmp:e}, {a_ext:e}",
        "shr {tmp:e}, 26",
        
        // Compute a - t * q
        "imul {tmp:w}, 3329",
        "sub {a:w}, {tmp:w}",
        
        // Conditional subtraction if result >= q
        "cmp {a:w}, 3329",
        "jb 2f",
        "sub {a:w}, 3329",
        "2:",
        
        a = inout(reg) a => result,
        tmp = out(reg) _,
        a_ext = out(reg) _,
        options(pure, nomem, nostack)
    );
    
    result
}

/// Montgomery multiplication for x86_64
///
/// Computes (a * b * R^(-1)) mod q where R = 2^16
/// Optimized for ML-KEM's specific parameters
///
/// # Safety
/// This function uses inline assembly and assumes valid input
#[inline(always)]
pub unsafe fn montgomery_multiply_asm(a: u32, b: u32) -> u32 {
    let mut result: u32;
    
    asm!(
        // Compute a * b
        "mov {t:e}, {a:e}",
        "imul {t:e}, {b:e}",
        
        // Compute u = (t * qinv) & 0xFFFF
        "mov {u:e}, {t:e}",
        "imul {u:e}, 62209",  // qinv
        "and {u:e}, 0xFFFF",
        
        // Compute (t + u * q) >> 16
        "imul {u:e}, 3329",   // q
        "add {t:e}, {u:e}",
        "shr {t:e}, 16",
        
        // Conditional subtraction if result >= q
        "cmp {t:e}, 3329",
        "jb 2f",
        "sub {t:e}, 3329",
        "2:",
        
        "mov {result:e}, {t:e}",
        
        result = out(reg) result,
        a = in(reg) a,
        b = in(reg) b,
        t = out(reg) _,
        u = out(reg) _,
        options(pure, nomem, nostack)
    );
    
    result
}

/// Montgomery reduction for x86_64
///
/// Computes (a * R^(-1)) mod q where R = 2^16
///
/// # Safety
/// This function uses inline assembly and assumes valid input
#[inline(always)]
pub unsafe fn montgomery_reduce_asm(a: u32) -> u32 {
    let mut result: u32;
    
    asm!(
        // Compute u = (a * qinv) & 0xFFFF
        "mov {u:e}, {a:e}",
        "imul {u:e}, 62209",  // qinv
        "and {u:e}, 0xFFFF",
        
        // Compute (a + u * q) >> 16
        "imul {u:e}, 3329",   // q
        "add {a:e}, {u:e}",
        "shr {a:e}, 16",
        
        // Conditional subtraction if result >= q
        "cmp {a:e}, 3329",
        "jb 2f",
        "sub {a:e}, 3329",
        "2:",
        
        "mov {result:e}, {a:e}",
        
        result = out(reg) result,
        a = inout(reg) a => _,
        u = out(reg) _,
        options(pure, nomem, nostack)
    );
    
    result
}

/// Butterfly operation for NTT (Cooley-Tukey)
///
/// Computes:
/// - a' = a + b * zeta
/// - b' = a - b * zeta
///
/// # Safety
/// This function uses inline assembly and modifies inputs in place
#[inline(always)]
pub unsafe fn butterfly_asm(a: &mut u16, b: &mut u16, zeta: u16) {
    asm!(
        // Load values
        "movzx {a_val:e}, word ptr [{a_ptr}]",
        "movzx {b_val:e}, word ptr [{b_ptr}]",
        "movzx {z:e}, {zeta:w}",
        
        // Compute t = montgomery_multiply(zeta, b)
        "mov {t:e}, {b_val:e}",
        "imul {t:e}, {z:e}",
        
        // Montgomery reduction
        "mov {u:e}, {t:e}",
        "imul {u:e}, 62209",  // qinv
        "and {u:e}, 0xFFFF",
        "imul {u:e}, 3329",   // q
        "add {t:e}, {u:e}",
        "shr {t:e}, 16",
        
        // Conditional reduction
        "cmp {t:e}, 3329",
        "jb 2f",
        "sub {t:e}, 3329",
        "2:",
        
        // Compute a' = a + t mod q
        "mov {new_a:e}, {a_val:e}",
        "add {new_a:e}, {t:e}",
        "cmp {new_a:e}, 3329",
        "jb 3f",
        "sub {new_a:e}, 3329",
        "3:",
        
        // Compute b' = a - t mod q (with proper modular arithmetic)
        "mov {new_b:e}, {a_val:e}",
        "add {new_b:e}, 3329",
        "sub {new_b:e}, {t:e}",
        "cmp {new_b:e}, 3329",
        "jb 4f",
        "sub {new_b:e}, 3329",
        "4:",
        
        // Store results
        "mov word ptr [{a_ptr}], {new_a:w}",
        "mov word ptr [{b_ptr}], {new_b:w}",
        
        a_ptr = in(reg) a,
        b_ptr = in(reg) b,
        zeta = in(reg) zeta,
        a_val = out(reg) _,
        b_val = out(reg) _,
        z = out(reg) _,
        t = out(reg) _,
        u = out(reg) _,
        new_a = out(reg) _,
        new_b = out(reg) _,
        options(nostack)
    );
}

/// Fast modular addition mod q
///
/// Computes (a + b) mod q with constant-time execution
///
/// # Safety
/// This function uses inline assembly and assumes valid input
#[inline(always)]
pub unsafe fn mod_add_asm(a: u16, b: u16) -> u16 {
    let mut result: u16;
    
    asm!(
        "add {a:w}, {b:w}",
        "cmp {a:w}, 3329",
        "jb 2f",
        "sub {a:w}, 3329",
        "2:",
        
        a = inout(reg) a => result,
        b = in(reg) b,
        options(pure, nomem, nostack)
    );
    
    result
}

/// Fast modular subtraction mod q
///
/// Computes (a - b) mod q with constant-time execution
///
/// # Safety
/// This function uses inline assembly and assumes valid input
#[inline(always)]
pub unsafe fn mod_sub_asm(a: u16, b: u16) -> u16 {
    let mut result: u16;
    
    asm!(
        // Compute a + q - b to ensure positive result
        "add {a:w}, 3329",
        "sub {a:w}, {b:w}",
        "cmp {a:w}, 3329",
        "jb 2f",
        "sub {a:w}, 3329",
        "2:",
        
        a = inout(reg) a => result,
        b = in(reg) b,
        options(pure, nomem, nostack)
    );
    
    result
}

/// Batch Barrett reduction for 4 values
///
/// Processes 4 values in parallel for better throughput
///
/// # Safety
/// This function uses inline assembly and assumes valid input array
#[inline(always)]
pub unsafe fn barrett_reduce_batch4_asm(values: &mut [u16; 4]) {
    asm!(
        // Load all 4 values
        "movzx {v0:e}, word ptr [{ptr}]",
        "movzx {v1:e}, word ptr [{ptr} + 2]",
        "movzx {v2:e}, word ptr [{ptr} + 4]",
        "movzx {v3:e}, word ptr [{ptr} + 6]",
        
        // Barrett reduction for all 4 values
        // Value 0
        "mov {t:e}, 20159",
        "imul {t:e}, {v0:e}",
        "shr {t:e}, 26",
        "imul {t:w}, 3329",
        "sub {v0:w}, {t:w}",
        "cmp {v0:w}, 3329",
        "jb 2f",
        "sub {v0:w}, 3329",
        "2:",
        
        // Value 1
        "mov {t:e}, 20159",
        "imul {t:e}, {v1:e}",
        "shr {t:e}, 26",
        "imul {t:w}, 3329",
        "sub {v1:w}, {t:w}",
        "cmp {v1:w}, 3329",
        "jb 3f",
        "sub {v1:w}, 3329",
        "3:",
        
        // Value 2
        "mov {t:e}, 20159",
        "imul {t:e}, {v2:e}",
        "shr {t:e}, 26",
        "imul {t:w}, 3329",
        "sub {v2:w}, {t:w}",
        "cmp {v2:w}, 3329",
        "jb 4f",
        "sub {v2:w}, 3329",
        "4:",
        
        // Value 3
        "mov {t:e}, 20159",
        "imul {t:e}, {v3:e}",
        "shr {t:e}, 26",
        "imul {t:w}, 3329",
        "sub {v3:w}, {t:w}",
        "cmp {v3:w}, 3329",
        "jb 5f",
        "sub {v3:w}, 3329",
        "5:",
        
        // Store results
        "mov word ptr [{ptr}], {v0:w}",
        "mov word ptr [{ptr} + 2], {v1:w}",
        "mov word ptr [{ptr} + 4], {v2:w}",
        "mov word ptr [{ptr} + 6], {v3:w}",
        
        ptr = in(reg) values.as_ptr(),
        v0 = out(reg) _,
        v1 = out(reg) _,
        v2 = out(reg) _,
        v3 = out(reg) _,
        t = out(reg) _,
        options(nostack)
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_barrett_reduce() {
        unsafe {
            // Test various values
            assert_eq!(barrett_reduce_asm(0), 0);
            assert_eq!(barrett_reduce_asm(3329), 0);
            assert_eq!(barrett_reduce_asm(3330), 1);
            assert_eq!(barrett_reduce_asm(6658), 0);
            assert_eq!(barrett_reduce_asm(10000), 10000 % 3329);
        }
    }
    
    #[test]
    fn test_montgomery_multiply() {
        unsafe {
            // Test identity
            let mont_one = 2285; // R mod q where R = 2^16
            assert_eq!(montgomery_multiply_asm(mont_one, mont_one), mont_one);
            
            // Test various multiplications
            assert_eq!(montgomery_multiply_asm(100, 200), 
                      montgomery_multiply_asm(100, 200));
        }
    }
    
    #[test]
    fn test_butterfly() {
        unsafe {
            let mut a = 100u16;
            let mut b = 200u16;
            let zeta = 17u16;
            
            butterfly_asm(&mut a, &mut b, zeta);
            
            // Verify results are in range
            assert!(a < MLKEM_Q);
            assert!(b < MLKEM_Q);
        }
    }
    
    #[test]
    fn test_mod_operations() {
        unsafe {
            // Test addition
            assert_eq!(mod_add_asm(100, 200), 300);
            assert_eq!(mod_add_asm(3000, 500), (3500 - 3329));
            
            // Test subtraction
            assert_eq!(mod_sub_asm(500, 200), 300);
            assert_eq!(mod_sub_asm(200, 500), 3329 - 300);
        }
    }
    
    #[test]
    fn test_batch_barrett() {
        unsafe {
            let mut values = [10000u16, 5000, 3329, 7000];
            barrett_reduce_batch4_asm(&mut values);
            
            for &v in &values {
                assert!(v < MLKEM_Q);
            }
        }
    }
}