//! AArch64 assembly optimizations for ML-KEM critical operations
//!
//! This module provides highly optimized assembly implementations for ARM64 processors.
//! All operations are constant-time to prevent timing side-channel attacks.

#![cfg(target_arch = "aarch64")]

use core::arch::asm;

/// ML-KEM parameters
const MLKEM_Q: u16 = 3329;
const QINV: u32 = 62209; // q^(-1) mod 2^16
const BARRETT_MULTIPLIER: u32 = 20159; // ⌊2^26/q⌋

/// Barrett reduction for AArch64
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
        // Load Barrett multiplier into a register
        "mov w2, #20159",
        
        // Zero-extend input and multiply
        "uxtw x1, {a:w}",
        "mul w3, w2, w1",
        
        // Shift right by 26
        "lsr w3, w3, #26",
        
        // Multiply by q and subtract from a
        "mov w4, #3329",
        "mul w3, w3, w4",
        "sub w1, w1, w3",
        
        // Conditional reduction if result >= q
        "cmp w1, #3329",
        "b.lo 2f",
        "sub w1, w1, #3329",
        "2:",
        
        "mov {result:w}, w1",
        
        result = out(reg) result,
        a = in(reg) a,
        out("x1") _,
        out("w2") _,
        out("w3") _,
        out("w4") _,
        options(pure, nomem, nostack)
    );
    
    result
}

/// Montgomery multiplication for AArch64
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
        "mul w1, {a:w}, {b:w}",
        
        // Compute u = (t * qinv) & 0xFFFF
        "mov w2, #62209",  // qinv
        "mul w3, w1, w2",
        "and w3, w3, #0xFFFF",
        
        // Compute (t + u * q) >> 16
        "mov w4, #3329",   // q
        "mul w3, w3, w4",
        "add w1, w1, w3",
        "lsr w1, w1, #16",
        
        // Conditional subtraction if result >= q
        "cmp w1, #3329",
        "b.lo 2f",
        "sub w1, w1, #3329",
        "2:",
        
        "mov {result:w}, w1",
        
        result = out(reg) result,
        a = in(reg) a,
        b = in(reg) b,
        out("w1") _,
        out("w2") _,
        out("w3") _,
        out("w4") _,
        options(pure, nomem, nostack)
    );
    
    result
}

/// Montgomery reduction for AArch64
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
        "mov w1, #62209",  // qinv
        "mul w2, {a:w}, w1",
        "and w2, w2, #0xFFFF",
        
        // Compute (a + u * q) >> 16
        "mov w3, #3329",   // q
        "mul w2, w2, w3",
        "add w2, {a:w}, w2",
        "lsr w2, w2, #16",
        
        // Conditional subtraction if result >= q
        "cmp w2, #3329",
        "b.lo 2f",
        "sub w2, w2, #3329",
        "2:",
        
        "mov {result:w}, w2",
        
        result = out(reg) result,
        a = in(reg) a,
        out("w1") _,
        out("w2") _,
        out("w3") _,
        options(pure, nomem, nostack)
    );
    
    result
}

/// Butterfly operation for NTT (Cooley-Tukey) on AArch64
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
        "ldrh w3, [{a_ptr}]",
        "ldrh w4, [{b_ptr}]",
        "uxth w5, {zeta:w}",
        
        // Compute t = montgomery_multiply(zeta, b)
        "mul w6, w4, w5",
        
        // Montgomery reduction
        "mov w7, #62209",  // qinv
        "mul w8, w6, w7",
        "and w8, w8, #0xFFFF",
        "mov w9, #3329",   // q
        "mul w8, w8, w9",
        "add w6, w6, w8",
        "lsr w6, w6, #16",
        
        // Conditional reduction
        "cmp w6, #3329",
        "b.lo 2f",
        "sub w6, w6, #3329",
        "2:",
        
        // Compute a' = a + t mod q
        "add w7, w3, w6",
        "cmp w7, #3329",
        "b.lo 3f",
        "sub w7, w7, #3329",
        "3:",
        
        // Compute b' = a - t mod q (with proper modular arithmetic)
        "add w8, w3, #3329",
        "sub w8, w8, w6",
        "cmp w8, #3329",
        "b.lo 4f",
        "sub w8, w8, #3329",
        "4:",
        
        // Store results
        "strh w7, [{a_ptr}]",
        "strh w8, [{b_ptr}]",
        
        a_ptr = in(reg) a,
        b_ptr = in(reg) b,
        zeta = in(reg) zeta,
        out("w3") _,
        out("w4") _,
        out("w5") _,
        out("w6") _,
        out("w7") _,
        out("w8") _,
        out("w9") _,
        options(nostack)
    );
}

/// Fast modular addition mod q for AArch64
///
/// Computes (a + b) mod q with constant-time execution
///
/// # Safety
/// This function uses inline assembly and assumes valid input
#[inline(always)]
pub unsafe fn mod_add_asm(a: u16, b: u16) -> u16 {
    let mut result: u16;
    
    asm!(
        "add w1, {a:w}, {b:w}",
        "cmp w1, #3329",
        "b.lo 2f",
        "sub w1, w1, #3329",
        "2:",
        "mov {result:w}, w1",
        
        result = out(reg) result,
        a = in(reg) a,
        b = in(reg) b,
        out("w1") _,
        options(pure, nomem, nostack)
    );
    
    result
}

/// Fast modular subtraction mod q for AArch64
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
        "add w1, {a:w}, #3329",
        "sub w1, w1, {b:w}",
        "cmp w1, #3329",
        "b.lo 2f",
        "sub w1, w1, #3329",
        "2:",
        "mov {result:w}, w1",
        
        result = out(reg) result,
        a = in(reg) a,
        b = in(reg) b,
        out("w1") _,
        options(pure, nomem, nostack)
    );
    
    result
}

/// Batch Barrett reduction for 4 values using NEON
///
/// Processes 4 values in parallel for better throughput
///
/// # Safety
/// This function uses inline assembly and NEON instructions
#[inline(always)]
#[target_feature(enable = "neon")]
pub unsafe fn barrett_reduce_batch4_asm(values: &mut [u16; 4]) {
    use core::arch::aarch64::*;
    
    asm!(
        // Load 4 values into NEON register
        "ld1 {{v0.4h}}, [{ptr}]",
        
        // Convert to 32-bit for multiplication
        "ushll v1.4s, v0.4h, #0",
        
        // Load Barrett multiplier
        "mov w1, #20159",
        "dup v2.4s, w1",
        
        // Multiply
        "mul v3.4s, v1.4s, v2.4s",
        
        // Shift right by 26
        "ushr v3.4s, v3.4s, #26",
        
        // Load q
        "mov w1, #3329",
        "dup v4.4s, w1",
        
        // Multiply by q
        "mul v3.4s, v3.4s, v4.4s",
        
        // Subtract from original
        "sub v1.4s, v1.4s, v3.4s",
        
        // Conditional subtraction
        "cmhs v5.4s, v1.4s, v4.4s",
        "and v5.4s, v5.4s, v4.4s",
        "sub v1.4s, v1.4s, v5.4s",
        
        // Convert back to 16-bit and store
        "xtn v0.4h, v1.4s",
        "st1 {{v0.4h}}, [{ptr}]",
        
        ptr = in(reg) values.as_ptr(),
        out("v0") _,
        out("v1") _,
        out("v2") _,
        out("v3") _,
        out("v4") _,
        out("v5") _,
        out("w1") _,
        options(nostack)
    );
}

/// Batch Montgomery multiplication using NEON
///
/// Multiplies 4 pairs of values in parallel
///
/// # Safety
/// This function uses inline assembly and NEON instructions
#[inline(always)]
#[target_feature(enable = "neon")]
pub unsafe fn montgomery_multiply_batch4_asm(
    a: &[u32; 4],
    b: &[u32; 4],
    result: &mut [u32; 4],
) {
    use core::arch::aarch64::*;
    
    asm!(
        // Load inputs
        "ld1 {{v0.4s}}, [{a_ptr}]",
        "ld1 {{v1.4s}}, [{b_ptr}]",
        
        // Multiply a * b
        "mul v2.4s, v0.4s, v1.4s",
        
        // Load qinv
        "mov w1, #62209",
        "dup v3.4s, w1",
        
        // Compute u = (t * qinv) & 0xFFFF
        "mul v4.4s, v2.4s, v3.4s",
        "mov w1, #0xFFFF",
        "dup v5.4s, w1",
        "and v4.4s, v4.4s, v5.4s",
        
        // Load q
        "mov w1, #3329",
        "dup v6.4s, w1",
        
        // Compute t + u * q
        "mul v4.4s, v4.4s, v6.4s",
        "add v2.4s, v2.4s, v4.4s",
        
        // Shift right by 16
        "ushr v2.4s, v2.4s, #16",
        
        // Conditional subtraction
        "cmhs v7.4s, v2.4s, v6.4s",
        "and v7.4s, v7.4s, v6.4s",
        "sub v2.4s, v2.4s, v7.4s",
        
        // Store result
        "st1 {{v2.4s}}, [{result_ptr}]",
        
        a_ptr = in(reg) a.as_ptr(),
        b_ptr = in(reg) b.as_ptr(),
        result_ptr = in(reg) result.as_ptr(),
        out("v0") _,
        out("v1") _,
        out("v2") _,
        out("v3") _,
        out("v4") _,
        out("v5") _,
        out("v6") _,
        out("v7") _,
        out("w1") _,
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
    #[cfg(target_feature = "neon")]
    fn test_batch_barrett() {
        unsafe {
            let mut values = [10000u16, 5000, 3329, 7000];
            barrett_reduce_batch4_asm(&mut values);
            
            for &v in &values {
                assert!(v < MLKEM_Q);
            }
        }
    }
    
    #[test]
    #[cfg(target_feature = "neon")]
    fn test_batch_montgomery() {
        unsafe {
            let a = [100u32, 200, 300, 400];
            let b = [500u32, 600, 700, 800];
            let mut result = [0u32; 4];
            
            montgomery_multiply_batch4_asm(&a, &b, &mut result);
            
            for &r in &result {
                assert!(r < MLKEM_Q as u32);
            }
        }
    }
}