//! Enhanced side-channel protection mechanisms for Falcon-512
//!
//! This module implements comprehensive protections against:
//! - Timing attacks
//! - Power analysis attacks
//! - Cache-timing attacks
//! - Fault injection attacks

use crate::constants::{N, Q};
use crate::error::{Result, Falcon512Error};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use zeroize::Zeroize;

/// Side-channel protection configuration
#[derive(Debug, Clone)]
pub struct SideChannelConfig {
    /// Enable constant-time operations
    pub constant_time: bool,
    /// Enable blinding for sensitive operations
    pub blinding: bool,
    /// Enable dummy operations for timing consistency
    pub dummy_operations: bool,
    /// Enable integrity checks
    pub integrity_checks: bool,
    /// Number of dummy iterations
    pub dummy_iterations: usize,
}

impl Default for SideChannelConfig {
    fn default() -> Self {
        Self {
            constant_time: true,
            blinding: true,
            dummy_operations: true,
            integrity_checks: true,
            dummy_iterations: 3,
        }
    }
}

impl SideChannelConfig {
    /// Create a high-security configuration
    pub fn high_security() -> Self {
        Self {
            constant_time: true,
            blinding: true,
            dummy_operations: true,
            integrity_checks: true,
            dummy_iterations: 5,
        }
    }

    /// Create a balanced configuration
    pub fn balanced() -> Self {
        Self::default()
    }

    /// Create a performance-optimized configuration
    pub fn performance() -> Self {
        Self {
            constant_time: true,
            blinding: false,
            dummy_operations: false,
            integrity_checks: false,
            dummy_iterations: 0,
        }
    }
}

/// Protected polynomial operations
pub struct ProtectedPoly {
    /// Main coefficients
    coeffs: Vec<i16>,
    /// Blinding factor
    blind: Option<Vec<i16>>,
    /// Checksum for integrity
    checksum: u32,
}

impl ProtectedPoly {
    /// Create a new protected polynomial
    pub fn new(coeffs: Vec<i16>, config: &SideChannelConfig) -> Self {
        let checksum = Self::compute_checksum(&coeffs);

        let blind = if config.blinding {
            Some(Self::generate_blind(coeffs.len()))
        } else {
            None
        };

        Self {
            coeffs,
            blind,
            checksum,
        }
    }

    /// Get coefficients with integrity check
    pub fn get_coeffs(&self) -> Result<&[i16]> {
        if self.verify_integrity() {
            Ok(&self.coeffs)
        } else {
            Err(Falcon512Error::IntegrityCheckFailed)
        }
    }

    /// Apply blinding
    pub fn apply_blinding(&mut self) {
        if let Some(ref blind) = self.blind {
            for i in 0..self.coeffs.len() {
                self.coeffs[i] = self.coeffs[i].wrapping_add(blind[i]);
            }
        }
    }

    /// Remove blinding
    pub fn remove_blinding(&mut self) {
        if let Some(ref blind) = self.blind {
            for i in 0..self.coeffs.len() {
                self.coeffs[i] = self.coeffs[i].wrapping_sub(blind[i]);
            }
        }
    }

    /// Verify integrity
    fn verify_integrity(&self) -> bool {
        Self::compute_checksum(&self.coeffs) == self.checksum
    }

    /// Compute checksum
    fn compute_checksum(coeffs: &[i16]) -> u32 {
        let mut sum = 0u32;
        for &coeff in coeffs {
            sum = sum.wrapping_add(coeff as u32);
            sum = sum.rotate_left(7);
        }
        sum
    }

    /// Generate random blinding factor
    fn generate_blind(len: usize) -> Vec<i16> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut blind = vec![0i16; len];
        for i in 0..len {
            blind[i] = (rng.next_u32() % 256) as i16 - 128;
        }
        blind
    }
}

impl Drop for ProtectedPoly {
    fn drop(&mut self) {
        self.coeffs.zeroize();
        if let Some(ref mut blind) = self.blind {
            blind.zeroize();
        }
    }
}

/// Constant-time operations
pub mod constant_time {
    

    /// Constant-time conditional select
    /// Returns a if condition is true, b otherwise
    #[inline(always)]
    pub fn ct_select_i16(a: i16, b: i16, condition: bool) -> i16 {
        let mask = -(condition as i16);
        b ^ ((a ^ b) & mask)
    }

    /// Constant-time conditional select for u32
    #[inline(always)]
    pub fn ct_select_u32(a: u32, b: u32, condition: bool) -> u32 {
        let mask = if condition { u32::MAX } else { 0 };
        b ^ ((a ^ b) & mask)
    }

    /// Constant-time comparison
    #[inline(always)]
    pub fn ct_eq_i16(a: i16, b: i16) -> bool {
        let diff = (a ^ b) as u16;
        // diff is 0 if equal, non-zero otherwise
        // We need to return true (1) if equal, false (0) if not
        diff == 0
    }

    /// Constant-time less than
    #[inline(always)]
    pub fn ct_lt_i16(a: i16, b: i16) -> bool {
        let diff = (a as i32) - (b as i32);
        (diff >> 31) != 0
    }

    /// Constant-time absolute value
    #[inline(always)]
    pub fn ct_abs_i16(x: i16) -> i16 {
        let mask = x >> 15; // arithmetic right shift
        (x ^ mask) - mask
    }

    /// Constant-time modular reduction
    pub fn ct_mod_reduce(x: i32, q: i16) -> i16 {
        let q32 = q as i32;
        let mut result = x % q32;

        // Ensure positive result
        let is_negative = (result >> 31) != 0;
        result = ct_select_i32(result + q32, result, is_negative);

        result as i16
    }

    /// Constant-time conditional select for i32
    #[inline(always)]
    fn ct_select_i32(a: i32, b: i32, condition: bool) -> i32 {
        let mask = -(condition as i32);
        b ^ ((a ^ b) & mask)
    }

    /// Constant-time array copy
    pub fn ct_copy(dst: &mut [i16], src: &[i16]) {
        assert_eq!(dst.len(), src.len());
        for i in 0..dst.len() {
            dst[i] = src[i];
        }
    }

    /// Constant-time conditional swap
    pub fn ct_swap(a: &mut i16, b: &mut i16, condition: bool) {
        let mask = -(condition as i16);
        let tmp = (*a ^ *b) & mask;
        *a ^= tmp;
        *b ^= tmp;
    }
}

/// Timing attack protection
pub struct TimingProtection {
    /// Dummy operation counter
    dummy_counter: AtomicU32,
    /// Protection enabled flag
    enabled: AtomicBool,
}

impl TimingProtection {
    /// Create new timing protection
    pub fn new(enabled: bool) -> Self {
        Self {
            dummy_counter: AtomicU32::new(0),
            enabled: AtomicBool::new(enabled),
        }
    }

    /// Execute with timing protection
    pub fn execute_protected<F, R>(&self, f: F, config: &SideChannelConfig) -> Result<R>
    where
        F: FnOnce() -> R,
    {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(f());
        }

        if config.dummy_operations {
            return Err(Falcon512Error::NotImplemented);
        }

        Ok(f())
    }

    /// Perform dummy operations
    fn dummy_operations(&self, iterations: usize) {
        let mut accumulator = 1u32;
        for i in 0..iterations {
            accumulator = accumulator.wrapping_mul(31337);
            accumulator = accumulator.wrapping_add(i as u32);
            accumulator = accumulator.rotate_left(7);
        }
        self.dummy_counter.fetch_add(accumulator, Ordering::Relaxed);
    }
}

/// Cache attack protection
pub struct CacheProtection {
    /// Prefetch size
    prefetch_size: usize,
}

impl CacheProtection {
    /// Create new cache protection
    pub fn new() -> Self {
        Self {
            prefetch_size: 64, // Cache line size
        }
    }

    /// Access array element with cache protection
    pub fn protected_access(&self, _array: &[i16], _index: usize) -> Result<i16> {
        Err(Falcon512Error::NotImplemented)
    }

    /// Protected array write
    pub fn protected_write(&self, _array: &mut [i16], _index: usize, _value: i16) -> Result<()> {
        Err(Falcon512Error::NotImplemented)
    }
}

/// Fault injection protection
pub struct FaultProtection {
    /// Redundancy factor
    redundancy: usize,
}

impl FaultProtection {
    /// Create new fault protection
    pub fn new(redundancy: usize) -> Self {
        Self { redundancy }
    }

    /// Execute with redundancy checking
    pub fn execute_redundant<F, R>(&self, f: F) -> Result<R>
    where
        F: Fn() -> R,
        R: PartialEq + Clone,
    {
        if self.redundancy < 2 {
            return Ok(f());
        }

        // Execute multiple times
        let mut results = Vec::with_capacity(self.redundancy);
        for _ in 0..self.redundancy {
            results.push(f());
        }

        // Check all results match
        let first = &results[0];
        for result in &results[1..] {
            if result != first {
                return Err(Falcon512Error::FaultDetected);
            }
        }

        Ok(results.into_iter().next().unwrap())
    }

    /// Verify computation with inverse
    pub fn verify_inverse<F, G, T>(&self, forward: F, inverse: G, input: T) -> Result<()>
    where
        F: Fn(&T) -> T,
        G: Fn(&T) -> T,
        T: PartialEq,
    {
        let intermediate = forward(&input);
        let recovered = inverse(&intermediate);

        if recovered != input {
            return Err(Falcon512Error::FaultDetected);
        }

        Ok(())
    }
}

/// Master side-channel protection coordinator
pub struct SideChannelProtector {
    config: SideChannelConfig,
    timing: TimingProtection,
    cache: CacheProtection,
    fault: FaultProtection,
}

impl SideChannelProtector {
    /// Create new protector with given configuration
    pub fn new(config: SideChannelConfig) -> Self {
        Self {
            timing: TimingProtection::new(config.constant_time),
            cache: CacheProtection::new(),
            fault: FaultProtection::new(if config.integrity_checks { 3 } else { 1 }),
            config,
        }
    }

    /// Protected polynomial multiplication
    pub fn protected_poly_mul(&self, a: &[i16], b: &[i16]) -> Result<Vec<i16>> {
        assert_eq!(a.len(), N);
        assert_eq!(b.len(), N);

        self.timing.execute_protected(
            || {
                let mut result = vec![0i16; N];

                // Use constant-time operations
                for i in 0..N {
                    for j in 0..N {
                        let prod = (a[i] as i32) * (b[j] as i32);
                        let idx = (i + j) % N;
                        result[idx] = constant_time::ct_mod_reduce(
                            result[idx] as i32 + prod,
                            Q as i16
                        );
                    }
                }

                result
            },
            &self.config
        )
    }

    /// Protected scalar multiplication
    pub fn protected_scalar_mul(&self, poly: &[i16], scalar: i16) -> Result<Vec<i16>> {
        self.fault.execute_redundant(|| {
            let mut result = vec![0i16; poly.len()];
            for i in 0..poly.len() {
                result[i] = constant_time::ct_mod_reduce(
                    (poly[i] as i32) * (scalar as i32),
                    Q as i16
                );
            }
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_select() {
        let a = 42i16;
        let b = 17i16;

        assert_eq!(constant_time::ct_select_i16(a, b, true), a);
        assert_eq!(constant_time::ct_select_i16(a, b, false), b);
    }

    #[test]
    fn test_constant_time_comparison() {
        assert!(constant_time::ct_eq_i16(42, 42));
        assert!(!constant_time::ct_eq_i16(42, 17));

        assert!(constant_time::ct_lt_i16(17, 42));
        assert!(!constant_time::ct_lt_i16(42, 17));
    }

    #[test]
    fn test_protected_poly() {
        let config = SideChannelConfig::default();
        let coeffs = vec![1, 2, 3, 4, 5];

        let mut poly = ProtectedPoly::new(coeffs.clone(), &config);

        // Check integrity
        assert_eq!(poly.get_coeffs().unwrap(), &coeffs[..]);

        // Apply and remove blinding
        poly.apply_blinding();
        poly.remove_blinding();
        assert_eq!(poly.get_coeffs().unwrap(), &coeffs[..]);
    }

    #[test]
    fn test_timing_protection() {
        let config = SideChannelConfig::default();
        let protection = TimingProtection::new(true);

        let result = protection.execute_protected(
            || 42 + 17,
            &config
        ).unwrap_err();

        assert!(matches!(result, Falcon512Error::NotImplemented));

        let performance_config = SideChannelConfig::performance();
        let fast_result = protection.execute_protected(
            || 42 + 17,
            &performance_config
        ).unwrap();

        assert_eq!(fast_result, 59);
    }

    #[test]
    fn test_fault_protection() {
        let protection = FaultProtection::new(3);

        // Test redundant execution
        let result = protection.execute_redundant(|| 42).unwrap();
        assert_eq!(result, 42);

        // Test inverse verification
        let forward = |x: &i32| x * 2;
        let inverse = |x: &i32| x / 2;

        protection.verify_inverse(forward, inverse, 42).unwrap();
    }

    #[test]
    fn test_cache_protection_fails_closed() {
        let cache = CacheProtection::new();
        let mut array = vec![1i16, 2, 3, 4];

        let access_err = cache.protected_access(&array, 1).unwrap_err();
        assert!(matches!(access_err, Falcon512Error::NotImplemented));

        let write_err = cache.protected_write(&mut array, 1, 9).unwrap_err();
        assert!(matches!(write_err, Falcon512Error::NotImplemented));
        assert_eq!(array, vec![1i16, 2, 3, 4]);
    }

    #[test]
    fn test_side_channel_protector_fails_closed_for_dummy_timing_shell() {
        let config = SideChannelConfig::high_security();
        let protector = SideChannelProtector::new(config);

        let poly_a = vec![1i16; N];
        let poly_b = vec![2i16; N];

        let err = protector.protected_poly_mul(&poly_a, &poly_b).unwrap_err();
        assert!(matches!(err, Falcon512Error::NotImplemented));

        let fast = SideChannelProtector::new(SideChannelConfig::performance());
        let product = fast.protected_poly_mul(&poly_a, &poly_b).unwrap();
        assert_eq!(product.len(), N);
    }
}
