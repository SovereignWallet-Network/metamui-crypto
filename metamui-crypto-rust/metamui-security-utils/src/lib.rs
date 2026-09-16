#![no_std]
#![warn(missing_docs, rust_2018_idioms)]
#![doc = include_str!("../README.md")]

//! Native security utilities for MetaMUI cryptographic implementations.
//!
//! This crate provides constant-time operations and secure memory clearing
//! without external dependencies, ensuring full control over security-critical code.




#[cfg(feature = "std")]
extern crate std;

/// Constant-time operations for preventing timing attacks
pub mod constant_time;
/// Secure memory management and clearing operations
pub mod memory;
/// Platform-specific secure random number generation
pub mod platform_random;

pub use constant_time::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};
pub use memory::{Zeroize, ZeroizeOnDrop, Zeroizing, zero};
pub use platform_random::{fill_random_bytes, random_u32, random_u64, random_array, PlatformRandomError};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        let a = 5u32;
        let b = 5u32;
        let c = 6u32;

        assert_eq!(a.ct_eq(&b).unwrap_u8(), 1);
        assert_eq!(a.ct_eq(&c).unwrap_u8(), 0);
    }
}