//! MetaMUI Hardware Acceleration Support
//!
//! This crate provides hardware acceleration detection and optimized implementations
//! for cryptographic operations across different CPU architectures.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

pub mod features;
pub mod operations;
pub mod detection;

pub use features::{HardwareFeatures, detect_features};
pub use operations::{AcceleratedOps, get_accelerated_ops};
pub use detection::{get_hardware_features};

/// Re-export commonly used items
pub mod prelude {
    pub use crate::features::{HardwareFeatures, detect_features};
    pub use crate::operations::{AcceleratedOps, get_accelerated_ops};
}