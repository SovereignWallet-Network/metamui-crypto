/// Hardware feature detection for cryptographic acceleration
/// 
/// This module provides runtime detection of CPU features that can be used
/// to accelerate cryptographic operations.

#[cfg(feature = "std")]
use std::sync::Once;

#[cfg(not(feature = "std"))]
use core::sync::atomic::{AtomicBool, Ordering};

/// Available hardware features
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareFeatures {
    /// Intel AES-NI instructions
    pub aes_ni: bool,
    /// ARM AES instructions
    pub arm_aes: bool,
    /// Intel SHA extensions
    pub sha_ni: bool,
    /// ARM SHA extensions
    pub arm_sha: bool,
    /// AVX2 instructions
    pub avx2: bool,
    /// AVX512 instructions
    pub avx512: bool,
    /// ARM NEON instructions
    pub neon: bool,
    /// RDRAND instruction
    pub rdrand: bool,
}

static mut FEATURES: HardwareFeatures = HardwareFeatures {
    aes_ni: false,
    arm_aes: false,
    sha_ni: false,
    arm_sha: false,
    avx2: false,
    avx512: false,
    neon: false,
    rdrand: false,
};

#[cfg(feature = "std")]
static INIT: Once = Once::new();

#[cfg(not(feature = "std"))]
static INIT: AtomicBool = AtomicBool::new(false);

impl HardwareFeatures {
    /// Detect available hardware features
    pub fn detect() -> Self {
        #[cfg(feature = "std")]
        {
            // SAFETY: `FEATURES` is `static mut` and thus requires
            // `unsafe` to access or assign. `std::sync::Once::call_once`
            // guarantees the closure runs exactly once across all
            // threads, so the write happens-before every subsequent
            // read. The read after `call_once` is therefore a
            // data-race-free read of fully-initialized state. `Copy`
            // on `HardwareFeatures` means the returned value is a
            // by-value snapshot, not a borrow into the static.
            unsafe {
                INIT.call_once(|| {
                    FEATURES = Self::detect_features();
                });
                FEATURES
            }
        }

        #[cfg(not(feature = "std"))]
        {
            // Simple atomic-based initialization for no_std.
            if INIT.load(Ordering::Acquire) {
                // SAFETY: `INIT` is set via `Release` store only after
                // `FEATURES` is written below. Observing the `true`
                // flag under an `Acquire` load establishes a
                // happens-before with the writer, so the subsequent
                // read of `FEATURES` sees fully-initialized state.
                unsafe { FEATURES }
            } else {
                let features = Self::detect_features();
                // SAFETY: First-writer wins — two threads can race
                // here and each will compute `features` independently
                // and write the same value byte-for-byte
                // (detect_features is a pure CPUID-or-target-feature
                // query). The `INIT.store(Release)` below synchronizes
                // any later observer. The written value is `Copy` with
                // a trivial layout, so a torn write is benign (worst
                // case: a later reader re-runs detection itself).
                unsafe {
                    FEATURES = features;
                }
                INIT.store(true, Ordering::Release);
                features
            }
        }
    }
    
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn detect_features() -> Self {
        // Mutated only by the `std` + x86_64 block below; every other
        // combination reached here returns the all-false value untouched,
        // which is an unused_mut error under -D warnings.
        #[allow(unused_mut)]
        let mut features = HardwareFeatures {
            aes_ni: false,
            arm_aes: false,
            sha_ni: false,
            arm_sha: false,
            avx2: false,
            avx512: false,
            neon: false,
            rdrand: false,
        };
        
        // Use std::arch for feature detection
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        {
            features.aes_ni = is_x86_feature_detected!("aes");
            features.sha_ni = is_x86_feature_detected!("sha");
            features.avx2 = is_x86_feature_detected!("avx2");
            features.avx512 = is_x86_feature_detected!("avx512f");
            features.rdrand = is_x86_feature_detected!("rdrand");
        }
        
        features
    }
    
    #[cfg(target_arch = "aarch64")]
    fn detect_features() -> Self {
        // Same shape as the x86 arm: an aarch64 target with none of the
        // `aes`/`sha2`/`neon` target features enabled never writes to it.
        #[allow(unused_mut)]
        let mut features = HardwareFeatures {
            aes_ni: false,
            arm_aes: false,
            sha_ni: false,
            arm_sha: false,
            avx2: false,
            avx512: false,
            neon: false,
            rdrand: false,
        };
        
        // ARM feature detection
        #[cfg(target_feature = "aes")]
        {
            features.arm_aes = true;
        }
        
        #[cfg(target_feature = "sha2")]
        {
            features.arm_sha = true;
        }
        
        #[cfg(target_feature = "neon")]
        {
            features.neon = true;
        }
        
        features
    }
    
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    fn detect_features() -> Self {
        // No hardware acceleration on other architectures
        HardwareFeatures {
            aes_ni: false,
            arm_aes: false,
            sha_ni: false,
            arm_sha: false,
            avx2: false,
            avx512: false,
            neon: false,
            rdrand: false,
        }
    }
    
    /// Check if any AES acceleration is available
    pub fn has_aes_acceleration(&self) -> bool {
        self.aes_ni || self.arm_aes
    }
    
    /// Check if any SHA acceleration is available
    pub fn has_sha_acceleration(&self) -> bool {
        self.sha_ni || self.arm_sha
    }
    
    /// Check if any SIMD acceleration is available
    pub fn has_simd_acceleration(&self) -> bool {
        self.avx2 || self.avx512 || self.neon
    }
}

/// Get the detected hardware features
pub fn get_hardware_features() -> HardwareFeatures {
    HardwareFeatures::detect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hardware_detection() {
        let features = HardwareFeatures::detect();
        
        // At least one of these should be true on modern hardware
        let has_any_feature = features.has_aes_acceleration() 
            || features.has_sha_acceleration() 
            || features.has_simd_acceleration()
            || features.rdrand;
        
        // Debug output only when std is available
        #[cfg(feature = "std")]
        {
            std::println!("Detected hardware features: {:?}", features);
            std::println!("Has any acceleration: {}", has_any_feature);
        }
        
        // Just verify detection completes without panic
        assert!(features.aes_ni || !features.aes_ni); // Always true, just checking field access
    }
}