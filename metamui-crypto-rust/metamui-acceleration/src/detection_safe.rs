use std::sync::OnceLock;

/// Hardware feature detection with safe initialization
#[derive(Debug, Clone, Copy, Default)]
pub struct HardwareFeatures {
    pub has_aes: bool,
    pub has_avx2: bool,
    pub has_neon: bool,
    pub has_sha: bool,
}

impl HardwareFeatures {
    /// Detect available hardware features
    fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self {
                has_aes: is_x86_feature_detected!("aes"),
                has_avx2: is_x86_feature_detected!("avx2"),
                has_sha: is_x86_feature_detected!("sha"),
                has_neon: false,
            }
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            Self {
                has_aes: std::arch::is_aarch64_feature_detected!("aes"),
                has_neon: std::arch::is_aarch64_feature_detected!("neon"),
                has_sha: std::arch::is_aarch64_feature_detected!("sha2"),
                has_avx2: false,
            }
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Self::default()
        }
    }
}

/// Global hardware features detected at runtime
static FEATURES: OnceLock<HardwareFeatures> = OnceLock::new();

/// Get detected hardware features (safe, no unsafe required)
pub fn hardware_features() -> &'static HardwareFeatures {
    FEATURES.get_or_init(HardwareFeatures::detect)
}

/// Check if AES instructions are available
pub fn has_aes() -> bool {
    hardware_features().has_aes
}

/// Check if AVX2 instructions are available
pub fn has_avx2() -> bool {
    hardware_features().has_avx2
}

/// Check if NEON instructions are available
pub fn has_neon() -> bool {
    hardware_features().has_neon
}

/// Check if SHA instructions are available
pub fn has_sha() -> bool {
    hardware_features().has_sha
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_feature_detection() {
        let features = hardware_features();
        
        // At least one feature should be detected on modern CPUs
        let has_any = features.has_aes || features.has_avx2 || 
                      features.has_neon || features.has_sha;
        
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        assert!(has_any, "No CPU features detected on modern architecture");
        
        // Features should be consistent across calls
        assert_eq!(hardware_features() as *const _, hardware_features() as *const _);
    }
}