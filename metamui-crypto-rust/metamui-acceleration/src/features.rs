//! Hardware feature detection

/// Available hardware features
#[derive(Debug, Clone, Copy, Default)]
pub struct HardwareFeatures {
    // x86/x64 features
    pub has_sse: bool,
    pub has_sse2: bool,
    pub has_sse3: bool,
    pub has_ssse3: bool,
    pub has_sse41: bool,
    pub has_sse42: bool,
    pub has_avx: bool,
    pub has_avx2: bool,
    pub has_avx512f: bool,
    pub has_aes: bool,
    pub has_pclmulqdq: bool,
    pub has_rdrand: bool,
    pub has_rdseed: bool,
    pub has_sha: bool,
    
    // ARM features
    pub has_neon: bool,
    pub has_crc32: bool,
    pub has_crypto: bool,
    pub has_sve: bool,
    pub has_sve2: bool,
    
    // General features
    pub cpu_count: usize,
    pub cache_line_size: usize,
}

/// Detect available hardware features
pub fn detect_features() -> HardwareFeatures {
    let mut features = HardwareFeatures::default();
    
    // Set common defaults
    features.cpu_count = 1; // Conservative default
    features.cache_line_size = 64; // Common cache line size
    
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        crate::x86::detect_x86_features(&mut features);
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        crate::aarch64::detect_arm_features(&mut features);
    }
    
    features
}

impl HardwareFeatures {
    /// Check if any SIMD acceleration is available
    pub fn has_simd(&self) -> bool {
        self.has_sse2 || self.has_neon || self.has_avx
    }
    
    /// Check if cryptographic acceleration is available
    pub fn has_crypto_acceleration(&self) -> bool {
        self.has_aes || self.has_sha || self.has_crypto
    }
    
    /// Get optimal vector width in bytes
    pub fn optimal_vector_width(&self) -> usize {
        if self.has_avx512f {
            64
        } else if self.has_avx2 {
            32
        } else if self.has_sse2 || self.has_neon {
            16
        } else {
            8
        }
    }
    
    /// Check if hardware random is available
    pub fn has_hardware_random(&self) -> bool {
        self.has_rdrand || self.has_rdseed
    }
}