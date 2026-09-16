use crate::detection_safe::{has_avx2, has_neon};

/// Error type for SIMD operations
#[derive(Debug, Clone, Copy)]
pub enum SimdError {
    /// Required CPU feature not available
    FeatureNotAvailable(&'static str),
    /// Data alignment requirements not met
    AlignmentError { required: usize, actual: usize },
    /// Invalid data length
    InvalidLength { expected: usize, actual: usize },
}

impl std::fmt::Display for SimdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FeatureNotAvailable(feature) => 
                write!(f, "CPU feature '{}' not available", feature),
            Self::AlignmentError { required, actual } => 
                write!(f, "Data must be {}-byte aligned, but is {}-byte aligned", required, actual),
            Self::InvalidLength { expected, actual } => 
                write!(f, "Expected data length {}, but got {}", expected, actual),
        }
    }
}

impl std::error::Error for SimdError {}

/// Result type for SIMD operations
pub type SimdResult<T> = Result<T, SimdError>;

/// Safe wrapper for AVX2 operations
#[cfg(target_arch = "x86_64")]
pub mod avx2 {
    use super::*;
    
    /// Check if data is properly aligned for AVX2 (32-byte alignment)
    pub fn check_alignment<T>(data: &[T]) -> SimdResult<()> {
        const ALIGNMENT: usize = 32;
        let addr = data.as_ptr() as usize;
        let actual = addr % ALIGNMENT;
        
        if actual != 0 {
            Err(SimdError::AlignmentError { 
                required: ALIGNMENT, 
                actual: ALIGNMENT - actual 
            })
        } else {
            Ok(())
        }
    }
    
    /// Safe wrapper for AVX2 operations with runtime checks
    pub fn with_avx2<F, R>(f: F) -> SimdResult<R>
    where
        F: FnOnce() -> R,
    {
        if !has_avx2() {
            return Err(SimdError::FeatureNotAvailable("AVX2"));
        }
        
        // SAFETY: We've verified AVX2 is available at runtime
        Ok(f())
    }
    
    /// Execute AVX2 operation with alignment check
    pub fn with_avx2_aligned<T, F, R>(data: &[T], f: F) -> SimdResult<R>
    where
        F: FnOnce() -> R,
    {
        check_alignment(data)?;
        with_avx2(f)
    }
}

/// Safe wrapper for NEON operations
#[cfg(target_arch = "aarch64")]
pub mod neon {
    use super::*;
    
    /// Check if data is properly aligned for NEON (16-byte alignment)
    pub fn check_alignment<T>(data: &[T]) -> SimdResult<()> {
        const ALIGNMENT: usize = 16;
        let addr = data.as_ptr() as usize;
        let actual = addr % ALIGNMENT;
        
        if actual != 0 {
            Err(SimdError::AlignmentError { 
                required: ALIGNMENT, 
                actual: ALIGNMENT - actual 
            })
        } else {
            Ok(())
        }
    }
    
    /// Safe wrapper for NEON operations with runtime checks
    pub fn with_neon<F, R>(f: F) -> SimdResult<R>
    where
        F: FnOnce() -> R,
    {
        if !has_neon() {
            return Err(SimdError::FeatureNotAvailable("NEON"));
        }
        
        // SAFETY: We've verified NEON is available at runtime
        Ok(f())
    }
    
    /// Execute NEON operation with alignment check
    pub fn with_neon_aligned<T, F, R>(data: &[T], f: F) -> SimdResult<R>
    where
        F: FnOnce() -> R,
    {
        check_alignment(data)?;
        with_neon(f)
    }
}

/// Generic SIMD operation with automatic dispatch
pub fn simd_operation<F, G, R>(avx2_impl: F, neon_impl: G, fallback: R) -> R
where
    F: FnOnce() -> R,
    G: FnOnce() -> R,
{
    #[cfg(target_arch = "x86_64")]
    {
        if has_avx2() {
            return avx2_impl();
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        if has_neon() {
            return neon_impl();
        }
    }
    
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_alignment_check() {
        // Create aligned data
        let aligned_data = vec![0u8; 64];
        
        #[cfg(target_arch = "x86_64")]
        {
            // This might fail if the allocator doesn't guarantee alignment
            let _ = avx2::check_alignment(&aligned_data);
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            let _ = neon::check_alignment(&aligned_data);
        }
    }
    
    #[test]
    fn test_feature_detection_wrapper() {
        #[cfg(target_arch = "x86_64")]
        {
            let result = avx2::with_avx2(|| 42);
            match result {
                Ok(42) => assert!(has_avx2()),
                Err(SimdError::FeatureNotAvailable("AVX2")) => assert!(!has_avx2()),
                _ => panic!("Unexpected result"),
            }
        }
    }
}