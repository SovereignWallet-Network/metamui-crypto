//! Backend selector for automatic runtime selection

use super::{BackendEnum, CpuFeatures};
use super::reference::ReferenceBackend;

#[cfg(feature = "simd")]
use super::simd_backend::SimdBackend;

#[cfg(feature = "gpu")]
use super::gpu_backend::GpuBackend;

/// Backend selector for automatic runtime backend selection
pub struct BackendSelector;

impl BackendSelector {
    /// Select the best available backend based on platform capabilities
    pub fn select() -> BackendEnum {
        let _features = CpuFeatures::detect();
        
        // Check GPU availability first
        #[cfg(feature = "gpu")]
        {
            if crate::gpu::GpuDevice::is_available() {
                if let Ok(gpu) = GpuBackend::new() {
                    return BackendEnum::Gpu(gpu);
                }
            }
        }
        
        // Check SIMD availability
        #[cfg(feature = "simd")]
        {
            #[cfg(all(target_arch = "aarch64", feature = "neon"))]
            {
                if features.neon {
                    if let Ok(simd) = SimdBackend::new() {
                        return BackendEnum::Simd(simd);
                    }
                }
            }
            
            #[cfg(target_arch = "x86_64")]
            {
                if features.avx2 || features.avx512 {
                    if let Ok(simd) = SimdBackend::new() {
                        return BackendEnum::Simd(simd);
                    }
                }
            }
        }
        
        // Default to reference implementation
        BackendEnum::Reference(ReferenceBackend::new())
    }
    
    /// Select backend by name
    pub fn select_by_name(name: &str) -> Option<BackendEnum> {
        match name.to_lowercase().as_str() {
            "reference" => Some(BackendEnum::Reference(ReferenceBackend::new())),
            
            #[cfg(feature = "simd")]
            "simd" | "neon" | "avx2" | "avx512" => {
                SimdBackend::new().ok().map(BackendEnum::Simd)
            }
            
            #[cfg(feature = "gpu")]
            "gpu" | "webgpu" => {
                GpuBackend::new().ok().map(BackendEnum::Gpu)
            }
            
            _ => None,
        }
    }
}