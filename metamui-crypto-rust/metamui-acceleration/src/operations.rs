//! High-level accelerated operations interface

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use alloc::vec;

/// Trait for accelerated operations
pub trait AcceleratedOps {
    /// XOR two byte arrays
    fn xor(&self, a: &[u8], b: &[u8], out: &mut [u8]);
    
    /// Generate random bytes (if hardware RNG available)
    fn random_bytes(&self, out: &mut [u8]) -> bool;
    
    /// Check if this implementation uses hardware acceleration
    fn is_accelerated(&self) -> bool;
    
    /// Get name of acceleration method
    fn acceleration_type(&self) -> &'static str;
}

/// Software fallback implementation
pub struct SoftwareOps;

impl AcceleratedOps for SoftwareOps {
    fn xor(&self, a: &[u8], b: &[u8], out: &mut [u8]) {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), out.len());
        
        for i in 0..a.len() {
            out[i] = a[i] ^ b[i];
        }
    }
    
    fn random_bytes(&self, _out: &mut [u8]) -> bool {
        // No hardware RNG available
        false
    }
    
    fn is_accelerated(&self) -> bool {
        false
    }
    
    fn acceleration_type(&self) -> &'static str {
        "software"
    }
}

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2"))]
pub struct Avx2Ops;

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2"))]
impl AcceleratedOps for Avx2Ops {
    fn xor(&self, a: &[u8], b: &[u8], out: &mut [u8]) {
        // SAFETY: This whole `impl` block is gated on
        // `target_feature = "avx2"`, so the AVX2 intrinsics inside
        // `xor_blocks` are valid on every CPU that this code was
        // compiled for. The called function's `/// # Safety` doc
        // states it requires AVX2, and we satisfy that at compile
        // time. Slice arguments are forwarded verbatim; length
        // invariants (equal lengths) are asserted inside.
        unsafe {
            crate::x86::avx2::xor_blocks(a, b, out);
        }
    }

    #[cfg(target_feature = "rdrand")]
    fn random_bytes(&self, out: &mut [u8]) -> bool {
        // SAFETY: Gated on `target_feature = "rdrand"` so the RDRAND
        // instruction is available. `fill_random` consumes the
        // `&mut [u8]` exclusively and writes `out.len()` bytes at
        // most; the slice's provenance and length are preserved.
        unsafe {
            crate::x86::rdrand::fill_random(out)
        }
    }
    
    #[cfg(not(target_feature = "rdrand"))]
    fn random_bytes(&self, _out: &mut [u8]) -> bool {
        false
    }
    
    fn is_accelerated(&self) -> bool {
        true
    }
    
    fn acceleration_type(&self) -> &'static str {
        "AVX2"
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub struct NeonOps;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
impl AcceleratedOps for NeonOps {
    fn xor(&self, a: &[u8], b: &[u8], out: &mut [u8]) {
        // SAFETY: Gated on `target_feature = "neon"`, so the NEON
        // intrinsics inside `xor_blocks` are compile-time guaranteed
        // available. Slice arguments forward verbatim; length
        // invariants (equal lengths) are asserted inside.
        unsafe {
            crate::aarch64::neon::xor_blocks(a, b, out);
        }
    }
    
    fn random_bytes(&self, _out: &mut [u8]) -> bool {
        // ARM doesn't have a standard hardware RNG instruction
        false
    }
    
    fn is_accelerated(&self) -> bool {
        true
    }
    
    fn acceleration_type(&self) -> &'static str {
        "NEON"
    }
}

/// Get the best available accelerated operations for the current CPU
pub fn get_accelerated_ops() -> Box<dyn AcceleratedOps> {
    let features = crate::detect_features();
    
    // Check for x86/x64 acceleration
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if features.has_avx2 {
            #[cfg(target_feature = "avx2")]
            return Box::new(Avx2Ops);
        }
    }
    
    // Check for ARM acceleration
    #[cfg(target_arch = "aarch64")]
    {
        if features.has_neon {
            #[cfg(target_feature = "neon")]
            return Box::new(NeonOps);
        }
    }
    
    // Other architectures (wasm32, armv7, …) have no accelerated backend;
    // the feature report is still computed so the API is uniform.
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    let _ = &features;

    // Fallback to software
    Box::new(SoftwareOps)
}

/// Utility function for accelerated XOR
pub fn xor_accelerated(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; a.len()];
    let ops = get_accelerated_ops();
    ops.xor(a, b, &mut result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_software_xor() {
        let a = vec![0x11, 0x22, 0x33, 0x44];
        let b = vec![0x55, 0x66, 0x77, 0x88];
        let mut out = vec![0; 4];
        
        let ops = SoftwareOps;
        ops.xor(&a, &b, &mut out);
        
        assert_eq!(out, vec![0x44, 0x44, 0x44, 0xCC]);
    }
    
    #[test]
    fn test_accelerated_ops_selection() {
        let ops = get_accelerated_ops();
        
        // Should get some implementation
        assert!(!ops.acceleration_type().is_empty());
        
        // Test basic XOR
        let a = vec![0xFF; 32];
        let b = vec![0xAA; 32];
        let mut out = vec![0; 32];
        
        ops.xor(&a, &b, &mut out);
        
        for byte in out {
            assert_eq!(byte, 0x55);
        }
    }
}