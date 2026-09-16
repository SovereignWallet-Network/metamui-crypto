//! x86/x64 specific hardware acceleration.
//!
//! # Safety contract (applies to every `pub unsafe fn` in this file)
//!
//! Each intrinsic wrapper below is marked `unsafe fn` because its
//! behaviour is UB on CPUs that don't implement the required
//! instruction-set extension — e.g. executing `vaesenc` on a CPU
//! without AES-NI traps with `#UD` (invalid opcode), and reading the
//! `__m128i` / `__m256i` / `__m512i` vector types through a bad
//! alignment path can tear.
//!
//! Each wrapper carries a `#[target_feature(enable = "…")]` attribute
//! that promises the matching feature is available for the body's
//! intrinsics to be legal. The enclosing `#[cfg(... target_feature
//! = "…")]` guard means these wrappers are only compiled when the
//! feature is statically guaranteed for the crate build, so a
//! correctly-configured release binary can only reach the wrapper on
//! a CPU that supports it.
//!
//! Callers invoking these functions from *unrelated* target_feature
//! contexts (e.g. a function with no `#[target_feature]` attribute
//! calling one that does) must themselves gate on a runtime CPUID
//! check (`is_x86_feature_detected!("…")`) before the call; that is
//! the residual obligation reflected in the `unsafe` keyword on the
//! call site. The `operations.rs` `Avx2Ops` / `Rdrand` dispatch
//! tables already do this correctly — see the `// SAFETY:` blocks
//! there.

use crate::features::HardwareFeatures;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn detect_x86_features(features: &mut HardwareFeatures) {
    // Runtime feature detection only available with std
    #[cfg(feature = "std")]
    {
        #[cfg(target_arch = "x86_64")]
        {
            features.has_sse = is_x86_feature_detected!("sse");
            features.has_sse2 = is_x86_feature_detected!("sse2");
            features.has_sse3 = is_x86_feature_detected!("sse3");
            features.has_ssse3 = is_x86_feature_detected!("ssse3");
            features.has_sse41 = is_x86_feature_detected!("sse4.1");
            features.has_sse42 = is_x86_feature_detected!("sse4.2");
            features.has_avx = is_x86_feature_detected!("avx");
            features.has_avx2 = is_x86_feature_detected!("avx2");
            features.has_avx512f = is_x86_feature_detected!("avx512f");
            features.has_aes = is_x86_feature_detected!("aes");
            features.has_pclmulqdq = is_x86_feature_detected!("pclmulqdq");
            features.has_rdrand = is_x86_feature_detected!("rdrand");
            features.has_rdseed = is_x86_feature_detected!("rdseed");
            features.has_sha = is_x86_feature_detected!("sha");
        }

        #[cfg(target_arch = "x86")]
        {
            features.has_sse = is_x86_feature_detected!("sse");
            features.has_sse2 = is_x86_feature_detected!("sse2");
            features.has_sse3 = is_x86_feature_detected!("sse3");
            features.has_ssse3 = is_x86_feature_detected!("ssse3");
            features.has_sse41 = is_x86_feature_detected!("sse4.1");
            features.has_sse42 = is_x86_feature_detected!("sse4.2");
            features.has_avx = is_x86_feature_detected!("avx");
            features.has_avx2 = is_x86_feature_detected!("avx2");
            features.has_aes = is_x86_feature_detected!("aes");
            features.has_pclmulqdq = is_x86_feature_detected!("pclmulqdq");
            features.has_rdrand = is_x86_feature_detected!("rdrand");
            features.has_sha = is_x86_feature_detected!("sha");
        }
    }

    // Without std, we cannot detect features at runtime
    // Features will remain at their default (false) values
    #[cfg(not(feature = "std"))]
    {
        let _ = features; // Suppress unused variable warning
    }
}

// AES-NI accelerated operations
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
pub mod aes_ni {
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    
    /// AES encryption round using AES-NI
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn aes_enc_round(state: __m128i, round_key: __m128i) -> __m128i {
        _mm_aesenc_si128(state, round_key)
    }
    
    /// AES last encryption round using AES-NI
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn aes_enc_last_round(state: __m128i, round_key: __m128i) -> __m128i {
        _mm_aesenclast_si128(state, round_key)
    }
    
    /// AES decryption round using AES-NI
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn aes_dec_round(state: __m128i, round_key: __m128i) -> __m128i {
        _mm_aesdec_si128(state, round_key)
    }
    
    /// AES last decryption round using AES-NI
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn aes_dec_last_round(state: __m128i, round_key: __m128i) -> __m128i {
        _mm_aesdeclast_si128(state, round_key)
    }
    
    /// AES inverse mix columns
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn aes_inv_mix_columns(data: __m128i) -> __m128i {
        _mm_aesimc_si128(data)
    }
}

// AVX2 accelerated operations
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2"))]
pub mod avx2 {
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    
    /// XOR two 256-bit vectors
    #[inline]
    #[target_feature(enable = "avx2")]
    pub unsafe fn xor_256(a: __m256i, b: __m256i) -> __m256i {
        _mm256_xor_si256(a, b)
    }
    
    /// Parallel byte-wise XOR for large buffers
    #[target_feature(enable = "avx2")]
    pub unsafe fn xor_blocks(a: &[u8], b: &[u8], out: &mut [u8]) {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), out.len());
        
        let chunks = a.len() / 32;
        let remainder = a.len() % 32;
        
        // Process 32-byte chunks
        for i in 0..chunks {
            let offset = i * 32;
            let a_vec = _mm256_loadu_si256(a[offset..].as_ptr() as *const __m256i);
            let b_vec = _mm256_loadu_si256(b[offset..].as_ptr() as *const __m256i);
            let result = _mm256_xor_si256(a_vec, b_vec);
            _mm256_storeu_si256(out[offset..].as_mut_ptr() as *mut __m256i, result);
        }
        
        // Handle remainder
        let offset = chunks * 32;
        for i in 0..remainder {
            out[offset + i] = a[offset + i] ^ b[offset + i];
        }
    }
}

// SHA extensions
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "sha"))]
pub mod sha_ni {
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    
    /// SHA256 message schedule update
    #[inline]
    #[target_feature(enable = "sha")]
    pub unsafe fn sha256_msg1(a: __m128i, b: __m128i) -> __m128i {
        _mm_sha256msg1_epu32(a, b)
    }
    
    /// SHA256 message schedule update 2
    #[inline]
    #[target_feature(enable = "sha")]
    pub unsafe fn sha256_msg2(a: __m128i, b: __m128i) -> __m128i {
        _mm_sha256msg2_epu32(a, b)
    }
    
    /// SHA256 hash update
    #[inline]
    #[target_feature(enable = "sha")]
    pub unsafe fn sha256_rounds(state: __m128i, msg: __m128i, k: __m128i) -> __m128i {
        _mm_sha256rnds2_epu32(state, msg, k)
    }
}

// Hardware random number generation
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "rdrand"))]
pub mod rdrand {
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    
    /// Generate a random 32-bit value
    #[inline]
    #[target_feature(enable = "rdrand")]
    pub unsafe fn random_u32() -> Option<u32> {
        let mut value = 0u32;
        if _rdrand32_step(&mut value) == 1 {
            Some(value)
        } else {
            None
        }
    }
    
    /// Generate a random 64-bit value (x86_64 only)
    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "rdrand")]
    pub unsafe fn random_u64() -> Option<u64> {
        let mut value = 0u64;
        if _rdrand64_step(&mut value) == 1 {
            Some(value)
        } else {
            None
        }
    }
    
    /// Fill a buffer with random bytes
    #[target_feature(enable = "rdrand")]
    pub unsafe fn fill_random(buffer: &mut [u8]) -> bool {
        let chunks = buffer.len() / 4;
        let remainder = buffer.len() % 4;
        
        // Fill 4-byte chunks
        for i in 0..chunks {
            match random_u32() {
                Some(value) => {
                    let bytes = value.to_le_bytes();
                    buffer[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
                }
                None => return false,
            }
        }
        
        // Handle remainder
        if remainder > 0 {
            match random_u32() {
                Some(value) => {
                    let bytes = value.to_le_bytes();
                    buffer[chunks * 4..].copy_from_slice(&bytes[..remainder]);
                }
                None => return false,
            }
        }
        
        true
    }
}