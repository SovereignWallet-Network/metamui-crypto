//! ARM AArch64 specific hardware acceleration.
//!
//! # Safety contract (applies to every `pub unsafe fn` in this file)
//!
//! Each intrinsic wrapper below is marked `unsafe fn` because its
//! behaviour is UB on cores that don't implement the required ARMv8
//! feature — e.g. `veorq_u8` requires NEON (FEAT_AdvSIMD),
//! `vaeseq_u8` requires the cryptographic extension (FEAT_AES),
//! `vsha256hq_u32` requires SHA-2 (FEAT_SHA2).
//!
//! Each wrapper carries a `#[target_feature(enable = "…")]` attribute
//! that promises the matching feature is available for its body. The
//! enclosing module's `#[cfg(all(target_arch = "aarch64",
//! target_feature = "…"))]` guard compiles these wrappers only when
//! the feature is statically guaranteed for the crate build.
//!
//! Callers invoking these from contexts without a matching
//! `#[target_feature]` attribute must themselves check availability
//! at runtime (`cfg!(target_feature = "…")` for compile-time,
//! `std::arch::is_aarch64_feature_detected!("…")` for runtime);
//! that is the residual obligation reflected in the `unsafe`
//! keyword on the call site. The dispatch tables in `operations.rs`
//! — `NeonOps` etc. — already do this correctly.

use crate::features::HardwareFeatures;

#[cfg(target_arch = "aarch64")]
pub fn detect_arm_features(features: &mut HardwareFeatures) {
    // Use compile-time feature detection for no_std compatibility
    features.has_neon = cfg!(target_feature = "neon");
    features.has_crc32 = cfg!(target_feature = "crc");
    features.has_crypto = cfg!(target_feature = "aes") || cfg!(target_feature = "sha2");
    
    // SVE detection (Scalable Vector Extension)
    features.has_sve = cfg!(target_feature = "sve");
    features.has_sve2 = cfg!(target_feature = "sve2");
}

// NEON SIMD operations
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub mod neon {
    use core::arch::aarch64::*;
    
    /// XOR two 128-bit vectors
    #[inline]
    #[target_feature(enable = "neon")]
    pub unsafe fn xor_128(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
        veorq_u8(a, b)
    }
    
    /// Parallel byte-wise XOR for buffers
    #[target_feature(enable = "neon")]
    pub unsafe fn xor_blocks(a: &[u8], b: &[u8], out: &mut [u8]) {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), out.len());
        
        let chunks = a.len() / 16;
        let remainder = a.len() % 16;
        
        // Process 16-byte chunks
        for i in 0..chunks {
            let offset = i * 16;
            let a_vec = vld1q_u8(a[offset..].as_ptr());
            let b_vec = vld1q_u8(b[offset..].as_ptr());
            let result = veorq_u8(a_vec, b_vec);
            vst1q_u8(out[offset..].as_mut_ptr(), result);
        }
        
        // Handle remainder
        let offset = chunks * 16;
        for i in 0..remainder {
            out[offset + i] = a[offset + i] ^ b[offset + i];
        }
    }
    
    /// Rotate left for 32-bit values (useful for hash functions)
    /// Note: For NEON, the shift amount must be a compile-time constant,
    /// so we provide specific functions for common rotations
    
    #[inline]
    #[target_feature(enable = "neon")]
    pub unsafe fn rotate_left_32_by_8(x: uint32x4_t) -> uint32x4_t {
        let left = vshlq_n_u32(x, 8);
        let right = vshrq_n_u32(x, 24);
        vorrq_u32(left, right)
    }
    
    #[inline]
    #[target_feature(enable = "neon")]
    pub unsafe fn rotate_left_32_by_16(x: uint32x4_t) -> uint32x4_t {
        let left = vshlq_n_u32(x, 16);
        let right = vshrq_n_u32(x, 16);
        vorrq_u32(left, right)
    }
    
    #[inline]
    #[target_feature(enable = "neon")]
    pub unsafe fn rotate_left_32_by_24(x: uint32x4_t) -> uint32x4_t {
        let left = vshlq_n_u32(x, 24);
        let right = vshrq_n_u32(x, 8);
        vorrq_u32(left, right)
    }
    
    /// Add two vectors of 32-bit integers
    #[inline]
    #[target_feature(enable = "neon")]
    pub unsafe fn add_32(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        vaddq_u32(a, b)
    }
    
    /// Multiply two vectors of 32-bit integers
    #[inline]
    #[target_feature(enable = "neon")]
    pub unsafe fn mul_32(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        vmulq_u32(a, b)
    }
}

// ARM Crypto Extensions
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
pub mod crypto {
    use core::arch::aarch64::*;
    
    /// AES single round encryption
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn aes_enc_round(state: uint8x16_t, round_key: uint8x16_t) -> uint8x16_t {
        vaesmcq_u8(vaeseq_u8(state, round_key))
    }
    
    /// AES last round encryption
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn aes_enc_last_round(state: uint8x16_t, round_key: uint8x16_t) -> uint8x16_t {
        vaeseq_u8(state, round_key)
    }
    
    /// AES single round decryption
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn aes_dec_round(state: uint8x16_t, round_key: uint8x16_t) -> uint8x16_t {
        vaesimcq_u8(vaesdq_u8(state, round_key))
    }
    
    /// AES last round decryption
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn aes_dec_last_round(state: uint8x16_t, round_key: uint8x16_t) -> uint8x16_t {
        vaesdq_u8(state, round_key)
    }
    
    /// AES inverse mix columns
    #[inline]
    #[target_feature(enable = "aes")]
    pub unsafe fn aes_inv_mix_columns(data: uint8x16_t) -> uint8x16_t {
        vaesimcq_u8(data)
    }
}

// SHA-256 acceleration (requires sha2 feature)
#[cfg(all(target_arch = "aarch64", target_feature = "sha2"))]
pub mod sha2 {
    use core::arch::aarch64::*;
    
    /// SHA256 hash update - part 1
    #[inline]
    #[target_feature(enable = "sha2")]
    pub unsafe fn sha256_hash_update_part1(
        hash_abcd: uint32x4_t,
        hash_efgh: uint32x4_t,
        wk: uint32x4_t,
    ) -> uint32x4_t {
        vsha256hq_u32(hash_abcd, hash_efgh, wk)
    }
    
    /// SHA256 hash update - part 2
    #[inline]
    #[target_feature(enable = "sha2")]
    pub unsafe fn sha256_hash_update_part2(
        hash_efgh: uint32x4_t,
        hash_abcd: uint32x4_t,
        wk: uint32x4_t,
    ) -> uint32x4_t {
        vsha256h2q_u32(hash_efgh, hash_abcd, wk)
    }
    
    /// SHA256 schedule update 0
    #[inline]
    #[target_feature(enable = "sha2")]
    pub unsafe fn sha256_schedule_update0(w0_3: uint32x4_t, w4_7: uint32x4_t) -> uint32x4_t {
        vsha256su0q_u32(w0_3, w4_7)
    }
    
    /// SHA256 schedule update 1
    #[inline]
    #[target_feature(enable = "sha2")]
    pub unsafe fn sha256_schedule_update1(
        tw0_3: uint32x4_t,
        w8_11: uint32x4_t,
        w12_15: uint32x4_t,
    ) -> uint32x4_t {
        vsha256su1q_u32(tw0_3, w8_11, w12_15)
    }
}

// SVE (Scalable Vector Extension) operations
#[cfg(all(target_arch = "aarch64", target_feature = "sve"))]
pub mod sve {
    // SVE provides variable-length vector operations
    // This is a placeholder for future SVE implementations
    // SVE intrinsics are not yet stable in Rust
}