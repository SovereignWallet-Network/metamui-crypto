//! Enum-based backend wrapper to enable dynamic dispatch
//!
//! This module provides an enum wrapper for backends to work around
//! the trait object limitations with generic methods.

use crate::{Keypair, PublicKey, SecretKey, Ciphertext, SharedSecret, Result};
use rand_core::{CryptoRng, RngCore};
use super::{Backend, PerformanceHints, Operation, MemoryEstimate};

/// Backend enum for dynamic dispatch
pub enum BackendEnum {
    /// Reference implementation
    Reference(super::reference::ReferenceBackend),
    /// SIMD backend
    #[cfg(feature = "simd")]
    Simd(super::simd_backend::SimdBackend),
    /// GPU backend
    #[cfg(feature = "gpu")]
    Gpu(super::gpu_backend::GpuBackend),
}

impl Backend for BackendEnum {
    fn name(&self) -> &str {
        match self {
            Self::Reference(b) => b.name(),
            #[cfg(feature = "simd")]
            Self::Simd(b) => b.name(),
            #[cfg(feature = "gpu")]
            Self::Gpu(b) => b.name(),
        }
    }

    fn supports_batch(&self) -> bool {
        match self {
            Self::Reference(b) => b.supports_batch(),
            #[cfg(feature = "simd")]
            Self::Simd(b) => b.supports_batch(),
            #[cfg(feature = "gpu")]
            Self::Gpu(b) => b.supports_batch(),
        }
    }

    fn performance_hints(&self) -> PerformanceHints {
        match self {
            Self::Reference(b) => b.performance_hints(),
            #[cfg(feature = "simd")]
            Self::Simd(b) => b.performance_hints(),
            #[cfg(feature = "gpu")]
            Self::Gpu(b) => b.performance_hints(),
        }
    }

    fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Keypair> {
        match self {
            Self::Reference(b) => b.keygen(rng),
            #[cfg(feature = "simd")]
            Self::Simd(b) => b.keygen(rng),
            #[cfg(feature = "gpu")]
            Self::Gpu(b) => b.keygen(rng),
        }
    }

    fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret)> {
        match self {
            Self::Reference(b) => b.encapsulate(public_key, rng),
            #[cfg(feature = "simd")]
            Self::Simd(b) => b.encapsulate(public_key, rng),
            #[cfg(feature = "gpu")]
            Self::Gpu(b) => b.encapsulate(public_key, rng),
        }
    }

    fn decapsulate(
        &self,
        secret_key: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> Result<SharedSecret> {
        match self {
            Self::Reference(b) => b.decapsulate(secret_key, ciphertext),
            #[cfg(feature = "simd")]
            Self::Simd(b) => b.decapsulate(secret_key, ciphertext),
            #[cfg(feature = "gpu")]
            Self::Gpu(b) => b.decapsulate(secret_key, ciphertext),
        }
    }

    #[cfg(feature = "parallel")]
    fn batch_keygen<R: RngCore + CryptoRng>(
        &self,
        count: usize,
        rng: &mut R,
    ) -> Result<Vec<Keypair>> {
        match self {
            Self::Reference(b) => b.batch_keygen(count, rng),
            #[cfg(feature = "simd")]
            Self::Simd(b) => b.batch_keygen(count, rng),
            #[cfg(feature = "gpu")]
            Self::Gpu(b) => b.batch_keygen(count, rng),
        }
    }

    #[cfg(feature = "parallel")]
    fn batch_encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_keys: &[PublicKey],
        rng: &mut R,
    ) -> Result<Vec<(Ciphertext, SharedSecret)>> {
        match self {
            Self::Reference(b) => b.batch_encapsulate(public_keys, rng),
            #[cfg(feature = "simd")]
            Self::Simd(b) => b.batch_encapsulate(public_keys, rng),
            #[cfg(feature = "gpu")]
            Self::Gpu(b) => b.batch_encapsulate(public_keys, rng),
        }
    }

    #[cfg(feature = "parallel")]
    fn batch_decapsulate(
        &self,
        secret_keys: &[SecretKey],
        ciphertexts: &[Ciphertext],
    ) -> Result<Vec<SharedSecret>> {
        match self {
            Self::Reference(b) => b.batch_decapsulate(secret_keys, ciphertexts),
            #[cfg(feature = "simd")]
            Self::Simd(b) => b.batch_decapsulate(secret_keys, ciphertexts),
            #[cfg(feature = "gpu")]
            Self::Gpu(b) => b.batch_decapsulate(secret_keys, ciphertexts),
        }
    }

    fn memory_estimate(&self, operation: Operation) -> MemoryEstimate {
        match self {
            Self::Reference(b) => b.memory_estimate(operation),
            #[cfg(feature = "simd")]
            Self::Simd(b) => b.memory_estimate(operation),
            #[cfg(feature = "gpu")]
            Self::Gpu(b) => b.memory_estimate(operation),
        }
    }
}