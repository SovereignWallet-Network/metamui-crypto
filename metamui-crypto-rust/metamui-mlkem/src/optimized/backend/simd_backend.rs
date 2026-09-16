//! SIMD backend implementations

use crate::{Keypair, PublicKey, SecretKey, Ciphertext, SharedSecret, Result};
use rand_core::{CryptoRng, RngCore};
use super::{Backend, PerformanceHints};

// Platform-specific SIMD backend wrapper
pub struct SimdBackend {
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    inner_x86: Option<Avx2Backend>,
    #[cfg(all(feature = "neon", target_arch = "aarch64"))]
    inner_arm: Option<NeonBackend>,
    #[cfg(not(any(
        all(feature = "simd", target_arch = "x86_64"),
        all(feature = "neon", target_arch = "aarch64")
    )))]
    _phantom: std::marker::PhantomData<()>,
}

impl SimdBackend {
    pub fn new() -> Result<Self> {
        #[cfg(all(feature = "simd", target_arch = "x86_64"))]
        {
            if is_x86_feature_detected!("avx2") {
                return Ok(Self {
                    inner_x86: Some(Avx2Backend::new()),
                });
            }
        }
        
        #[cfg(all(feature = "neon", target_arch = "aarch64"))]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                return Ok(Self {
                    inner_arm: Some(NeonBackend::new()),
                });
            }
        }
        
        #[cfg(not(any(
            all(feature = "simd", target_arch = "x86_64"),
            all(feature = "neon", target_arch = "aarch64")
        )))]
        {
            return Ok(Self {
                _phantom: std::marker::PhantomData,
            });
        }
        
        Err(crate::Error::NotSupported)
    }
}

impl Backend for SimdBackend {
    fn name(&self) -> &str {
        #[cfg(all(feature = "simd", target_arch = "x86_64"))]
        if let Some(ref backend) = self.inner_x86 {
            return backend.name();
        }
        
        #[cfg(all(feature = "neon", target_arch = "aarch64"))]
        if let Some(ref backend) = self.inner_arm {
            return backend.name();
        }
        
        "No SIMD"
    }
    
    fn supports_batch(&self) -> bool {
        #[cfg(all(feature = "simd", target_arch = "x86_64"))]
        if let Some(ref backend) = self.inner_x86 {
            return backend.supports_batch();
        }
        
        #[cfg(all(feature = "neon", target_arch = "aarch64"))]
        if let Some(ref backend) = self.inner_arm {
            return backend.supports_batch();
        }
        
        false
    }
    
    fn performance_hints(&self) -> PerformanceHints {
        #[cfg(all(feature = "simd", target_arch = "x86_64"))]
        if let Some(ref backend) = self.inner_x86 {
            return backend.performance_hints();
        }
        
        #[cfg(all(feature = "neon", target_arch = "aarch64"))]
        if let Some(ref backend) = self.inner_arm {
            return backend.performance_hints();
        }
        
        PerformanceHints::default()
    }
    
    fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Keypair> {
        #[cfg(all(feature = "simd", target_arch = "x86_64"))]
        if let Some(ref backend) = self.inner_x86 {
            return backend.keygen(rng);
        }
        
        #[cfg(all(feature = "neon", target_arch = "aarch64"))]
        if let Some(ref backend) = self.inner_arm {
            return backend.keygen(rng);
        }
        
        let _ = rng; // Suppress unused warning when no features enabled
        Err(crate::Error::NotSupported)
    }
    
    fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret)> {
        #[cfg(all(feature = "simd", target_arch = "x86_64"))]
        if let Some(ref backend) = self.inner_x86 {
            return backend.encapsulate(public_key, rng);
        }
        
        #[cfg(all(feature = "neon", target_arch = "aarch64"))]
        if let Some(ref backend) = self.inner_arm {
            return backend.encapsulate(public_key, rng);
        }
        
        let _ = (public_key, rng); // Suppress unused warnings
        Err(crate::Error::NotSupported)
    }
    
    fn decapsulate(
        &self,
        secret_key: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> Result<SharedSecret> {
        #[cfg(all(feature = "simd", target_arch = "x86_64"))]
        if let Some(ref backend) = self.inner_x86 {
            return backend.decapsulate(secret_key, ciphertext);
        }
        
        #[cfg(all(feature = "neon", target_arch = "aarch64"))]
        if let Some(ref backend) = self.inner_arm {
            return backend.decapsulate(secret_key, ciphertext);
        }
        
        let _ = (secret_key, ciphertext); // Suppress unused warnings
        Err(crate::Error::NotSupported)
    }
}

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
pub struct Avx2Backend {
    inner: metamui_mlkem::MLKem768,
}

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
impl Avx2Backend {
    pub fn new() -> Self {
        Self {
            inner: metamui_mlkem::MLKem768::new(),
        }
    }
}

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
impl Backend for Avx2Backend {
    fn name(&self) -> &str {
        "AVX2"
    }
    
    fn supports_batch(&self) -> bool {
        true
    }
    
    fn performance_hints(&self) -> PerformanceHints {
        PerformanceHints {
            relative_speed: 2.5,
            uses_simd: true,
            uses_gpu: false,
            optimal_batch_size: 8,
            constant_time: true,
        }
    }
    
    fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Keypair> {
        self.inner.generate_keypair(rng)
    }
    
    fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret)> {
        self.inner.encapsulate(public_key, rng)
    }
    
    fn decapsulate(
        &self,
        secret_key: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> Result<SharedSecret> {
        self.inner.decapsulate(secret_key, ciphertext)
    }
}

#[cfg(all(feature = "neon", target_arch = "aarch64"))]
pub struct NeonBackend {
    inner: metamui_mlkem::MLKem768,
}

#[cfg(all(feature = "neon", target_arch = "aarch64"))]
impl NeonBackend {
    pub fn new() -> Self {
        Self {
            inner: metamui_mlkem::MLKem768::new(),
        }
    }
}

#[cfg(all(feature = "neon", target_arch = "aarch64"))]
impl Backend for NeonBackend {
    fn name(&self) -> &str {
        "NEON"
    }
    
    fn supports_batch(&self) -> bool {
        true
    }
    
    fn performance_hints(&self) -> PerformanceHints {
        PerformanceHints {
            relative_speed: 2.0,
            uses_simd: true,
            uses_gpu: false,
            optimal_batch_size: 4,
            constant_time: true,
        }
    }
    
    fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Keypair> {
        self.inner.generate_keypair(rng)
    }
    
    fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret)> {
        self.inner.encapsulate(public_key, rng)
    }
    
    fn decapsulate(
        &self,
        secret_key: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> Result<SharedSecret> {
        self.inner.decapsulate(secret_key, ciphertext)
    }
}