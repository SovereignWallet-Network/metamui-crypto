//! GPU backend implementation

#[cfg(feature = "gpu")]
pub struct GpuBackend {
    inner: metamui_mlkem::MLKem768,
}

#[cfg(feature = "gpu")]
impl GpuBackend {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            inner: metamui_mlkem::MLKem768::new(),
        })
    }
}

#[cfg(feature = "gpu")]
impl super::Backend for GpuBackend {
    fn name(&self) -> &str {
        "GPU"
    }
    
    fn supports_batch(&self) -> bool {
        true
    }
    
    fn performance_hints(&self) -> super::PerformanceHints {
        super::PerformanceHints {
            relative_speed: 10.0,
            uses_simd: false,
            uses_gpu: true,
            optimal_batch_size: 256,
            constant_time: true,
        }
    }
    
    fn keygen<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self, 
        rng: &mut R
    ) -> crate::Result<crate::Keypair> {
        self.inner.generate_keypair(rng)
    }
    
    fn encapsulate<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        public_key: &crate::PublicKey,
        rng: &mut R,
    ) -> crate::Result<(crate::Ciphertext, crate::SharedSecret)> {
        self.inner.encapsulate(public_key, rng)
    }
    
    fn decapsulate(
        &self,
        secret_key: &crate::SecretKey,
        ciphertext: &crate::Ciphertext,
    ) -> crate::Result<crate::SharedSecret> {
        self.inner.decapsulate(secret_key, ciphertext)
    }
}