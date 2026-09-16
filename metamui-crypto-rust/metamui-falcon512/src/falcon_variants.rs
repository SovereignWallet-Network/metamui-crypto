//! Falcon signature scheme variants (512 and 1024)
//! 
//! This module provides support for both Falcon-512 and Falcon-1024 variants
//! as specified in the NIST PQC Round 3 submission.


/// Falcon signature scheme variants
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FalconVariant {
    /// Falcon-512: NIST Security Level 1 (128-bit security)
    /// - Polynomial degree: n = 512
    /// - Public key: 897 bytes
    /// - Secret key: 2305 bytes
    /// - Signature: ~666 bytes (690 max in NIST format)
    Falcon512,
    
    /// Falcon-1024: NIST Security Level 5 (256-bit security)
    /// - Polynomial degree: n = 1024
    /// - Public key: 1793 bytes
    /// - Secret key: 2305 bytes
    /// - Signature: ~1330 bytes
    Falcon1024,
}

impl FalconVariant {
    /// Get the polynomial degree n
    pub fn n(&self) -> usize {
        match self {
            Self::Falcon512 => 512,
            Self::Falcon1024 => 1024,
        }
    }
    
    /// Get log2(n)
    pub fn logn(&self) -> usize {
        match self {
            Self::Falcon512 => 9,
            Self::Falcon1024 => 10,
        }
    }
    
    /// Get the modulus q (always 12289 for Falcon)
    pub fn q(&self) -> u16 {
        12289
    }
    
    /// Get the Gaussian standard deviation for key generation
    pub fn sigma(&self) -> f64 {
        match self {
            Self::Falcon512 => 165.7366171829776,
            Self::Falcon1024 => 203.93,
        }
    }
    
    /// Get the Gaussian standard deviation for signing
    pub fn sigma_min(&self) -> f64 {
        match self {
            Self::Falcon512 => 1.2778336969128337,
            Self::Falcon1024 => 1.0163,
        }
    }
    
    /// Get the signature norm bound (beta squared)
    pub fn beta_squared(&self) -> u64 {
        match self {
            Self::Falcon512 => 34034726,    // sqrt(34034726) ≈ 5834
            Self::Falcon1024 => 70265242,    // sqrt(70265242) ≈ 8382; reference l2bound[10] (#359)
        }
    }
    
    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::Falcon512 => 897,
            Self::Falcon1024 => 1793,
        }
    }
    
    /// Get the secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            Self::Falcon512 => 2305,
            Self::Falcon1024 => 2305,
        }
    }
    
    /// Get the average signature size in bytes
    pub fn signature_size_avg(&self) -> usize {
        match self {
            Self::Falcon512 => 666,
            Self::Falcon1024 => 1330,
        }
    }
    
    /// Get the maximum signature size in bytes (NIST format)
    pub fn signature_size_max(&self) -> usize {
        match self {
            Self::Falcon512 => 690,
            Self::Falcon1024 => 1330,
        }
    }
    
    /// Get NIST security level
    pub fn security_level(&self) -> u8 {
        match self {
            Self::Falcon512 => 1,   // 128-bit security
            Self::Falcon1024 => 5,  // 256-bit security
        }
    }
    
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::Falcon512 => "Falcon-512 (NIST Level 1, 128-bit security)",
            Self::Falcon1024 => "Falcon-1024 (NIST Level 5, 256-bit security)",
        }
    }
}

impl Default for FalconVariant {
    fn default() -> Self {
        // Default to Falcon-512 for compatibility
        Self::Falcon512
    }
}

/// Parameters for a specific Falcon variant
pub struct FalconParams {
    pub variant: FalconVariant,
    pub n: usize,
    pub logn: usize,
    pub q: u16,
    pub sigma: f64,
    pub sigma_min: f64,
    pub beta_squared: u64,
}

impl From<FalconVariant> for FalconParams {
    fn from(variant: FalconVariant) -> Self {
        FalconParams {
            variant,
            n: variant.n(),
            logn: variant.logn(),
            q: variant.q(),
            sigma: variant.sigma(),
            sigma_min: variant.sigma_min(),
            beta_squared: variant.beta_squared(),
        }
    }
}

/// Create parameters for Falcon-512
pub fn falcon512_params() -> FalconParams {
    FalconParams::from(FalconVariant::Falcon512)
}

/// Create parameters for Falcon-1024
pub fn falcon1024_params() -> FalconParams {
    FalconParams::from(FalconVariant::Falcon1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_falcon_variants() {
        // Test Falcon-512 parameters
        let f512 = FalconVariant::Falcon512;
        assert_eq!(f512.n(), 512);
        assert_eq!(f512.logn(), 9);
        assert_eq!(f512.q(), 12289);
        assert_eq!(f512.public_key_size(), 897);
        assert_eq!(f512.secret_key_size(), 2305);
        assert_eq!(f512.signature_size_avg(), 666);
        assert_eq!(f512.security_level(), 1);
        
        // Test Falcon-1024 parameters
        let f1024 = FalconVariant::Falcon1024;
        assert_eq!(f1024.n(), 1024);
        assert_eq!(f1024.logn(), 10);
        assert_eq!(f1024.q(), 12289);
        assert_eq!(f1024.public_key_size(), 1793);
        assert_eq!(f1024.secret_key_size(), 2305);
        assert_eq!(f1024.signature_size_avg(), 1330);
        assert_eq!(f1024.security_level(), 5);
    }
    
    #[test]
    fn test_default_variant() {
        let default = FalconVariant::default();
        assert_eq!(default, FalconVariant::Falcon512);
    }
}