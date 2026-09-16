//! ML-KEM parameter sets as defined in NIST FIPS 203

use crate::error::MLKemError;

/// ML-KEM parameter set
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLKemParams {
    /// Module dimension
    pub k: usize,
    /// Polynomial degree (always 256 for ML-KEM)
    pub n: usize,
    /// Modulus (always 3329 for ML-KEM)
    pub q: u16,
    /// Noise parameter η₁ for key generation
    pub eta1: usize,
    /// Noise parameter η₂ for encryption
    pub eta2: usize,
    /// Compression parameter for u
    pub du: usize,
    /// Compression parameter for v
    pub dv: usize,
    /// Public key size in bytes
    pub public_key_bytes: usize,
    /// Secret key size in bytes
    pub secret_key_bytes: usize,
    /// Ciphertext size in bytes
    pub ciphertext_bytes: usize,
    /// Shared secret size in bytes (always 32)
    pub shared_secret_bytes: usize,
}

/// ML-KEM parameter set identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MLKemParameterSet {
    /// ML-KEM-512 (NIST Level 1)
    MLKem512,
    /// ML-KEM-768 (NIST Level 3)
    MLKem768,
    /// ML-KEM-1024 (NIST Level 5)
    MLKem1024,
}

/// ML-KEM-512 parameters (NIST Level 1)
pub const MLKEM512_PARAMS: MLKemParams = MLKemParams {
    k: 2,
    n: 256,
    q: 3329,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
    public_key_bytes: 800,  // 32*k*12 + 32
    secret_key_bytes: 1632, // 32*k*12 + 32 + 32 + 32*k*12
    ciphertext_bytes: 768,  // 32*k*du + 32*dv
    shared_secret_bytes: 32,
};

/// ML-KEM-768 parameters (NIST Level 3)
pub const MLKEM768_PARAMS: MLKemParams = MLKemParams {
    k: 3,
    n: 256,
    q: 3329,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
    public_key_bytes: 1184,  // 32*k*12 + 32
    secret_key_bytes: 2400,  // 32*k*12 + 32 + 32 + 32*k*12
    ciphertext_bytes: 1088,  // 32*k*du + 32*dv
    shared_secret_bytes: 32,
};

/// ML-KEM-1024 parameters (NIST Level 5)
pub const MLKEM1024_PARAMS: MLKemParams = MLKemParams {
    k: 4,
    n: 256,
    q: 3329,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
    public_key_bytes: 1568,  // 32*k*12 + 32
    secret_key_bytes: 3168,  // 32*k*12 + 32 + 32 + 32*k*12
    ciphertext_bytes: 1568,  // 32*k*du + 32*dv
    shared_secret_bytes: 32,
};

impl MLKemParameterSet {
    /// Get the parameters for this parameter set
    pub fn params(&self) -> &'static MLKemParams {
        match self {
            MLKemParameterSet::MLKem512 => &MLKEM512_PARAMS,
            MLKemParameterSet::MLKem768 => &MLKEM768_PARAMS,
            MLKemParameterSet::MLKem1024 => &MLKEM1024_PARAMS,
        }
    }
    
    /// Get the security level in bits
    pub fn security_level(&self) -> usize {
        match self {
            MLKemParameterSet::MLKem512 => 128,  // NIST Level 1
            MLKemParameterSet::MLKem768 => 192,  // NIST Level 3
            MLKemParameterSet::MLKem1024 => 256, // NIST Level 5
        }
    }
    
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, MLKemError> {
        match s.to_lowercase().as_str() {
            "mlkem512" | "ml-kem-512" | "512" => Ok(MLKemParameterSet::MLKem512),
            "mlkem768" | "ml-kem-768" | "768" => Ok(MLKemParameterSet::MLKem768),
            "mlkem1024" | "ml-kem-1024" | "1024" => Ok(MLKemParameterSet::MLKem1024),
            _ => Err(MLKemError::InvalidParameter),
        }
    }
}

impl MLKemParams {
    /// Calculate polynomial vector size in bytes
    pub fn polyvec_bytes(&self) -> usize {
        self.k * 384 // Each polynomial is 384 bytes when compressed to 12 bits
    }
    
    /// Calculate compressed polynomial vector size for u
    pub fn polyvec_compressed_bytes_u(&self) -> usize {
        self.k * self.du * 32
    }
    
    /// Calculate compressed polynomial size for v
    pub fn poly_compressed_bytes_v(&self) -> usize {
        self.dv * 32
    }
    
    /// Validate parameters
    pub fn validate(&self) -> Result<(), MLKemError> {
        // Check standard constraints
        if self.n != 256 {
            return Err(MLKemError::InvalidParameter);
        }
        if self.q != 3329 {
            return Err(MLKemError::InvalidParameter);
        }
        if self.k < 2 || self.k > 4 {
            return Err(MLKemError::InvalidParameter);
        }
        if self.eta1 < 2 || self.eta1 > 3 {
            return Err(MLKemError::InvalidParameter);
        }
        if self.eta2 != 2 {
            return Err(MLKemError::InvalidParameter);
        }
        if self.du < 10 || self.du > 11 {
            return Err(MLKemError::InvalidParameter);
        }
        if self.dv < 4 || self.dv > 5 {
            return Err(MLKemError::InvalidParameter);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parameter_validation() {
        assert!(MLKEM512_PARAMS.validate().is_ok());
        assert!(MLKEM768_PARAMS.validate().is_ok());
        assert!(MLKEM1024_PARAMS.validate().is_ok());
    }
    
    #[test]
    fn test_parameter_sizes() {
        // ML-KEM-512
        assert_eq!(MLKEM512_PARAMS.public_key_bytes, 800);
        assert_eq!(MLKEM512_PARAMS.secret_key_bytes, 1632);
        assert_eq!(MLKEM512_PARAMS.ciphertext_bytes, 768);
        
        // ML-KEM-768
        assert_eq!(MLKEM768_PARAMS.public_key_bytes, 1184);
        assert_eq!(MLKEM768_PARAMS.secret_key_bytes, 2400);
        assert_eq!(MLKEM768_PARAMS.ciphertext_bytes, 1088);
        
        // ML-KEM-1024
        assert_eq!(MLKEM1024_PARAMS.public_key_bytes, 1568);
        assert_eq!(MLKEM1024_PARAMS.secret_key_bytes, 3168);
        assert_eq!(MLKEM1024_PARAMS.ciphertext_bytes, 1568);
    }
    
    #[test]
    fn test_security_levels() {
        assert_eq!(MLKemParameterSet::MLKem512.security_level(), 128);
        assert_eq!(MLKemParameterSet::MLKem768.security_level(), 192);
        assert_eq!(MLKemParameterSet::MLKem1024.security_level(), 256);
    }
    
    #[test]
    fn test_from_str() {
        assert_eq!(MLKemParameterSet::from_str("mlkem512").unwrap(), MLKemParameterSet::MLKem512);
        assert_eq!(MLKemParameterSet::from_str("ML-KEM-768").unwrap(), MLKemParameterSet::MLKem768);
        assert_eq!(MLKemParameterSet::from_str("1024").unwrap(), MLKemParameterSet::MLKem1024);
        assert!(MLKemParameterSet::from_str("invalid").is_err());
    }
}