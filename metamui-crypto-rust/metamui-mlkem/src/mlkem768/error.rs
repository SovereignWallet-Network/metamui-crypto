/**
 * ML-KEM-768 Error Types
 *
 * Error handling for NIST FIPS 203 ML-KEM-768 implementation
 */
use core::fmt;

/// ML-KEM-768 error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MLKemError {
    /// Invalid public key format or size
    InvalidPublicKey,

    /// Invalid private key format or size  
    InvalidPrivateKey,

    /// Invalid ciphertext format or size
    InvalidCiphertext,

    /// Random number generation failed
    RandomGenerationFailed,

    /// Memory allocation failed
    MemoryAllocationFailed,

    /// Side-channel attack detected (fault injection, timing)
    SideChannelDetected,

    /// Invalid polynomial coefficient (outside valid range)
    InvalidPolynomial,

    /// Invalid compression parameters
    InvalidCompression,

    /// Decapsulation failed (authentication error)
    DecapsulationFailed,

    /// Implementation-specific error
    ImplementationError(String),

    /// Input validation failed
    InvalidInput(&'static str),

    /// Buffer size mismatch
    BufferSizeMismatch {
        /// Expected buffer size
        expected: usize,
        /// Actual buffer size provided
        actual: usize,
    },

    /// Unsupported operation
    UnsupportedOperation,
}

impl fmt::Display for MLKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MLKemError::InvalidPublicKey => {
                write!(f, "Invalid public key: must be 1184 bytes and pass the FIPS 203 §7.2 modulus check")
            }
            MLKemError::InvalidPrivateKey => {
                write!(f, "Invalid private key: must be 2400 bytes and pass the FIPS 203 §7.3 hash check")
            }
            MLKemError::InvalidCiphertext => {
                write!(f, "Invalid ciphertext: must be exactly 1088 bytes")
            }
            MLKemError::RandomGenerationFailed => {
                write!(
                    f,
                    "Failed to generate cryptographically secure random bytes"
                )
            }
            MLKemError::MemoryAllocationFailed => {
                write!(f, "Failed to allocate secure memory")
            }
            MLKemError::SideChannelDetected => {
                write!(f, "Potential side-channel attack detected")
            }
            MLKemError::InvalidPolynomial => {
                write!(
                    f,
                    "Invalid polynomial: coefficient outside valid range [0, 3328]"
                )
            }
            MLKemError::InvalidCompression => {
                write!(f, "Invalid compression parameters")
            }
            MLKemError::DecapsulationFailed => {
                write!(f, "Decapsulation failed: ciphertext authentication error")
            }
            MLKemError::ImplementationError(msg) => {
                write!(f, "Implementation error: {}", msg)
            }
            MLKemError::InvalidInput(msg) => {
                write!(f, "Invalid input: {}", msg)
            }
            MLKemError::BufferSizeMismatch { expected, actual } => {
                write!(
                    f,
                    "Buffer size mismatch: expected {} bytes, got {}",
                    expected, actual
                )
            }
            MLKemError::UnsupportedOperation => {
                write!(f, "Unsupported operation for current configuration")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MLKemError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Result type for ML-KEM operations
pub type MLKemResult<T> = Result<T, MLKemError>;

/// Validation helper functions
impl MLKemError {
    /// Validate public key size
    pub fn validate_public_key_size(size: usize) -> MLKemResult<()> {
        if size == crate::mlkem768::constants::MLKEM_PUBLICKEY_BYTES {
            Ok(())
        } else {
            Err(MLKemError::BufferSizeMismatch {
                expected: crate::mlkem768::constants::MLKEM_PUBLICKEY_BYTES,
                actual: size,
            })
        }
    }

    /// Validate private key size
    pub fn validate_private_key_size(size: usize) -> MLKemResult<()> {
        if size == crate::mlkem768::constants::MLKEM_SECRETKEY_BYTES {
            Ok(())
        } else {
            Err(MLKemError::BufferSizeMismatch {
                expected: crate::mlkem768::constants::MLKEM_SECRETKEY_BYTES,
                actual: size,
            })
        }
    }

    /// Validate ciphertext size
    pub fn validate_ciphertext_size(size: usize) -> MLKemResult<()> {
        if size == crate::mlkem768::constants::MLKEM_CIPHERTEXT_BYTES {
            Ok(())
        } else {
            Err(MLKemError::BufferSizeMismatch {
                expected: crate::mlkem768::constants::MLKEM_CIPHERTEXT_BYTES,
                actual: size,
            })
        }
    }

    /// Validate polynomial coefficient
    pub fn validate_coefficient(coeff: u16) -> MLKemResult<()> {
        if coeff < crate::mlkem768::constants::MLKEM_Q {
            Ok(())
        } else {
            Err(MLKemError::InvalidPolynomial)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem768::constants::*;

    #[test]
    fn test_error_display() {
        let error = MLKemError::InvalidPublicKey;
        assert_eq!(
            format!("{}", error),
            "Invalid public key: must be 1184 bytes and pass the FIPS 203 §7.2 modulus check"
        );

        let error = MLKemError::BufferSizeMismatch {
            expected: 1184,
            actual: 1000,
        };
        assert_eq!(
            format!("{}", error),
            "Buffer size mismatch: expected 1184 bytes, got 1000"
        );
    }

    #[test]
    fn test_validation_functions() {
        // Test public key validation
        assert!(MLKemError::validate_public_key_size(MLKEM_PUBLICKEY_BYTES).is_ok());
        assert!(MLKemError::validate_public_key_size(1000).is_err());

        // Test private key validation
        assert!(MLKemError::validate_private_key_size(MLKEM_SECRETKEY_BYTES).is_ok());
        assert!(MLKemError::validate_private_key_size(2000).is_err());

        // Test ciphertext validation
        assert!(MLKemError::validate_ciphertext_size(MLKEM_CIPHERTEXT_BYTES).is_ok());
        assert!(MLKemError::validate_ciphertext_size(1000).is_err());

        // Test coefficient validation
        assert!(MLKemError::validate_coefficient(0).is_ok());
        assert!(MLKemError::validate_coefficient(MLKEM_Q - 1).is_ok());
        assert!(MLKemError::validate_coefficient(MLKEM_Q).is_err());
        assert!(MLKemError::validate_coefficient(u16::MAX).is_err());
    }

    #[test]
    fn test_error_equality() {
        let error1 = MLKemError::InvalidPublicKey;
        let error2 = MLKemError::InvalidPublicKey;
        let error3 = MLKemError::InvalidPrivateKey;

        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
    }

    #[test]
    fn test_error_clone() {
        let error = MLKemError::InvalidPublicKey;
        let cloned = error.clone();
        assert_eq!(error, cloned);
    }
}
