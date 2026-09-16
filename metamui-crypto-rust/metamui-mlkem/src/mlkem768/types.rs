/**
 * ML-KEM-768 Type Definitions
 *
 * Core types for NIST FIPS 203 ML-KEM-768 implementation
 */
use crate::mlkem768::constants::*;
use crate::mlkem768::error::{MLKemError, MLKemResult};
use metamui_security_utils::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-768 public key (1,184 bytes)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
    bytes: [u8; MLKEM_PUBLICKEY_BYTES],
}

impl PublicKey {
    /// Create a new public key from bytes
    pub fn from_bytes(bytes: [u8; MLKEM_PUBLICKEY_BYTES]) -> Self {
        Self { bytes }
    }

    /// Create a public key from a byte slice with validation
    pub fn from_slice(slice: &[u8]) -> MLKemResult<Self> {
        if slice.len() != MLKEM_PUBLICKEY_BYTES {
            return Err(MLKemError::BufferSizeMismatch {
                expected: MLKEM_PUBLICKEY_BYTES,
                actual: slice.len(),
            });
        }

        let mut bytes = [0u8; MLKEM_PUBLICKEY_BYTES];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Get the public key as bytes
    pub fn as_bytes(&self) -> &[u8; MLKEM_PUBLICKEY_BYTES] {
        &self.bytes
    }

    /// Get the public key as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to bytes array
    pub fn to_bytes(self) -> [u8; MLKEM_PUBLICKEY_BYTES] {
        self.bytes
    }
}

/// ML-KEM-768 private key (2,400 bytes) with secure zeroization
///
/// Deliberately neither `Clone` nor `Debug`: each instance is a single
/// wiping owner of the key material, and `Debug` would print the bytes.
pub struct PrivateKey {
    bytes: [u8; MLKEM_SECRETKEY_BYTES],
}

impl PrivateKey {
    /// Create a new private key from bytes
    pub fn from_bytes(bytes: [u8; MLKEM_SECRETKEY_BYTES]) -> Self {
        Self { bytes }
    }

    /// Create a private key from a byte slice with validation
    pub fn from_slice(slice: &[u8]) -> MLKemResult<Self> {
        if slice.len() != MLKEM_SECRETKEY_BYTES {
            return Err(MLKemError::BufferSizeMismatch {
                expected: MLKEM_SECRETKEY_BYTES,
                actual: slice.len(),
            });
        }

        let mut bytes = [0u8; MLKEM_SECRETKEY_BYTES];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Get the private key as bytes (read-only reference)
    pub fn as_bytes(&self) -> &[u8; MLKEM_SECRETKEY_BYTES] {
        &self.bytes
    }

    /// Get the private key as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to bytes array (consumes self)
    ///
    /// The returned copy is the caller's to wipe; the consumed instance
    /// zeroizes its own copy on drop.
    pub fn to_bytes(self) -> [u8; MLKEM_SECRETKEY_BYTES] {
        *self.as_bytes()
    }
}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PrivateKey {}

impl PartialEq for PrivateKey {
    /// Constant-time comparison to prevent timing attacks
    fn eq(&self, other: &Self) -> bool {
        use metamui_security_utils::constant_time::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for PrivateKey {}

/// ML-KEM-768 ciphertext (1,088 bytes)
#[derive(Clone)]
pub struct Ciphertext {
    bytes: [u8; MLKEM_CIPHERTEXT_BYTES],
}

impl Ciphertext {
    /// Create a new ciphertext from bytes
    pub fn from_bytes(bytes: [u8; MLKEM_CIPHERTEXT_BYTES]) -> Self {
        Self { bytes }
    }

    /// Create a ciphertext from a byte slice with validation
    pub fn from_slice(slice: &[u8]) -> MLKemResult<Self> {
        if slice.len() != MLKEM_CIPHERTEXT_BYTES {
            return Err(MLKemError::BufferSizeMismatch {
                expected: MLKEM_CIPHERTEXT_BYTES,
                actual: slice.len(),
            });
        }

        let mut bytes = [0u8; MLKEM_CIPHERTEXT_BYTES];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Get the ciphertext as bytes
    pub fn as_bytes(&self) -> &[u8; MLKEM_CIPHERTEXT_BYTES] {
        &self.bytes
    }

    /// Get the ciphertext as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to bytes array
    pub fn to_bytes(self) -> [u8; MLKEM_CIPHERTEXT_BYTES] {
        self.bytes
    }
}

/// ML-KEM-768 shared secret (32 bytes) with secure zeroization
///
/// Deliberately not `Debug`: it would print the secret bytes.
pub struct SharedSecret {
    bytes: [u8; MLKEM_SHAREDSECRET_BYTES],
}

impl SharedSecret {
    /// Create a new shared secret from bytes
    pub fn from_bytes(bytes: [u8; MLKEM_SHAREDSECRET_BYTES]) -> Self {
        Self { bytes }
    }

    /// Create a shared secret from a byte slice with validation
    pub fn from_slice(slice: &[u8]) -> MLKemResult<Self> {
        if slice.len() != MLKEM_SHAREDSECRET_BYTES {
            return Err(MLKemError::BufferSizeMismatch {
                expected: MLKEM_SHAREDSECRET_BYTES,
                actual: slice.len(),
            });
        }

        let mut bytes = [0u8; MLKEM_SHAREDSECRET_BYTES];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Get the shared secret as bytes (read-only reference)
    pub fn as_bytes(&self) -> &[u8; MLKEM_SHAREDSECRET_BYTES] {
        &self.bytes
    }

    /// Get the shared secret as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to bytes array (consumes self)
    ///
    /// The returned copy is the caller's to wipe; the consumed instance
    /// zeroizes its own copy on drop.
    pub fn to_bytes(self) -> [u8; MLKEM_SHAREDSECRET_BYTES] {
        *self.as_bytes()
    }
}

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SharedSecret {}

impl PartialEq for SharedSecret {
    /// Constant-time comparison to prevent timing attacks
    fn eq(&self, other: &Self) -> bool {
        use metamui_security_utils::constant_time::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for SharedSecret {}

impl metamui_security_utils::ConstantTimeEq for SharedSecret {
    fn ct_eq(&self, other: &Self) -> metamui_security_utils::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

/// ML-KEM-768 keypair

pub struct KeyPair {
    /// Public key component
    pub public_key: PublicKey,
    /// Private key component
    pub private_key: PrivateKey,
}

impl KeyPair {
    /// Create a new keypair
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Split the keypair into individual components
    pub fn split(self) -> (PublicKey, PrivateKey) {
        (self.public_key, self.private_key)
    }
}

impl PartialEq for KeyPair {
    /// Constant-time comparison to prevent timing attacks
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key && self.private_key == other.private_key
    }
}

impl Eq for KeyPair {}

/// Polynomial type for internal operations
#[derive(Clone, Debug)]
pub struct Polynomial {
    /// Polynomial coefficients in NTT domain
    pub coeffs: [u16; MLKEM_N],
}

impl Polynomial {
    /// Create a new zero polynomial
    pub fn new() -> Self {
        Self {
            coeffs: [0u16; MLKEM_N],
        }
    }

    /// Create polynomial from coefficient array
    pub fn from_coeffs(coeffs: [u16; MLKEM_N]) -> MLKemResult<Self> {
        // Validate all coefficients are in valid range
        for &coeff in &coeffs {
            if coeff >= MLKEM_Q {
                return Err(MLKemError::InvalidPolynomial);
            }
        }
        Ok(Self { coeffs })
    }

    /// Reduce all coefficients modulo q
    pub fn reduce(&mut self) {
        for coeff in &mut self.coeffs {
            *coeff %= MLKEM_Q;
        }
    }

    /// Clear polynomial by zeroing all coefficients
    pub fn clear(&mut self) {
        self.coeffs.fill(0);
    }

    /// Check if polynomial is in NTT form
    pub fn is_ntt_form(&self) -> bool {
        // The crate does not yet track NTT-domain state explicitly, so claiming
        // success here would let placeholder state masquerade as validated.
        false
    }
}

impl Default for Polynomial {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        use metamui_security_utils::constant_time::ConstantTimeEq;
        // Constant-time comparison for security
        self.coeffs.ct_eq(&other.coeffs).into()
    }
}

impl Eq for Polynomial {}

/// Vector of polynomials
#[derive(Clone, Debug)]
pub struct PolynomialVector {
    /// Vector of k polynomials
    pub polys: [Polynomial; MLKEM_K],
}

impl PolynomialVector {
    /// Create a new zero polynomial vector
    pub fn new() -> Self {
        Self {
            polys: [Polynomial::new(), Polynomial::new(), Polynomial::new()],
        }
    }

    /// Create from polynomial array
    pub fn from_polys(polys: [Polynomial; MLKEM_K]) -> Self {
        Self { polys }
    }
}

impl Default for PolynomialVector {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for PolynomialVector {
    fn eq(&self, other: &Self) -> bool {
        self.polys
            .iter()
            .zip(other.polys.iter())
            .all(|(a, b)| a == b)
    }
}

impl Eq for PolynomialVector {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_creation() {
        let bytes = [0u8; MLKEM_PUBLICKEY_BYTES];
        let pk = PublicKey::from_bytes(bytes);
        assert_eq!(pk.as_bytes(), &bytes);
        assert_eq!(pk.as_slice().len(), MLKEM_PUBLICKEY_BYTES);
    }

    #[test]
    fn test_public_key_from_slice() {
        let bytes = vec![0u8; MLKEM_PUBLICKEY_BYTES];
        let pk = PublicKey::from_slice(&bytes).unwrap();
        assert_eq!(pk.as_slice().len(), MLKEM_PUBLICKEY_BYTES);

        // Test invalid size
        let invalid_bytes = vec![0u8; 100];
        assert!(PublicKey::from_slice(&invalid_bytes).is_err());
    }

    #[test]
    fn test_private_key_creation() {
        let bytes = [42u8; MLKEM_SECRETKEY_BYTES];
        let sk = PrivateKey::from_bytes(bytes);

        // Verify initial content
        assert_eq!(sk.as_bytes()[0], 42);
        assert_eq!(sk.as_slice().len(), MLKEM_SECRETKEY_BYTES);
    }

    #[test]
    fn test_shared_secret_constant_time_eq() {
        let bytes1 = [1u8; MLKEM_SHAREDSECRET_BYTES];
        let bytes2 = [1u8; MLKEM_SHAREDSECRET_BYTES];
        let bytes3 = [2u8; MLKEM_SHAREDSECRET_BYTES];

        let ss1 = SharedSecret::from_bytes(bytes1);
        let ss2 = SharedSecret::from_bytes(bytes2);
        let ss3 = SharedSecret::from_bytes(bytes3);

        assert!(ss1 == ss2);
        assert!(ss1 != ss3);
    }

    #[test]
    fn test_polynomial_validation() {
        let valid_coeffs = [0u16; MLKEM_N];
        assert!(Polynomial::from_coeffs(valid_coeffs).is_ok());

        let mut invalid_coeffs = [0u16; MLKEM_N];
        invalid_coeffs[0] = MLKEM_Q; // Invalid coefficient
        assert!(Polynomial::from_coeffs(invalid_coeffs).is_err());
    }

    #[test]
    fn test_polynomial_ntt_form_fails_closed() {
        let poly = Polynomial::new();
        assert!(!poly.is_ntt_form());
    }

    #[test]
    fn test_keypair_creation() {
        let pk_bytes = [1u8; MLKEM_PUBLICKEY_BYTES];
        let sk_bytes = [2u8; MLKEM_SECRETKEY_BYTES];

        let pk = PublicKey::from_bytes(pk_bytes);
        let sk = PrivateKey::from_bytes(sk_bytes);
        let keypair = KeyPair::new(pk.clone(), sk);

        assert_eq!(keypair.public_key, pk);
        assert!(keypair.private_key == PrivateKey::from_bytes(sk_bytes));

        let (split_pk, split_sk) = keypair.split();
        assert_eq!(split_pk, pk);
        assert!(split_sk == PrivateKey::from_bytes(sk_bytes));
    }
}
