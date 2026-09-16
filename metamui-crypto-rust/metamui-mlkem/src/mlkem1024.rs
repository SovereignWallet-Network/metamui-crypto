//! ML-KEM-1024 implementation (NIST Level 5 security)

use crate::{
    error::{MLKemError, Result},
    params::MLKEM1024_PARAMS,
    kem::mlkem_keygen,
    kem::mlkem_encapsulate,
    kem::mlkem_decapsulate,
    Kem,
};
use rand_core::{CryptoRng, RngCore};
use metamui_security_utils::Zeroize;

/// ML-KEM-1024 public key
#[derive(Clone)]
pub struct PublicKey {
    bytes: [u8; 1568],
}

/// ML-KEM-1024 secret key
pub struct SecretKey {
    bytes: [u8; 3168],
}

/// ML-KEM-1024 ciphertext
#[derive(Clone)]
pub struct Ciphertext {
    bytes: [u8; 1568],
}

/// ML-KEM-1024 shared secret
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl PublicKey {
    /// Create a public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM1024_PARAMS.public_key_bytes {
            return Err(MLKemError::InvalidKeySize);
        }
        let mut key = PublicKey {
            bytes: [0u8; 1568],
        };
        key.bytes.copy_from_slice(bytes);
        Ok(key)
    }
    
    /// Get the public key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl SecretKey {
    /// Create a secret key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM1024_PARAMS.secret_key_bytes {
            return Err(MLKemError::InvalidKeySize);
        }
        let mut key = SecretKey {
            bytes: [0u8; 3168],
        };
        key.bytes.copy_from_slice(bytes);
        Ok(key)
    }
    
    /// Get the secret key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Ciphertext {
    /// Create a ciphertext from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM1024_PARAMS.ciphertext_bytes {
            return Err(MLKemError::InvalidCiphertextSize);
        }
        let mut ct = Ciphertext {
            bytes: [0u8; 1568],
        };
        ct.bytes.copy_from_slice(bytes);
        Ok(ct)
    }
    
    /// Get the ciphertext as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl SharedSecret {
    /// Get the shared secret as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// Implement zeroization for secret values
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// Implement AsRef and AsMut for compatibility
impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for PublicKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for SecretKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for Ciphertext {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsMut<[u8]> for SharedSecret {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

/// Generate an ML-KEM-1024 keypair from explicit (d, z) per FIPS 203 §6.1.
///
/// Used for ACVP keyGen byte-equality validation against NIST FIPS 203
/// test vectors.
///
/// Test-only: compiled with the `fips203-internal` feature (see the crate docs).
#[cfg(feature = "fips203-internal")]
pub fn generate_keypair_from_dz(d: &[u8; 32], z: &[u8; 32]) -> Result<(PublicKey, SecretKey)> {
    let mut pk = PublicKey { bytes: [0u8; 1568] };
    let mut sk = SecretKey { bytes: [0u8; 3168] };
    crate::kem::mlkem_keygen_from_dz(&MLKEM1024_PARAMS, &mut pk.bytes, &mut sk.bytes, d, z)?;
    Ok((pk, sk))
}

/// Generate an ML-KEM-1024 keypair deterministically from a 32-byte seed.
///
/// Cross-language byte-equality contract: see `crate::kem::mlkem_keygen_from_seed`.
///
/// Test-only: compiled with the `fips203-internal` feature (see the crate docs).
#[cfg(feature = "fips203-internal")]
pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> Result<(PublicKey, SecretKey)> {
    let mut pk = PublicKey { bytes: [0u8; 1568] };
    let mut sk = SecretKey { bytes: [0u8; 3168] };
    crate::kem::mlkem_keygen_from_seed(&MLKEM1024_PARAMS, &mut pk.bytes, &mut sk.bytes, seed)?;
    Ok((pk, sk))
}

/// Deterministically encapsulate an ML-KEM-1024 shared secret using `m` as
/// the 32-byte message instead of sampling from an RNG.
///
/// Test-only: compiled with the `fips203-internal` feature (see the crate docs).
#[cfg(feature = "fips203-internal")]
pub fn encapsulate_deterministic(
    public_key: &PublicKey,
    m: &[u8; 32],
) -> Result<(Ciphertext, SharedSecret)> {
    let mut ct = Ciphertext { bytes: [0u8; 1568] };
    let mut ss = SharedSecret { bytes: [0u8; 32] };
    crate::kem::mlkem_encapsulate_deterministic(
        &MLKEM1024_PARAMS,
        &public_key.bytes,
        &mut ct.bytes,
        &mut ss.bytes,
        m,
    )?;
    Ok((ct, ss))
}

/// Decapsulate an ML-KEM-1024 shared secret (free-function convenience
/// matching the deterministic API surface used by KAT generators).
pub fn decapsulate(secret_key: &SecretKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
    let mut ss = SharedSecret { bytes: [0u8; 32] };
    crate::kem::mlkem_decapsulate(
        &MLKEM1024_PARAMS,
        &secret_key.bytes,
        &ciphertext.bytes,
        &mut ss.bytes,
    )?;
    Ok(ss)
}

/// ML-KEM-1024 implementation
pub struct MLKem1024;

impl Kem for MLKem1024 {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Ciphertext = Ciphertext;
    type SharedSecret = SharedSecret;
    
    fn generate_keypair<R: RngCore + CryptoRng>(
        rng: &mut R
    ) -> Result<(Self::PublicKey, Self::SecretKey)> {
        let mut pk = PublicKey { bytes: [0u8; 1568] };
        let mut sk = SecretKey { bytes: [0u8; 3168] };
        
        mlkem_keygen(&MLKEM1024_PARAMS, &mut pk.bytes, &mut sk.bytes, rng)?;
        
        Ok((pk, sk))
    }
    
    fn encapsulate<R: RngCore + CryptoRng>(
        public_key: &Self::PublicKey,
        rng: &mut R
    ) -> Result<(Self::Ciphertext, Self::SharedSecret)> {
        let mut ct = Ciphertext { bytes: [0u8; 1568] };
        let mut ss = SharedSecret { bytes: [0u8; 32] };
        
        mlkem_encapsulate(
            &MLKEM1024_PARAMS,
            &public_key.bytes,
            &mut ct.bytes,
            &mut ss.bytes,
            rng
        )?;
        
        Ok((ct, ss))
    }
    
    fn decapsulate(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext
    ) -> Result<Self::SharedSecret> {
        let mut ss = SharedSecret { bytes: [0u8; 32] };
        
        mlkem_decapsulate(
            &MLKEM1024_PARAMS,
            &secret_key.bytes,
            &ciphertext.bytes,
            &mut ss.bytes
        )?;
        
        Ok(ss)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    
    #[test]
    fn test_mlkem1024_keygen() {
        let mut rng = thread_rng();
        let result = MLKem1024::generate_keypair(&mut rng);
        assert!(result.is_ok());
        
        let (pk, sk) = result.unwrap();
        assert_eq!(pk.as_bytes().len(), 1568);
        assert_eq!(sk.as_bytes().len(), 3168);
    }
    
    #[test]
    fn test_mlkem1024_encap_decap() {
        let mut rng = thread_rng();
        
        // Generate keypair
        let (pk, sk) = MLKem1024::generate_keypair(&mut rng).unwrap();
        
        // Encapsulate
        let (ct, ss1) = MLKem1024::encapsulate(&pk, &mut rng).unwrap();
        assert_eq!(ct.as_bytes().len(), 1568);
        assert_eq!(ss1.as_bytes().len(), 32);
        
        // Decapsulate
        let ss2 = MLKem1024::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss2.as_bytes().len(), 32);
        
        // Shared secrets should match
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_mlkem1024_basic() {
        test_mlkem1024_keygen();
        test_mlkem1024_encap_decap();
    }

    #[test]
    fn test_mlkem1024_deterministic_roundtrip() {
        let seed = [0x42u8; 32];
        let m = [0x77u8; 32];

        let (pk, sk) = generate_keypair_from_seed(&seed).expect("keygen_from_seed");
        let (ct, ss_enc) = encapsulate_deterministic(&pk, &m).expect("encap_det");
        let ss_dec = decapsulate(&sk, &ct).expect("decap");
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn test_mlkem1024_deterministic_is_deterministic() {
        let seed = [0x55u8; 32];
        let m = [0x78u8; 32];

        let (pk1, sk1) = generate_keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = generate_keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1.as_bytes(), pk2.as_bytes(), "keygen non-determinism");
        assert_eq!(sk1.as_bytes(), sk2.as_bytes(), "keygen non-determinism");

        let (ct1, ss1) = encapsulate_deterministic(&pk1, &m).unwrap();
        let (ct2, ss2) = encapsulate_deterministic(&pk1, &m).unwrap();
        assert_eq!(ct1.as_bytes(), ct2.as_bytes(), "encap non-determinism");
        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "encap non-determinism");
    }
}

/// FIPS 203 §7.2 encapsulation-key check for ML-KEM-1024 (see
/// [`crate::kem::mlkem_validate_encapsulation_key`]).
pub fn validate_encapsulation_key(ek: &[u8]) -> bool {
    crate::kem::mlkem_validate_encapsulation_key(&crate::params::MLKEM1024_PARAMS, ek)
}

/// FIPS 203 §7.3 decapsulation-key check for ML-KEM-1024 (see
/// [`crate::kem::mlkem_validate_decapsulation_key`]).
pub fn validate_decapsulation_key(dk: &[u8]) -> bool {
    crate::kem::mlkem_validate_decapsulation_key(&crate::params::MLKEM1024_PARAMS, dk)
}
