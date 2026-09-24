//! Core types for SLH-DSA implementation

use crate::{Parameters, Result, Error};
use core::marker::PhantomData;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

/// SLH-DSA signing key (secret key)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey<P: Parameters> {
    /// Secret seed (SK.seed)
    sk_seed: Vec<u8>,
    /// Secret PRF key (SK.prf)
    sk_prf: Vec<u8>,
    /// Public seed (PK.seed)
    pk_seed: Vec<u8>,
    /// Public root (PK.root)
    pk_root: Vec<u8>,
    /// Parameter set marker
    _params: PhantomData<P>,
}

impl<P: Parameters> SigningKey<P> {
    /// Generate a new signing key
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut sk_seed = vec![0u8; P::N];
        let mut sk_prf = vec![0u8; P::N];
        let mut pk_seed = vec![0u8; P::N];
        
        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut sk_prf);
        rng.fill_bytes(&mut pk_seed);
        
        // Generate the root of the hypertree
        let pk_root = Self::generate_root(&sk_seed, &pk_seed);
        
        SigningKey {
            sk_seed,
            sk_prf,
            pk_seed,
            pk_root,
            _params: PhantomData,
        }
    }
    
    /// Generate the root of the hypertree
    fn generate_root(sk_seed: &[u8], pk_seed: &[u8]) -> Vec<u8> {
        crate::hypertree::hypertree_root::<P>(sk_seed, pk_seed)
    }
    
    /// Create a signing key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != P::SK_BYTES {
            return Err(Error::InvalidKeySize);
        }
        
        let n = P::N;
        Ok(SigningKey {
            sk_seed: bytes[0..n].to_vec(),
            sk_prf: bytes[n..2*n].to_vec(),
            pk_seed: bytes[2*n..3*n].to_vec(),
            pk_root: bytes[3*n..4*n].to_vec(),
            _params: PhantomData,
        })
    }
    
    /// Serialize the signing key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(P::SK_BYTES);
        bytes.extend_from_slice(&self.sk_seed);
        bytes.extend_from_slice(&self.sk_prf);
        bytes.extend_from_slice(&self.pk_seed);
        bytes.extend_from_slice(&self.pk_root);
        bytes
    }
    
    /// Get the corresponding verifying key
    pub fn verifying_key(&self) -> VerifyingKey<P> {
        VerifyingKey {
            pk_seed: self.pk_seed.clone(),
            pk_root: self.pk_root.clone(),
            _params: PhantomData,
        }
    }
    
    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature<P> {
        let sig = crate::signing::slh_sign_deterministic::<P>(
            &self.sk_seed,
            &self.sk_prf,
            &self.pk_seed,
            &self.pk_root,
            message,
            &[],
        ).unwrap_or_else(|_| vec![0u8; P::SIG_BYTES]);

        Signature {
            bytes: sig,
            _params: PhantomData,
        }
    }

    /// Sign a message with randomization
    pub fn sign_with_rng<R: RngCore + CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R
    ) -> Signature<P> {
        let sig = crate::signing::slh_sign_randomized::<P, R>(
            &self.sk_seed,
            &self.sk_prf,
            &self.pk_seed,
            &self.pk_root,
            message,
            rng,
            &[],
        ).unwrap_or_else(|_| vec![0u8; P::SIG_BYTES]);

        Signature {
            bytes: sig,
            _params: PhantomData,
        }
    }
}

/// SLH-DSA verifying key (public key)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey<P: Parameters> {
    /// Public seed (PK.seed)
    pk_seed: Vec<u8>,
    /// Public root (PK.root)
    pk_root: Vec<u8>,
    /// Parameter set marker
    _params: PhantomData<P>,
}

impl<P: Parameters> VerifyingKey<P> {
    /// Create a verifying key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != P::PK_BYTES {
            return Err(Error::InvalidKeySize);
        }
        
        let n = P::N;
        Ok(VerifyingKey {
            pk_seed: bytes[0..n].to_vec(),
            pk_root: bytes[n..2*n].to_vec(),
            _params: PhantomData,
        })
    }
    
    /// Serialize the verifying key to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(P::PK_BYTES);
        bytes.extend_from_slice(&self.pk_seed);
        bytes.extend_from_slice(&self.pk_root);
        bytes
    }
    
    /// Verify a signature on a message
    pub fn verify(&self, message: &[u8], signature: &Signature<P>) -> Result<()> {
        crate::verification::slh_verify::<P>(
            &self.pk_seed,
            &self.pk_root,
            message,
            &[],
            &signature.bytes,
        )
    }
    /// Verify a signature on a message with context
    pub fn verify_with_context(&self, message: &[u8], context: &[u8], signature: &Signature<P>) -> Result<()> {
        crate::verification::slh_verify::<P>(
            &self.pk_seed,
            &self.pk_root,
            message,
            context,
            &signature.bytes,
        )
    }
}

/// SLH-DSA signature
#[derive(Clone)]
pub struct Signature<P: Parameters> {
    /// Signature bytes
    bytes: Vec<u8>,
    /// Parameter set marker
    _params: PhantomData<P>,
}

impl<P: Parameters> Signature<P> {
    /// Create a signature from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != P::SIG_BYTES {
            return Err(Error::InvalidSignatureSize);
        }
        
        Ok(Signature {
            bytes: bytes.to_vec(),
            _params: PhantomData,
        })
    }
    
    /// Get the signature as bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Get the randomizer from the signature
    pub fn randomizer(&self) -> &[u8] {
        &self.bytes[0..P::N]
    }
    
    /// Get the FORS signature from the signature
    pub fn fors_signature(&self) -> &[u8] {
        let fors_sig_bytes = P::K * (P::A + 1) * P::N;
        &self.bytes[P::N..P::N + fors_sig_bytes]
    }
    
    /// Get the hypertree signature from the signature
    pub fn hypertree_signature(&self) -> &[u8] {
        let fors_sig_bytes = P::K * (P::A + 1) * P::N;
        &self.bytes[P::N + fors_sig_bytes..]
    }
}

// Address is defined in address.rs module

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SlhDsa128s;
    
    #[test]
    fn test_address_serialization() {
        use crate::address::Address;

        let mut addr = Address::new();
        addr.set_layer(3);
        addr.set_tree(0x123456789ABCDEF0);
        addr.set_type_wots();

        let bytes = addr.to_bytes();
        assert_eq!(bytes[0..4], [0, 0, 0, 3]); // layer
        assert_eq!(bytes[20..24], [0, 0, 0, 0]); // type (moved from bytes 12-15 to 20-23 for u128 tree)
    }
    
    #[test]
    fn test_key_sizes() {
        type TestParams = SlhDsa128s;
        
        // Test that key sizes match parameters
        assert_eq!(TestParams::SK_BYTES, 4 * TestParams::N);
        assert_eq!(TestParams::PK_BYTES, 2 * TestParams::N);
    }
}