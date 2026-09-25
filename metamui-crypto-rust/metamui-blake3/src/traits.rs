/// Traits for BLAKE3 operations

use crate::{Blake3Hash, Blake3Error, Blake3Result};

#[cfg(not(feature = "std"))]
use alloc::{vec::Vec, string::{String, ToString}};

/// Trait for types that can be hashed with BLAKE3
pub trait Blake3Hashable {
    /// Hash this value using BLAKE3
    fn blake3_hash(&self) -> Blake3Hash;
}

impl Blake3Hashable for [u8] {
    fn blake3_hash(&self) -> Blake3Hash {
        crate::MetaMUIBlake3::new().hash(self)
    }
}

impl Blake3Hashable for Vec<u8> {
    fn blake3_hash(&self) -> Blake3Hash {
        self.as_slice().blake3_hash()
    }
}

impl Blake3Hashable for str {
    fn blake3_hash(&self) -> Blake3Hash {
        self.as_bytes().blake3_hash()
    }
}

impl Blake3Hashable for String {
    fn blake3_hash(&self) -> Blake3Hash {
        self.as_str().blake3_hash()
    }
}

/// Trait for incremental hashing
pub trait Blake3Incremental {
    /// Update the hash with new data
    fn update(&mut self, data: &[u8]);
    
    /// Finalize the hash and return the result
    fn finalize(self) -> Blake3Hash;
    
    /// Reset the hasher to its initial state
    fn reset(&mut self);
}

impl Blake3Incremental for crate::MetaMUIBlake3 {
    fn update(&mut self, data: &[u8]) {
        crate::MetaMUIBlake3::update(self, data);
    }
    
    fn finalize(self) -> Blake3Hash {
        crate::MetaMUIBlake3::finalize(&self)
    }
    
    fn reset(&mut self) {
        crate::MetaMUIBlake3::reset(self);
    }
}

/// Trait for key derivation functions
pub trait Blake3KeyDerivation {
    /// Derive a key from input key material
    fn derive_key(&self, context: &str, input_key_material: &[u8], length: usize) -> Blake3Result<Vec<u8>>;
}

impl Blake3KeyDerivation for crate::MetaMUIBlake3 {
    fn derive_key(&self, context: &str, input_key_material: &[u8], length: usize) -> Blake3Result<Vec<u8>> {
        if context.is_empty() {
            return Err(Blake3Error::InvalidContext("Context cannot be empty".to_string()));
        }
        
        if length == 0 {
            return Err(Blake3Error::InvalidLength { expected: 1, actual: 0 });
        }
        
        Ok(crate::MetaMUIBlake3::derive_key(context, input_key_material, length))
    }
}

/// Trait for Message Authentication Code (MAC) operations
#[allow(dead_code)]
pub trait Blake3Mac {
    /// Generate a MAC for the given data
    fn mac(&self, data: &[u8]) -> Blake3Hash;

    /// Verify a MAC for the given data
    fn verify(&self, data: &[u8], expected_mac: &Blake3Hash) -> bool;
}

impl Blake3Mac for crate::Blake3Mac {
    fn mac(&self, data: &[u8]) -> Blake3Hash {
        self.mac(data)
    }
    
    fn verify(&self, data: &[u8], expected_mac: &Blake3Hash) -> bool {
        self.verify(data, expected_mac)
    }
}