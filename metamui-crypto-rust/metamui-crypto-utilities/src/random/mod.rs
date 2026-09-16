// MetaMUI metamui crypto utilities   random
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto


/// Secure random number generation utilities

use crate::error::{CryptoUtilError, Result};
use metamui_security_utils::Zeroize;


/// Test/benchmark random number generator
#[cfg(any(test, feature = "test-utils"))]
pub mod test_rng;

/// Secure random number generator
pub struct Random;


impl Random {
    /// Create a new secure random number generator
    pub fn new() -> Self {
        Self
    }
    
    /// Generate random bytes
    pub fn generate_bytes(&self, count: usize) -> Result<Vec<u8>> {
        if count == 0 || count > 1048576 {
            return Err(CryptoUtilError::InvalidInputLength {
                expected: 1048576,
                actual: count,
            });
        }
        
        let mut bytes = vec![0u8; count];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| CryptoUtilError::RandomGenerationFailed)?;
        Ok(bytes)
    }
    
    /// Generate a random 32-byte seed
    pub fn generate_seed(&self) -> Result<[u8; 32]> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|_| CryptoUtilError::RandomGenerationFailed)?;
        Ok(seed)
    }
    
    /// Generate a random u64
    pub fn generate_u64(&self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| CryptoUtilError::RandomGenerationFailed)?;
        Ok(u64::from_le_bytes(bytes))
    }
    
    /// Fill a mutable slice with random bytes
    pub fn fill_bytes(&self, dest: &mut [u8]) -> Result<()> {
        getrandom::getrandom(dest)
            .map_err(|_| CryptoUtilError::RandomGenerationFailed)?;
        Ok(())
    }
    
    /// Validate entropy quality
    pub fn validate_entropy(&self) -> Result<()> {
        // Test 1: Can generate random data
        let sample1 = self.generate_bytes(32)?;
        let sample2 = self.generate_bytes(32)?;
        
        // Test 2: Samples are different
        if sample1 == sample2 {
            return Err(CryptoUtilError::EntropyValidationFailed);
        }
        
        // Test 3: Not all zeros
        if sample1.iter().all(|&b| b == 0) {
            return Err(CryptoUtilError::EntropyValidationFailed);
        }
        
        // Test 4: Not all ones
        if sample1.iter().all(|&b| b == 0xFF) {
            return Err(CryptoUtilError::EntropyValidationFailed);
        }
        
        // Test 5: Basic entropy check - at least 8 unique bytes in 32
        let mut unique_bytes = [false; 256];
        let mut unique_count = 0;
        for &byte in sample1.iter() {
            if !unique_bytes[byte as usize] {
                unique_bytes[byte as usize] = true;
                unique_count += 1;
            }
        }
        
        if unique_count < 8 {
            return Err(CryptoUtilError::EntropyValidationFailed);
        }
        
        Ok(())
    }
}

impl Default for Random {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate secure random bytes (convenience function)
pub fn random_bytes(count: usize) -> Result<Vec<u8>> {
    Random::new().generate_bytes(count)
}

/// Random seed that automatically clears on drop
#[derive(Clone)]
pub struct RandomSeed([u8; 32]);

impl RandomSeed {
    /// Create a new random seed
    pub fn new() -> Result<Self> {
        let seed = Random::new().generate_seed()?;
        Ok(Self(seed))
    }
    
    /// Get the seed bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    /// Consume the seed and return the bytes
    pub fn into_bytes(mut self) -> [u8; 32] {
        let bytes = self.0;
        self.0.zeroize();
        bytes
    }
}

impl Drop for RandomSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for RandomSeed {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_random() {
        let rng = Random::new();
        
        // Test byte generation
        let bytes1 = rng.generate_bytes(32).unwrap();
        let bytes2 = rng.generate_bytes(32).unwrap();
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2);
        
        // Test seed generation
        let seed1 = rng.generate_seed().unwrap();
        let seed2 = rng.generate_seed().unwrap();
        assert_ne!(seed1, seed2);
        
        // Test u64 generation
        let u1 = rng.generate_u64().unwrap();
        let u2 = rng.generate_u64().unwrap();
        assert_ne!(u1, u2);
    }
    
    #[test]
    fn test_entropy_validation() {
        let rng = Random::new();
        assert!(rng.validate_entropy().is_ok());
    }
    
    #[test]
    fn test_random_seed() {
        let seed1 = RandomSeed::new().unwrap();
        let seed2 = RandomSeed::new().unwrap();
        assert_ne!(seed1.as_bytes(), seed2.as_bytes());
    }
    
    #[test]
    fn test_invalid_count() {
        let rng = Random::new();
        assert!(rng.generate_bytes(0).is_err());
        assert!(rng.generate_bytes(1048577).is_err());
    }
}
