// MetaMUI metamui crypto utilities - test random number generator
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! Deterministic random number generator for testing and benchmarking
//! 
//! This module provides a deterministic RNG that implements the `rand::RngCore` trait,
//! suitable for reproducible testing and benchmarking across all MetaMUI packages.

use rand::{RngCore, SeedableRng, Error as RandError};

/// Deterministic random number generator for testing
/// 
/// This RNG uses `rand::rngs::StdRng` internally, which is based on ChaCha8
/// and provides good performance with cryptographic quality randomness.
/// When seeded with the same value, it will always produce the same sequence.
#[derive(Clone, Debug)]
pub struct DeterministicRng {
    inner: rand::rngs::StdRng,
}

impl DeterministicRng {
    /// Create a new deterministic RNG with the given seed
    pub fn new(seed: u64) -> Self {
        Self {
            inner: rand::rngs::StdRng::seed_from_u64(seed),
        }
    }
    
    /// Create from a 32-byte seed
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: rand::rngs::StdRng::from_seed(seed),
        }
    }
    
    /// Get the internal RNG for advanced usage
    pub fn inner(&mut self) -> &mut rand::rngs::StdRng {
        &mut self.inner
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }
    
    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest)
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.inner.try_fill_bytes(dest)
    }
}

impl SeedableRng for DeterministicRng {
    type Seed = <rand::rngs::StdRng as SeedableRng>::Seed;
    
    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            inner: rand::rngs::StdRng::from_seed(seed),
        }
    }
}

/// Test RNG type alias for backward compatibility
pub type TestRng = DeterministicRng;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_deterministic_behavior() {
        let mut rng1 = DeterministicRng::new(42);
        let mut rng2 = DeterministicRng::new(42);
        
        // Should produce same values
        assert_eq!(rng1.next_u64(), rng2.next_u64());
        assert_eq!(rng1.next_u32(), rng2.next_u32());
        
        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];
        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);
        assert_eq!(bytes1, bytes2);
    }
    
    #[test]
    fn test_different_seeds() {
        let mut rng1 = DeterministicRng::new(42);
        let mut rng2 = DeterministicRng::new(43);
        
        // Should produce different values
        assert_ne!(rng1.next_u64(), rng2.next_u64());
    }
    
    #[test]
    fn test_clone() {
        let mut rng1 = DeterministicRng::new(42);
        let _val1 = rng1.next_u64();
        
        let mut rng2 = rng1.clone();
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }
    
    #[test]
    fn test_from_seed() {
        let seed = [1u8; 32];
        let mut rng1 = DeterministicRng::from_seed(seed);
        let mut rng2 = DeterministicRng::from_seed(seed);
        
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }
}