//! RNG utilities for Falcon-512

use rand_core::{RngCore, CryptoRng, Error as RngError};

// Simple test RNG for no_std
pub struct FalconRng {
    state: u64,
}

impl FalconRng {
    pub fn new(seed: u64) -> Self {
        FalconRng { state: seed }
    }
    
    pub fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(1664525).wrapping_add(1013904223);
        (self.state >> 32) as u32
    }
    
    pub fn next_u64(&mut self) -> u64 {
        let low = self.next_u32() as u64;
        let high = self.next_u32() as u64;
        (high << 32) | low
    }
}

// Implement RngCore trait for FalconRng
impl RngCore for FalconRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u32()
    }
    
    fn next_u64(&mut self) -> u64 {
        self.next_u64()
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= dest.len() {
            let val = self.next_u64();
            dest[i..i+8].copy_from_slice(&val.to_le_bytes());
            i += 8;
        }
        if i < dest.len() {
            let val = self.next_u64();
            let bytes = val.to_le_bytes();
            let remaining = dest.len() - i;
            dest[i..].copy_from_slice(&bytes[..remaining]);
        }
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// Mark FalconRng as cryptographically secure (for testing purposes)
impl CryptoRng for FalconRng {}

#[cfg(test)]
pub type TestRng = FalconRng;
