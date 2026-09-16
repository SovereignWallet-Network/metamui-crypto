/// SHAKE256 implementation for Falcon-512

use metamui_shake::shake256::{Shake256, Shake256Reader as MetaMUIShake256Reader};
use alloc::vec::Vec;

/// SHAKE256 context for Falcon
pub struct Shake256Context {
    hasher: Shake256,
}

impl Shake256Context {
    /// Create new SHAKE256 context
    pub fn new() -> Self {
        Self {
            hasher: Shake256::new(),
        }
    }

    /// Update with data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data).expect("SHAKE256 update should not fail");
    }

    /// Finalize and read output
    pub fn finalize_xof(self) -> Shake256Reader {
        Shake256Reader {
            reader: self.hasher.finalize_xof(),
        }
    }

    /// Hash message for signing
    pub fn hash_message(nonce: &[u8], message: &[u8]) -> Vec<u8> {
        let mut ctx = Self::new();
        
        // Domain separator for Falcon-512
        ctx.update(&[0x30, 0x50]); // "0P" for 512
        
        // Nonce (40 bytes)
        ctx.update(nonce);
        
        // Message
        ctx.update(message);
        
        let mut reader = ctx.finalize_xof();
        reader.read_bytes(64) // 512 bits
    }
}

pub struct Shake256Reader {
    reader: MetaMUIShake256Reader,
}

impl Shake256Reader {
    /// Read bytes from SHAKE256 output into buffer
    pub fn read(&mut self, buffer: &mut [u8]) {
        let output = self.reader.read(buffer.len());
        buffer.copy_from_slice(&output);
    }
    
    /// Read and return specified number of bytes
    pub fn read_bytes(&mut self, len: usize) -> Vec<u8> {
        self.reader.read(len)
    }
}

/// Generate randomness from seed using SHAKE256
pub fn expand_seed(seed: &[u8]) -> Shake256Reader {
    let mut ctx = Shake256Context::new();
    ctx.update(seed);
    ctx.finalize_xof()
}

/// Hash a message with nonce using SHAKE256 (wrapper for compatibility)
pub fn shake256_hash(nonce: &[u8], message: &[u8]) -> Vec<u8> {
    Shake256Context::hash_message(nonce, message)
}

/// Simple SHAKE256 function for generating output of specified length
pub fn shake256(input: &[u8], output: &mut [u8]) {
    let result = Shake256::hash(input, output.len());
    output.copy_from_slice(&result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake256() {
        let seed = b"test seed";
        let mut reader = expand_seed(seed);
        let output1 = reader.read_bytes(32);
        let output2 = reader.read_bytes(32);
        
        // Outputs should be different
        assert_ne!(output1, output2);
        
        // But deterministic
        let mut reader2 = expand_seed(seed);
        let output3 = reader2.read_bytes(32);
        assert_eq!(output1, output3);
    }
}