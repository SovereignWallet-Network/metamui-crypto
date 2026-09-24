/// SHA3 compatibility layer for Dilithium
/// Maps our native implementations to the sha3 crate interface

use metamui_shake::shake256::{Shake256 as NativeShake256, Shake256Reader};
use metamui_crypto_utilities::hashing::sha3::{Sha3_256 as NativeSha3_256, Sha3_512 as NativeSha3_512};
use metamui_crypto_utilities::hashing::keccak::keccak_f;

/// SHA3-256 wrapper
pub struct Sha3_256 {
    hasher: NativeSha3_256,
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self { hasher: NativeSha3_256::new() }
    }
}

impl Sha3_256 {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let _ = self.hasher.update(data.as_ref());
    }
    
    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize()
    }
}

/// SHA3-512 wrapper  
pub struct Sha3_512 {
    hasher: NativeSha3_512,
}

impl Default for Sha3_512 {
    fn default() -> Self {
        Self { hasher: NativeSha3_512::new() }
    }
}

impl Sha3_512 {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let _ = self.hasher.update(data.as_ref());
    }
    
    pub fn finalize(self) -> [u8; 64] {
        self.hasher.finalize()
    }
}

/// SHAKE256 wrapper
pub struct Shake256 {
    hasher: NativeShake256,
}

impl Default for Shake256 {
    fn default() -> Self {
        Self {
            hasher: NativeShake256::new(),
        }
    }
}

impl Shake256 {
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let _ = self.hasher.update(data.as_ref());
    }
    
    pub fn finalize_xof(self) -> Shake256XofReader {
        Shake256XofReader {
            reader: self.hasher.finalize_xof(),
        }
    }
}

pub struct Shake256XofReader {
    reader: Shake256Reader,
}

impl Shake256XofReader {
    pub fn read(&mut self, buffer: &mut [u8]) {
        let data = self.reader.read(buffer.len());
        buffer.copy_from_slice(&data);
    }
}

/// Digest trait compatibility
pub mod digest {
    use super::*;
    
    pub trait Digest {
        type OutputSize;
        
        fn new() -> Self;
        fn update(&mut self, data: impl AsRef<[u8]>);
        fn finalize(self) -> Self::OutputSize;
    }
    
    impl Digest for Sha3_256 {
        type OutputSize = [u8; 32];
        
        fn new() -> Self {
            Self::default()
        }
        
        fn update(&mut self, data: impl AsRef<[u8]>) {
            self.update(data);
        }
        
        fn finalize(self) -> Self::OutputSize {
            self.finalize()
        }
    }
    
    impl Digest for Sha3_512 {
        type OutputSize = [u8; 64];
        
        fn new() -> Self {
            Self::default()
        }
        
        fn update(&mut self, data: impl AsRef<[u8]>) {
            self.update(data);
        }
        
        fn finalize(self) -> Self::OutputSize {
            self.finalize()
        }
    }
    
    pub trait Update {
        fn update(&mut self, data: impl AsRef<[u8]>);
    }
    
    impl Update for Shake256 {
        fn update(&mut self, data: impl AsRef<[u8]>) {
            self.update(data);
        }
    }
    
    pub trait ExtendableOutput {
        type Reader: XofReader;
        
        fn finalize_xof(self) -> Self::Reader;
    }
    
    impl ExtendableOutput for Shake256 {
        type Reader = Shake256XofReader;
        
        fn finalize_xof(self) -> Self::Reader {
            self.finalize_xof()
        }
    }
    
    pub trait XofReader {
        fn read(&mut self, buffer: &mut [u8]);
    }
    
    impl XofReader for Shake256XofReader {
        fn read(&mut self, buffer: &mut [u8]) {
            self.read(buffer);
        }
    }
}

/// SHAKE128 implementation using Keccak
pub struct Shake128 {
    state: [u64; 25],
    buf: Vec<u8>,
    /// Reserved for an incremental XOF reader; today the Shake128
    /// interface squeezes a whole buffer at once in finalize_xof().
    #[allow(dead_code)]
    pos: usize,
}

impl Default for Shake128 {
    fn default() -> Self {
        Self { 
            state: [0u64; 25],
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl Shake128 {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
    
    pub fn finalize_xof(mut self) -> Shake128XofReader {
        // SHAKE128 has rate 168 (1344 bits = 21 * 8 bytes)
        const RATE: usize = 168;
        
        // Pad with SHAKE domain separator (0x1F) and padding
        self.buf.push(0x1F);
        while self.buf.len() % RATE != 0 {
            self.buf.push(0);
        }
        let last_idx = self.buf.len() - 1;
        self.buf[last_idx] |= 0x80;
        
        // Absorb all blocks
        for chunk in self.buf.chunks_exact(RATE) {
            // XOR chunk into state
            for i in 0..21 {  // 168 / 8 = 21
                if i * 8 < chunk.len() {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&chunk[i * 8..(i * 8 + 8).min(chunk.len())]);
                    self.state[i] ^= u64::from_le_bytes(bytes);
                }
            }
            keccak_f(&mut self.state);
        }
        
        Shake128XofReader { 
            state: self.state,
            buffer: vec![0u8; RATE],
            buffer_pos: RATE,
        }
    }
}

pub struct Shake128XofReader {
    state: [u64; 25],
    buffer: Vec<u8>,
    buffer_pos: usize,
}

impl digest::XofReader for Shake128XofReader {
    fn read(&mut self, out: &mut [u8]) {
        const RATE: usize = 168;
        let mut offset = 0;
        
        while offset < out.len() {
            // Refill buffer if needed
            if self.buffer_pos >= RATE {
                // Extract bytes from state
                for i in 0..21 {  // 168 / 8 = 21
                    let bytes = self.state[i].to_le_bytes();
                    self.buffer[i * 8..(i * 8 + 8).min(RATE)].copy_from_slice(&bytes[..8.min(RATE - i * 8)]);
                }
                keccak_f(&mut self.state);
                self.buffer_pos = 0;
            }
            
            // Copy from buffer
            let available = RATE - self.buffer_pos;
            let needed = out.len() - offset;
            let to_copy = available.min(needed);
            
            out[offset..offset + to_copy].copy_from_slice(
                &self.buffer[self.buffer_pos..self.buffer_pos + to_copy]
            );
            
            self.buffer_pos += to_copy;
            offset += to_copy;
        }
    }
}

impl digest::Update for Shake128 {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.update(data.as_ref());
    }
}

impl digest::ExtendableOutput for Shake128 {
    type Reader = Shake128XofReader;
    
    fn finalize_xof(self) -> Self::Reader {
        self.finalize_xof()
    }
}