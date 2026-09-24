//! SHAKE XOF (Extendable Output Function) wrappers for HAETAE
//!
//! This module provides streaming interfaces to SHAKE128 and SHAKE256
//! for deterministic polynomial expansion and key derivation, over the
//! in-house `metamui-shake` Keccak sponge (no RustCrypto crate is in this
//! crate's closure — CLAUDE.md, #199).
//!
//! Transcopy from: metamui-haetae/src/symmetric-shake.c

use metamui_shake::{Shake128, Shake128Reader, Shake256, Shake256Reader};
use crate::params::{SEEDBYTES, CRHBYTES};

/// SHAKE128 rate in bytes (168 bytes)
pub const SHAKE128_RATE: usize = 168;

/// SHAKE256 rate in bytes (136 bytes)
pub const SHAKE256_RATE: usize = 136;

/// SHAKE128 stream state
pub struct Shake128Stream {
    reader: Shake128Reader,
}

impl Shake128Stream {
    /// Initialize SHAKE128 stream with seed and nonce
    ///
    /// Absorbs: seed || nonce (little-endian u16)
    ///
    /// Transcopy from: void haetae_shake128_stream_init(...)
    pub fn new(seed: &[u8; SEEDBYTES], nonce: u16) -> Self {
        let mut hasher = Shake128::new();
        hasher.update(seed);
        hasher.update(&nonce.to_le_bytes());
        Self { reader: hasher.finalize_xof() }
    }

    /// Squeeze blocks of SHAKE128_RATE bytes
    ///
    /// # Arguments
    /// * `out` - Output buffer (must be multiple of SHAKE128_RATE)
    /// * `nblocks` - Number of blocks to squeeze
    pub fn squeeze_blocks(&mut self, out: &mut [u8], nblocks: usize) {
        assert_eq!(out.len(), nblocks * SHAKE128_RATE);
        self.reader.read_into(out);
    }

    /// Squeeze arbitrary number of bytes
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.reader.read_into(out);
    }
}

/// SHAKE256 stream state
pub struct Shake256Stream {
    reader: Shake256Reader,
}

impl Shake256Stream {
    /// Initialize SHAKE256 stream with seed and nonce
    ///
    /// Absorbs: seed || nonce (little-endian u16)
    ///
    /// Transcopy from: void haetae_shake256_stream_init(...)
    pub fn new(seed: &[u8; CRHBYTES], nonce: u16) -> Self {
        Self { reader: shake256_multi(&[seed, &nonce.to_le_bytes()]) }
    }

    /// Squeeze blocks of SHAKE256_RATE bytes
    ///
    /// # Arguments
    /// * `out` - Output buffer (must be multiple of SHAKE256_RATE)
    /// * `nblocks` - Number of blocks to squeeze
    pub fn squeeze_blocks(&mut self, out: &mut [u8], nblocks: usize) {
        assert_eq!(out.len(), nblocks * SHAKE256_RATE);
        self.reader.read_into(out);
    }

    /// Squeeze arbitrary number of bytes
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.reader.read_into(out);
    }
}

/// SHAKE256 over the concatenation of `parts`, returned in its squeeze
/// phase. This is the one absorb path every `H(...)` in sign/verify and the
/// challenge/hyperball samplers go through (the C code's
/// `shake256_init` / `absorb`* / `finalize` sequence).
pub fn shake256_multi(parts: &[&[u8]]) -> Shake256Reader {
    let mut hasher = Shake256::new();
    for part in parts {
        hasher
            .update(part)
            .expect("SHAKE-256 state is absorbing until finalize_xof");
    }
    hasher.finalize_xof()
}

/// SHAKE256 absorb-once interface for hashing
///
/// Transcopy from: void haetae_shake256_absorb_twice(...)
pub fn shake256_absorb_twice(input1: &[u8], input2: &[u8]) -> Shake256Reader {
    shake256_multi(&[input1, input2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake128_stream_basic() {
        let seed = [0u8; SEEDBYTES];
        let nonce = 0u16;
        
        let mut stream = Shake128Stream::new(&seed, nonce);
        let mut out1 = vec![0u8; SHAKE128_RATE];
        let mut out2 = vec![0u8; SHAKE128_RATE];
        
        stream.squeeze_blocks(&mut out1, 1);
        
        // Second stream with same seed/nonce should produce same output
        let mut stream2 = Shake128Stream::new(&seed, nonce);
        stream2.squeeze_blocks(&mut out2, 1);
        
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_shake128_different_nonces() {
        let seed = [0u8; SEEDBYTES];
        
        let mut stream1 = Shake128Stream::new(&seed, 0);
        let mut stream2 = Shake128Stream::new(&seed, 1);
        
        let mut out1 = vec![0u8; SHAKE128_RATE];
        let mut out2 = vec![0u8; SHAKE128_RATE];
        
        stream1.squeeze_blocks(&mut out1, 1);
        stream2.squeeze_blocks(&mut out2, 1);
        
        // Different nonces should produce different outputs
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_shake256_stream_basic() {
        let seed = [0u8; CRHBYTES];
        let nonce = 0u16;
        
        let mut stream = Shake256Stream::new(&seed, nonce);
        let mut out = vec![0u8; SHAKE256_RATE];
        
        stream.squeeze_blocks(&mut out, 1);
        
        // Should produce non-zero output
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_shake256_absorb_twice() {
        let input1 = b"hello";
        let input2 = b"world";
        
        let mut reader = shake256_absorb_twice(input1, input2);
        let mut out = [0u8; 32];
        reader.read_into(&mut out);
        
        // Should produce deterministic output
        let mut reader2 = shake256_absorb_twice(input1, input2);
        let mut out2 = [0u8; 32];
        reader2.read_into(&mut out2);
        
        assert_eq!(out, out2);
    }

    /// Absorbing in pieces equals absorbing the concatenation, and the
    /// squeeze stream continues across reads (both properties the samplers
    /// rely on).
    #[test]
    fn multi_part_absorb_and_continued_squeeze() {
        let mut a = shake256_multi(&[b"hello", b"world"]);
        let mut b = shake256_multi(&[b"helloworld"]);
        let mut a1 = [0u8; 100];
        let mut a2 = [0u8; 100];
        let mut b12 = [0u8; 200];
        a.read_into(&mut a1);
        a.read_into(&mut a2);
        b.read_into(&mut b12);
        assert_eq!(&b12[..100], &a1[..]);
        assert_eq!(&b12[100..], &a2[..]);
        assert_eq!(&b12[..], &metamui_shake::shake256(b"helloworld", 200)[..]);
    }
}
