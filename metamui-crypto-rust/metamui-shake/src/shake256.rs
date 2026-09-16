//! MetaMUI SHAKE-256 Implementation
//!
//! SHAKE-256 extendable-output function (XOF) based on Keccak sponge construction.
//! FIPS 202 compliant. Rate = 136 bytes (capacity = 512 bits).
//! Used by Falcon-512 for hash-to-point and seed expansion.
//!
//! Re-exported from [`metamui_shake::shake256`].

use alloc::vec;
use alloc::vec::Vec;

// ============================================================================
// Keccak-f[1600] Permutation
// ============================================================================

use crate::keccak::keccak_f1600 as keccak_f;

// ============================================================================
// SHAKE-256 Sponge
// ============================================================================

/// SHAKE-256 rate: 1088 bits = 136 bytes (capacity = 512 bits)
const RATE: usize = 136;

/// SHAKE-256 error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shake256Error {
    /// Hasher was already finalized
    AlreadyFinalized,
}

impl core::fmt::Display for Shake256Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Shake256Error::AlreadyFinalized => write!(f, "SHAKE256: already finalized"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Shake256Error {}

/// SHAKE-256 extendable-output function
#[derive(Clone)]
pub struct Shake256 {
    state: [u64; 25],
    buffer: [u8; RATE],
    buffer_len: usize,
    finalized: bool,
}

impl Shake256 {
    /// Create a new SHAKE-256 instance
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; RATE],
            buffer_len: 0,
            finalized: false,
        }
    }

    /// Absorb data into the sponge
    pub fn update(&mut self, data: &[u8]) -> Result<(), Shake256Error> {
        if self.finalized {
            return Err(Shake256Error::AlreadyFinalized);
        }

        let mut offset = 0;
        while offset < data.len() {
            let remaining = RATE - self.buffer_len;
            let copy_len = core::cmp::min(remaining, data.len() - offset);

            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[offset..offset + copy_len]);
            self.buffer_len += copy_len;
            offset += copy_len;

            if self.buffer_len == RATE {
                self.absorb_block();
                self.buffer_len = 0;
            }
        }

        Ok(())
    }

    /// Finalize the absorb phase and return an XOF reader
    pub fn finalize_xof(mut self) -> Shake256Reader {
        if !self.finalized {
            // SHAKE domain separator: 0x1F (differs from SHA-3's 0x06)
            self.buffer[self.buffer_len] = 0x1F;
            self.buffer_len += 1;

            // Zero-fill remaining buffer
            while self.buffer_len < RATE {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }

            // Set final bit for 10*1 padding
            self.buffer[RATE - 1] |= 0x80;

            self.absorb_block();
            self.finalized = true;
        }

        Shake256Reader {
            state: self.state,
            squeeze_offset: 0,
        }
    }

    /// Finalize and produce `output_len` bytes of output (convenience method).
    ///
    /// Equivalent to calling `finalize_xof()` then `reader.read(output_len)`.
    pub fn finalize(self, output_len: usize) -> Vec<u8> {
        let mut reader = self.finalize_xof();
        reader.read(output_len)
    }

    /// One-shot hash producing output of specified length
    pub fn hash(input: &[u8], output_len: usize) -> Vec<u8> {
        let mut hasher = Self::new();
        hasher.update(input).expect("fresh hasher cannot be finalized");
        let mut reader = hasher.finalize_xof();
        reader.read(output_len)
    }

    /// XOR the rate portion of the buffer into the state and permute
    fn absorb_block(&mut self) {
        // XOR buffer into state (rate bytes only, little-endian u64 words)
        let rate_words = RATE / 8; // 17 words for SHAKE-256
        for i in 0..rate_words {
            let word = u64::from_le_bytes([
                self.buffer[i * 8],
                self.buffer[i * 8 + 1],
                self.buffer[i * 8 + 2],
                self.buffer[i * 8 + 3],
                self.buffer[i * 8 + 4],
                self.buffer[i * 8 + 5],
                self.buffer[i * 8 + 6],
                self.buffer[i * 8 + 7],
            ]);
            self.state[i] ^= word;
        }
        keccak_f(&mut self.state);
    }
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SHAKE-256 XOF Reader (Squeeze Phase)
// ============================================================================

/// Reader for SHAKE-256 extendable output
#[derive(Clone)]
pub struct Shake256Reader {
    state: [u64; 25],
    squeeze_offset: usize,
}

impl Shake256Reader {
    /// Read `len` bytes of output from the XOF
    pub fn read(&mut self, len: usize) -> Vec<u8> {
        let mut output = vec![0u8; len];
        self.read_into(&mut output);
        output
    }

    /// Read bytes directly into the provided buffer, continuing the stream
    /// (the counterpart of [`crate::Shake128Reader::read_into`]).
    pub fn read_into(&mut self, output: &mut [u8]) {
        let mut written = 0;
        let mut remaining = output.len();

        while remaining > 0 {
            // How many bytes available in current squeeze block
            let available = RATE - self.squeeze_offset;

            if available == 0 {
                // Need to permute for more output
                keccak_f(&mut self.state);
                self.squeeze_offset = 0;
                continue;
            }

            let to_copy = core::cmp::min(available, remaining);

            // Extract bytes from state (little-endian)
            for i in 0..to_copy {
                let byte_pos = self.squeeze_offset + i;
                let word_idx = byte_pos / 8;
                let byte_idx = byte_pos % 8;
                output[written + i] = ((self.state[word_idx] >> (byte_idx * 8)) & 0xFF) as u8;
            }

            self.squeeze_offset += to_copy;
            written += to_copy;
            remaining -= to_copy;
        }
    }
}

/// One-shot SHAKE-256 producing `output_len` bytes of output
pub fn shake256(input: &[u8], output_len: usize) -> Vec<u8> {
    Shake256::hash(input, output_len)
}

/// Expand a seed into a SHAKE-256 XOF reader for deterministic pseudorandom output.
///
/// Used by Falcon-512 and other PQC algorithms for seed expansion.
pub fn expand_seed(seed: &[u8]) -> Shake256Reader {
    let mut hasher = Shake256::new();
    hasher.update(seed).expect("fresh hasher cannot be finalized");
    hasher.finalize_xof()
}

/// Domain-separated SHAKE-256 hash.
///
/// Absorbs the domain separator followed by the message, then squeezes `output_len` bytes.
pub fn hash_with_domain(domain: &[u8], message: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::new();
    hasher.update(domain).expect("fresh hasher cannot be finalized");
    hasher.update(message).expect("hasher cannot be finalized after one update");
    hasher.finalize(output_len)
}

/// SHAKE-256 based key derivation.
///
/// Absorbs `password || salt || info` (when provided) and squeezes `length` bytes.
/// Not a substitute for a proper KDF like HKDF — intended for internal seed-derived keying.
pub fn derive_key(password: &[u8], salt: &[u8], length: usize, info: Option<&[u8]>) -> Vec<u8> {
    let mut hasher = Shake256::new();
    hasher.update(password).expect("fresh hasher cannot be finalized");
    hasher.update(salt).expect("hasher cannot be finalized");
    if let Some(info_bytes) = info {
        hasher.update(info_bytes).expect("hasher cannot be finalized");
    }
    hasher.finalize(length)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake256_empty() {
        // NIST test vector: SHAKE256("") with 32 bytes output
        let output = Shake256::hash(b"", 32);
        assert_eq!(output.len(), 32);

        // Known answer: SHAKE256("") first 32 bytes
        let expected = hex::decode(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        ).unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn test_shake256_abc() {
        // SHAKE256("abc") first 32 bytes
        let output = Shake256::hash(b"abc", 32);
        let expected = hex::decode(
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        ).unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn test_shake256_xof_streaming() {
        // Verify streaming read produces same output as one-shot
        let mut hasher = Shake256::new();
        hasher.update(b"test seed").unwrap();
        let mut reader = hasher.finalize_xof();

        let first_32 = reader.read(32);
        let next_32 = reader.read(32);

        // First and second blocks should differ
        assert_ne!(first_32, next_32);

        // Same seed produces same output
        let full_64 = Shake256::hash(b"test seed", 64);
        assert_eq!(&full_64[..32], &first_32[..]);
        assert_eq!(&full_64[32..], &next_32[..]);
    }

    #[test]
    fn test_shake256_deterministic() {
        let out1 = Shake256::hash(b"deterministic", 64);
        let out2 = Shake256::hash(b"deterministic", 64);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_shake256_different_inputs() {
        let out1 = Shake256::hash(b"input1", 32);
        let out2 = Shake256::hash(b"input2", 32);
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_shake256_variable_output() {
        let out_16 = Shake256::hash(b"test", 16);
        let out_32 = Shake256::hash(b"test", 32);
        let out_64 = Shake256::hash(b"test", 64);

        assert_eq!(out_16.len(), 16);
        assert_eq!(out_32.len(), 32);
        assert_eq!(out_64.len(), 64);

        // Shorter output should be prefix of longer
        assert_eq!(&out_32[..16], &out_16[..]);
        assert_eq!(&out_64[..32], &out_32[..]);
    }

    #[test]
    fn test_shake256_incremental_update() {
        // One-shot
        let one_shot = Shake256::hash(b"hello world", 32);

        // Incremental
        let mut hasher = Shake256::new();
        hasher.update(b"hello ").unwrap();
        hasher.update(b"world").unwrap();
        let mut reader = hasher.finalize_xof();
        let incremental = reader.read(32);

        assert_eq!(one_shot, incremental);
    }

    #[test]
    fn test_shake256_convenience_fn() {
        let one_shot = Shake256::hash(b"test", 32);
        let via_fn = shake256(b"test", 32);
        assert_eq!(one_shot, via_fn);
    }
}

// ============================================================================
// Bit-oriented input (FIPS 202 §B.2 / NIST ACVP bit-oriented AFT)
// ============================================================================
//
// FIPS 202 defines SHAKE over bit strings of any length; `update` covers
// only whole bytes. NIST's ACVP SHAKE vectors
// (`test-vectors/sha-3/shake256-acvp.json`) are bit-oriented, so the trailing
// partial byte is exposed explicitly.
//
// Partial-byte convention: FIPS 202 Appendix B.1 (`h2b`) — the `bits` valid
// bits occupy the LOW positions of the byte, least-significant first (NIST
// hex notation: the 5-bit message `11001` is `0x13`). Callers holding an
// MSB-first (top-aligned) bit string shift it down by `8 - bits` first.
//
// Padding (`pad10*1` after the `1111` SHAKE suffix): partial bits, suffix
// and the leading pad `1` are packed into a 16-bit value and written low
// byte first. If the leading pad `1` landed on bit 7 of the block's last
// byte, the block is full and the closing `1` (0x80) needs a fresh block;
// otherwise it shares that byte exactly as in the byte-aligned case.
impl Shake256 {
    /// SHAKE suffix `1111` followed by the leading `pad10*1` bit, LSB-first:
    /// `0b11111` = 0x1F — the byte the byte-aligned `finalize_xof` appends.
    const SUFFIX_WITH_PAD: u16 = 0x1F;
    /// Number of bits in `SUFFIX_WITH_PAD` (suffix `1111` + pad `1`).
    const SUFFIX_WITH_PAD_BITS: usize = 5;

    /// Finalize the absorb phase with a trailing partial byte holding `bits`
    /// (0..=7) message bits in its low positions (FIPS 202 `h2b` order) and
    /// return the XOF reader. `bits == 0` is identical to
    /// [`finalize_xof`](Self::finalize_xof).
    ///
    /// # Panics
    /// If `bits >= 8` or the hasher was already finalized.
    pub fn finalize_xof_bits(mut self, partial: u8, bits: usize) -> Shake256Reader {
        assert!(bits < 8, "partial byte holds at most 7 bits, got {bits}");
        assert!(!self.finalized, "cannot finalize_xof_bits an already finalized hasher");
        self.absorb_partial_and_pad(partial, bits);
        self.finalize_xof()
    }

    /// One-shot XOF over the first `bit_len` bits of `data`, producing
    /// `output_len` bytes. Whole bytes are consumed in order; a trailing
    /// partial byte is interpreted per
    /// [`finalize_xof_bits`](Self::finalize_xof_bits).
    ///
    /// # Panics
    /// If `data` holds fewer than `bit_len` bits.
    pub fn hash_bits(data: &[u8], bit_len: usize, output_len: usize) -> Vec<u8> {
        assert!(
            bit_len <= data.len() * 8,
            "bit_len {bit_len} exceeds the {} bits supplied",
            data.len() * 8
        );
        let full = bit_len / 8;
        let rem = bit_len % 8;
        let mut hasher = Self::new();
        hasher.update(&data[..full]).expect("fresh hasher cannot be finalized");
        let partial = if rem > 0 { data[full] } else { 0 };
        hasher.finalize_xof_bits(partial, rem).read(output_len)
    }

    fn absorb_partial_and_pad(&mut self, partial: u8, bits: usize) {
        let mask: u16 = (1u16 << bits) - 1;
        let v: u16 = ((partial as u16) & mask) | (Self::SUFFIX_WITH_PAD << bits);
        // Bits consumed by partial ‖ suffix ‖ leading pad-1.
        let nb = bits + Self::SUFFIX_WITH_PAD_BITS;

        self.buffer[self.buffer_len] = (v & 0xFF) as u8;
        self.buffer_len += 1;
        if nb > 8 {
            if self.buffer_len == RATE {
                self.absorb_block();
                self.buffer_len = 0;
            }
            self.buffer[self.buffer_len] = (v >> 8) as u8;
            self.buffer_len += 1;
        }
        // The leading pad-1 sits on bit 7 of the last written byte iff
        // nb % 8 == 0; if that byte also closed the block, the closing 1
        // must open a new block.
        if self.buffer_len == RATE && nb % 8 == 0 {
            self.absorb_block();
            self.buffer_len = 0;
        }
        while self.buffer_len < RATE {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }
        self.buffer[RATE - 1] |= 0x80;
        self.absorb_block();
        self.finalized = true;
    }
}
