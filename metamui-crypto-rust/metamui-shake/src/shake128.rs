//! MetaMUI SHAKE-128 Implementation
//!
//! SHAKE-128 extendable-output function (XOF) based on Keccak sponge construction.
//! FIPS 202 compliant. Rate = 168 bytes (capacity = 256 bits).
//!
//! Re-exported from [`metamui_shake::shake128`].

use alloc::{vec, vec::Vec};

// ============================================================================
// Keccak-f[1600] Permutation
// ============================================================================

use crate::keccak::keccak_f1600 as keccak_f;

// ============================================================================
// SHAKE-128 Sponge
// ============================================================================

/// SHAKE-128 rate: 1344 bits = 168 bytes (capacity = 256 bits)
pub const RATE: usize = 168;

/// SHAKE-128 capacity in bytes
pub const CAPACITY: usize = 32;

/// SHAKE-128 extendable-output function
#[derive(Clone)]
pub struct Shake128 {
    state: [u64; 25],
    buffer: [u8; RATE],
    buffer_len: usize,
    finalized: bool,
}

impl Shake128 {
    /// Create a new SHAKE-128 instance
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; RATE],
            buffer_len: 0,
            finalized: false,
        }
    }

    /// Absorb data into the sponge
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        if self.finalized {
            panic!("Cannot update after finalization");
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

        self
    }

    /// Finalize the absorb phase and return an XOF reader
    pub fn finalize_xof(mut self) -> Shake128Reader {
        if !self.finalized {
            // SHAKE domain separator: 0x1F
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

        Shake128Reader {
            state: self.state,
            output_buffer: [0u8; RATE],
            output_pos: 0,
            buffer_filled: false,
        }
    }

    /// Convenience method to get fixed-length output
    pub fn digest(self, output_len: usize) -> Vec<u8> {
        self.finalize_xof().read(output_len)
    }

    /// One-shot hash producing output of specified length
    pub fn hash(input: &[u8], output_len: usize) -> Vec<u8> {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.digest(output_len)
    }

    /// Reset the hasher to initial state
    pub fn reset(&mut self) -> &mut Self {
        self.state = [0u64; 25];
        self.buffer = [0u8; RATE];
        self.buffer_len = 0;
        self.finalized = false;
        self
    }

    /// XOR the rate portion of the buffer into the state and permute
    fn absorb_block(&mut self) {
        let rate_words = RATE / 8; // 21 words for SHAKE-128
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

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SHAKE-128 XOF Reader (Squeeze Phase)
// ============================================================================

/// Reader for SHAKE-128 extendable output
pub struct Shake128Reader {
    state: [u64; 25],
    output_buffer: [u8; RATE],
    output_pos: usize,
    buffer_filled: bool,
}

impl Shake128Reader {
    /// Read `len` bytes of output from the XOF
    pub fn read(&mut self, len: usize) -> Vec<u8> {
        let mut output = vec![0u8; len];
        self.read_into(&mut output);
        output
    }

    /// Read bytes directly into the provided buffer
    pub fn read_into(&mut self, output: &mut [u8]) {
        let mut offset = 0;
        let length = output.len();

        while offset < length {
            if !self.buffer_filled || self.output_pos >= RATE {
                self.squeeze();
                self.output_pos = 0;
                self.buffer_filled = true;
            }

            let copy_len = core::cmp::min(RATE - self.output_pos, length - offset);
            output[offset..offset + copy_len]
                .copy_from_slice(&self.output_buffer[self.output_pos..self.output_pos + copy_len]);

            self.output_pos += copy_len;
            offset += copy_len;
        }
    }

    /// Squeeze a block from the Keccak state
    fn squeeze(&mut self) {
        // Extract bytes from state (little-endian)
        for i in 0..RATE / 8 {
            let word = self.state[i];
            for j in 0..8 {
                let idx = i * 8 + j;
                if idx < RATE {
                    self.output_buffer[idx] = ((word >> (j * 8)) & 0xFF) as u8;
                }
            }
        }

        // Apply Keccak-f for next squeeze
        keccak_f(&mut self.state);
    }
}

/// One-shot SHAKE-128 producing `output_len` bytes of output
pub fn shake128(input: &[u8], output_len: usize) -> Vec<u8> {
    Shake128::hash(input, output_len)
}

// XOF module for compatibility
pub mod xof {
    use super::*;

    pub use super::Shake128Reader as XofReader;

    pub fn shake128_xof(input: &[u8]) -> Shake128Reader {
        let mut hasher = Shake128::new();
        hasher.update(input);
        hasher.finalize_xof()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_shake128_empty() {
        // FIPS 202 test vector: SHAKE128("") first 16 bytes
        let output = shake128(b"", 16);
        assert_eq!(hex_encode(&output), "7f9c2ba4e88f827d616045507605853e");
    }

    #[test]
    fn test_shake128_abc() {
        // FIPS 202 test vector: SHAKE128("abc") first 16 bytes
        let output = shake128(b"abc", 16);
        assert_eq!(hex_encode(&output), "5881092dd818bf5cf8a3ddb793fbcba7");
    }

    #[test]
    fn test_shake128_streaming() {
        let mut hasher = Shake128::new();
        hasher.update(b"a");
        hasher.update(b"b");
        hasher.update(b"c");
        let output = hasher.digest(16);
        assert_eq!(hex_encode(&output), "5881092dd818bf5cf8a3ddb793fbcba7");
    }

    #[test]
    fn test_shake128_xof() {
        let hasher = Shake128::new();
        let mut reader = hasher.finalize_xof();

        let part1 = reader.read(8);
        let part2 = reader.read(8);

        let full = shake128(b"", 16);

        assert_eq!(&[&part1[..], &part2[..]].concat(), &full);
    }

    #[test]
    fn test_shake128_long_output() {
        let output = shake128(b"", 32);
        assert_eq!(
            hex_encode(&output),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
    }

    #[test]
    fn test_shake128_edge_cases() {
        // 167 zeros - exactly fills block after adding domain separator
        let zeros_167 = vec![0u8; 167];
        let output = shake128(&zeros_167, 32);
        assert_eq!(
            hex_encode(&output),
            "959c3093774a513e807a36f3b23e508c10a5d78cc387266b5676ccbfbacc244f"
        );

        // 168 zeros - one complete block
        let zeros_168 = vec![0u8; 168];
        let output = shake128(&zeros_168, 32);
        assert_eq!(
            hex_encode(&output),
            "7c00ff4748870cb26da4dc078aff74477ab153fa1191c7b636fea6c01ecc1fab"
        );

        // 169 zeros - one block plus one byte
        let zeros_169 = vec![0u8; 169];
        let output = shake128(&zeros_169, 32);
        assert_eq!(
            hex_encode(&output),
            "7dbf2395341028d86a561234f3fd598159b9307e5fabedfaeb9caab25d3bcc9a"
        );
    }

    #[test]
    fn test_shake128_deterministic() {
        let out1 = shake128(b"deterministic", 64);
        let out2 = shake128(b"deterministic", 64);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_shake128_different_inputs() {
        let out1 = shake128(b"input1", 32);
        let out2 = shake128(b"input2", 32);
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_shake128_variable_output() {
        let out_16 = shake128(b"test", 16);
        let out_32 = shake128(b"test", 32);
        let out_64 = shake128(b"test", 64);

        assert_eq!(out_16.len(), 16);
        assert_eq!(out_32.len(), 32);
        assert_eq!(out_64.len(), 64);

        // Shorter output should be prefix of longer
        assert_eq!(&out_32[..16], &out_16[..]);
        assert_eq!(&out_64[..32], &out_32[..]);
    }
}

// ============================================================================
// Bit-oriented input (FIPS 202 §B.2 / NIST ACVP bit-oriented AFT)
// ============================================================================
//
// FIPS 202 defines SHAKE over bit strings of any length; `update` covers
// only whole bytes. NIST's ACVP SHAKE vectors
// (`test-vectors/sha-3/shake128-acvp.json`) are bit-oriented, so the trailing
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
impl Shake128 {
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
    pub fn finalize_xof_bits(mut self, partial: u8, bits: usize) -> Shake128Reader {
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
        hasher.update(&data[..full]);
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
