// MetaMUI SHA-384 Implementation (FIPS 180-4)
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>

//! SHA-384 cryptographic hash function (FIPS 180-4) with HMAC-SHA-384 (RFC 2104).
//!
//! SHA-384 is identical to SHA-512 except for different initial hash values
//! (FIPS 180-4 Section 5.3.4) and output truncated to 48 bytes (384 bits).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use core::fmt;

// ---------------------------------------------------------------------------
// SHA-384 round constants (FIPS 180-4 Section 4.2.3)
// Identical to SHA-512: first 80 primes, cube root fractional parts as 64-bit words
// ---------------------------------------------------------------------------
const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

// ---------------------------------------------------------------------------
// Initial hash values (FIPS 180-4 Section 5.3.4)
// These are the first 64 bits of the fractional parts of the square roots
// of the 9th through 16th primes (23, 29, 31, 37, 41, 43, 47, 53).
// ---------------------------------------------------------------------------
const H0: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
    0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];

/// SHA-384 output size in bytes.
pub const SHA384_OUTPUT_SIZE: usize = 48;

/// SHA-384 block size in bytes (same as SHA-512).
pub const SHA384_BLOCK_SIZE: usize = 128;

// ---------------------------------------------------------------------------
// SHA-384 Error
// ---------------------------------------------------------------------------

/// Errors that can occur during SHA-384 hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sha384Error {
    /// The input data could not be processed.
    InvalidInput(&'static str),
    /// An internal error occurred during hashing.
    InternalError(&'static str),
}

impl fmt::Display for Sha384Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Sha384Error::InvalidInput(msg) => write!(f, "SHA-384 invalid input: {}", msg),
            Sha384Error::InternalError(msg) => write!(f, "SHA-384 internal error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Sha384Error {}

// ---------------------------------------------------------------------------
// Internal streaming state
// ---------------------------------------------------------------------------

/// Internal SHA-384 state for incremental (streaming) hashing.
///
/// SHA-384 uses the same compression function and block size as SHA-512,
/// but with different initial hash values and a truncated output.
pub(crate) struct Sha384State {
    /// Working hash values H0..H7
    state: [u64; 8],
    /// Partial-block buffer (128 bytes = one SHA-384/512 block)
    buffer: [u8; 128],
    /// How many bytes are currently buffered
    buffer_len: usize,
    /// Total number of message bytes ingested (for padding)
    total_len: u128,
}

impl Sha384State {
    /// Create a fresh state with the FIPS 180-4 Section 5.3.4 initial hash values.
    pub(crate) fn new() -> Self {
        Self {
            state: H0,
            buffer: [0u8; 128],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Feed more data into the hash.
    pub(crate) fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u128;

        // If there is buffered data, try to fill the buffer to a full block.
        if self.buffer_len > 0 {
            let space = 128 - self.buffer_len;
            let to_copy = if data.len() < space { data.len() } else { space };
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == 128 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }

        // Process as many full 128-byte blocks as possible directly from `data`.
        while offset + 128 <= data.len() {
            // SAFETY: the slice is exactly 128 bytes
            let block: [u8; 128] = data[offset..offset + 128].try_into().unwrap();
            self.compress(&block);
            offset += 128;
        }

        // Buffer the remaining bytes (< 128).
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize: apply FIPS 180-4 padding and return the 48-byte digest.
    ///
    /// SHA-384 output is the first 6 words (48 bytes) of the final state,
    /// unlike SHA-512 which returns all 8 words (64 bytes).
    pub(crate) fn finalize(mut self) -> [u8; 48] {
        let msg_len_bits: u128 = self.total_len * 8;

        // Append the 0x80 byte.
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If there is not enough room for the 16-byte length field,
        // pad this block with zeros, compress, and start a new block.
        if self.buffer_len > 112 {
            // Fill the rest of this block with zeros.
            for i in self.buffer_len..128 {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffer_len = 0;
            self.buffer = [0u8; 128];
        }

        // Pad with zeros up to byte 112.
        for i in self.buffer_len..112 {
            self.buffer[i] = 0;
        }

        // Append 128-bit big-endian message length.
        self.buffer[112..128].copy_from_slice(&msg_len_bits.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);

        // Produce the final digest from the first 6 state words (48 bytes).
        let mut digest = [0u8; 48];
        for i in 0..6 {
            digest[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_be_bytes());
        }
        digest
    }

    /// SHA-384/512 block compression function (80 rounds).
    ///
    /// This is identical to the SHA-512 compression function.
    #[inline]
    fn compress(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];

        // Prepare the message schedule (first 16 words from the block).
        for i in 0..16 {
            w[i] = u64::from_be_bytes(
                block[i * 8..(i + 1) * 8].try_into().unwrap(),
            );
        }

        // Extend the message schedule (words 16..79).
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1)
                ^ w[i - 15].rotate_right(8)
                ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19)
                ^ w[i - 2].rotate_right(61)
                ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables.
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // 80 rounds of compression.
        for i in 0..80 {
            let big_sigma1 = e.rotate_right(14)
                ^ e.rotate_right(18)
                ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(big_sigma1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let big_sigma0 = a.rotate_right(28)
                ^ a.rotate_right(34)
                ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = big_sigma0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add the compressed chunk to the current hash value.
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

// ---------------------------------------------------------------------------
// Public convenience function
// ---------------------------------------------------------------------------

/// Compute the SHA-384 digest of `data`, returning a 48-byte array.
///
/// This is a one-shot convenience wrapper. It never fails.
///
/// ```
/// use metamui_sha2::sha384;
///
/// let digest = sha384(b"abc");
/// assert_eq!(digest.len(), 48);
/// ```
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut state = Sha384State::new();
    state.update(data);
    state.finalize()
}

// ---------------------------------------------------------------------------
// Public struct wrapper
// ---------------------------------------------------------------------------

/// Reusable SHA-384 hasher.
///
/// ```
/// use metamui_sha2::MetaMUISha384;
///
/// let hasher = MetaMUISha384::new();
/// let digest = hasher.hash(b"abc").unwrap();
/// assert_eq!(digest.len(), 48);
/// ```
pub struct MetaMUISha384;

impl MetaMUISha384 {
    /// Create a new `MetaMUISha384` instance.
    pub fn new() -> Self {
        Self
    }

    /// Hash `data` and return the 48-byte SHA-384 digest.
    pub fn hash(&self, data: &[u8]) -> Result<[u8; 48], Sha384Error> {
        Ok(sha384(data))
    }

    /// Return the algorithm name.
    pub fn algorithm_name(&self) -> &'static str {
        "SHA-384"
    }

    /// Return the output size in bytes.
    pub fn output_size(&self) -> usize {
        SHA384_OUTPUT_SIZE
    }

    /// Return the block size in bytes.
    pub fn block_size(&self) -> usize {
        SHA384_BLOCK_SIZE
    }
}

impl Default for MetaMUISha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MetaMUISha384 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MetaMUISha384(output_size={})", self.output_size())
    }
}

impl fmt::Debug for MetaMUISha384 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetaMUISha384")
            .field("algorithm", &self.algorithm_name())
            .field("output_size", &self.output_size())
            .field("block_size", &self.block_size())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// HMAC-SHA-384 submodule (RFC 2104 / RFC 4231)
// ---------------------------------------------------------------------------

/// HMAC-SHA-384 implementation per RFC 2104.
pub mod hmac {
    use super::*;

    /// Block size for SHA-384 in bytes (same as SHA-512).
    const BLOCK_SIZE: usize = 128;

    // -----------------------------------------------------------------------
    // HMAC Error
    // -----------------------------------------------------------------------

    /// Errors that can occur during HMAC-SHA-384 operations.
    #[derive(Debug, Clone)]
    pub enum HmacError {
        /// The provided key was invalid.
        InvalidKeyLength(Vec<u8>),
    }

    impl fmt::Display for HmacError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                HmacError::InvalidKeyLength(_) => {
                    write!(f, "HMAC-SHA-384 invalid key")
                }
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for HmacError {}

    // -----------------------------------------------------------------------
    // HMAC Output
    // -----------------------------------------------------------------------

    /// The output of an HMAC-SHA-384 computation (48 bytes).
    pub struct HmacOutput {
        bytes: Vec<u8>,
    }

    impl HmacOutput {
        /// Consume `self` and return the raw bytes as a `Vec<u8>`.
        pub fn into_bytes(self) -> Vec<u8> {
            self.bytes
        }
    }

    impl AsRef<[u8]> for HmacOutput {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    // -----------------------------------------------------------------------
    // HmacSha384
    // -----------------------------------------------------------------------

    /// Streaming HMAC-SHA-384 computation.
    ///
    /// Usage:
    /// ```
    /// use metamui_sha2::sha384::hmac::HmacSha384;
    ///
    /// let mut mac = HmacSha384::new_from_slice(b"secret key").unwrap();
    /// mac.update(b"message part 1");
    /// mac.update(b"message part 2");
    /// let result = mac.finalize();
    /// let bytes = result.into_bytes();
    /// assert_eq!(bytes.len(), 48);
    /// ```
    pub struct HmacSha384 {
        /// The SHA-384 state that has already ingested `(key XOR ipad)`.
        inner_state: Sha384State,
        /// The pre-computed `(key XOR opad)` block -- needed at finalization.
        outer_key_pad: [u8; BLOCK_SIZE],
    }

    impl HmacSha384 {
        /// Create a new HMAC-SHA-384 instance from a key of arbitrary length.
        ///
        /// Per RFC 2104:
        /// - If `key.len() > BLOCK_SIZE`, the key is first hashed with SHA-384
        ///   (producing 48 bytes), then zero-padded to `BLOCK_SIZE`.
        /// - Otherwise the key is zero-padded to `BLOCK_SIZE` bytes.
        pub fn new_from_slice(key: &[u8]) -> Result<Self, HmacError> {
            // Derive the block-sized key.
            let mut key_block = [0u8; BLOCK_SIZE];
            if key.len() > BLOCK_SIZE {
                let hashed = sha384(key);
                key_block[..48].copy_from_slice(&hashed);
            } else {
                key_block[..key.len()].copy_from_slice(key);
            }

            // Compute inner and outer padded keys.
            let mut inner_key_pad = [0u8; BLOCK_SIZE];
            let mut outer_key_pad = [0u8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                inner_key_pad[i] = key_block[i] ^ 0x36;
                outer_key_pad[i] = key_block[i] ^ 0x5c;
            }

            // Clear the raw key material from the stack buffer.
            for b in key_block.iter_mut() {
                *b = 0;
            }

            // Start the inner hash with the inner padded key.
            let mut inner_state = Sha384State::new();
            inner_state.update(&inner_key_pad);

            // Clear the inner pad from the stack.
            for b in inner_key_pad.iter_mut() {
                *b = 0;
            }

            Ok(Self {
                inner_state,
                outer_key_pad,
            })
        }

        /// Feed more message data into the HMAC.
        pub fn update(&mut self, data: &[u8]) {
            self.inner_state.update(data);
        }

        /// Finalize the HMAC and return the 48-byte tag.
        ///
        /// This consumes `self` -- no further updates are possible.
        pub fn finalize(mut self) -> HmacOutput {
            // inner_hash = SHA-384( (key XOR ipad) || message )
            let inner_hash = self.inner_state.finalize();

            // outer_hash = SHA-384( (key XOR opad) || inner_hash )
            let mut outer_state = Sha384State::new();
            outer_state.update(&self.outer_key_pad);
            outer_state.update(&inner_hash);
            let result = outer_state.finalize();

            // Clear the outer key pad.
            for b in self.outer_key_pad.iter_mut() {
                *b = 0;
            }

            HmacOutput {
                bytes: result.to_vec(),
            }
        }
    }

    /// Convenience function: compute HMAC-SHA-384 in one shot.
    pub fn hmac_sha384(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha384::new_from_slice(key).unwrap();
        mac.update(message);
        mac.finalize().into_bytes()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SHA-384 test vectors (FIPS 180-4 / NIST)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha384_abc() {
        // NIST FIPS 180-4 example: SHA-384("abc")
        let expected = hex::decode(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7",
        )
        .unwrap();

        let digest = sha384(b"abc");
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha384_empty() {
        // SHA-384("")
        let expected = hex::decode(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b",
        )
        .unwrap();

        let digest = sha384(b"");
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha384_448_bits() {
        // SHA-384("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        let expected = hex::decode(
            "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6\
             b0455a8520bc4e6f5fe95b1fe3c8452b",
        )
        .unwrap();

        let digest = sha384(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha384_896_bits() {
        // SHA-384("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn
        //          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
        let expected = hex::decode(
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
             fcc7c71a557e2db966c3e9fa91746039",
        )
        .unwrap();

        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let digest = sha384(input);
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha384_one_million_a() {
        // SHA-384 of one million 'a' characters
        let expected = hex::decode(
            "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b\
             07b8b3dc38ecc4ebae97ddd87f3d8985",
        )
        .unwrap();

        // Feed in chunks to exercise the streaming path.
        let mut state = Sha384State::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            state.update(&chunk);
        }
        let digest = state.finalize();
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    // -----------------------------------------------------------------------
    // Struct API tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha384_struct_api() {
        let hasher = MetaMUISha384::new();
        let digest = hasher.hash(b"abc").unwrap();

        let expected = hex::decode(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7",
        )
        .unwrap();

        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha384_default_trait() {
        let hasher = MetaMUISha384::default();
        let digest = hasher.hash(b"abc").unwrap();
        assert_eq!(digest.len(), 48);
    }

    // -----------------------------------------------------------------------
    // Streaming equivalence test
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha384_streaming_equivalence() {
        let data = b"The quick brown fox jumps over the lazy dog";

        // One-shot
        let one_shot = sha384(data);

        // Streaming: byte-by-byte
        let mut state = Sha384State::new();
        for &byte in data.iter() {
            state.update(&[byte]);
        }
        let streaming = state.finalize();

        assert_eq!(one_shot, streaming);
    }

    // -----------------------------------------------------------------------
    // Boundary tests (SHA-384 uses 128-byte blocks, length field is 16 bytes)
    // Boundary at 112 bytes: 128 - 16 = 112
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha384_boundary_111_bytes() {
        // 111 bytes: after appending 0x80 we have 112 bytes, which exactly fits
        // the length field in the same block.
        let data = [0x63u8; 111];
        let d1 = sha384(&data);
        assert_eq!(d1.len(), 48);
        // Verify determinism
        assert_eq!(d1, sha384(&data));
    }

    #[test]
    fn test_sha384_boundary_112_bytes() {
        // 112 bytes: after appending 0x80 we have 113 bytes, which exceeds
        // the 112-byte threshold and requires a second block for the length.
        let data = [0x63u8; 112];
        let d2 = sha384(&data);
        assert_eq!(d2.len(), 48);

        // Different from 111 bytes
        let data_111 = [0x63u8; 111];
        let d1 = sha384(&data_111);
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_sha384_exactly_one_block() {
        // 128 bytes -- exactly one SHA-384 block
        let data = [0x61u8; 128];
        let digest = sha384(&data);
        assert_eq!(digest.len(), 48);
        // Verify determinism
        assert_eq!(digest, sha384(&data));
    }

    #[test]
    fn test_sha384_just_over_one_block() {
        // 129 bytes -- just over one block
        let data = [0x62u8; 129];
        let digest = sha384(&data);
        assert_eq!(digest.len(), 48);
    }

    // -----------------------------------------------------------------------
    // Error display test
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha384_error_display() {
        let err = Sha384Error::InvalidInput("test error");
        assert_eq!(format!("{}", err), "SHA-384 invalid input: test error");

        let err = Sha384Error::InternalError("internal issue");
        assert_eq!(format!("{}", err), "SHA-384 internal error: internal issue");
    }

    // -----------------------------------------------------------------------
    // HMAC-SHA-384 test vectors (RFC 4231)
    // -----------------------------------------------------------------------

    #[test]
    fn test_hmac_sha384_rfc4231_case1() {
        // Test Case 1
        // Key  = 0x0b repeated 20 times
        // Data = "Hi There"
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";

        let expected = hex::decode(
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
             faea9ea9076ede7f4af152e8b2fa9cb6",
        )
        .unwrap();

        let mut mac = hmac::HmacSha384::new_from_slice(&key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        assert_eq!(result.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha384_rfc4231_case2() {
        // Test Case 2
        // Key  = "Jefe"
        // Data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";

        let expected = hex::decode(
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649",
        )
        .unwrap();

        let mut mac = hmac::HmacSha384::new_from_slice(key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        assert_eq!(result.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha384_rfc4231_case3() {
        // Test Case 3
        // Key  = 0xaa repeated 20 times
        // Data = 0xdd repeated 50 times
        let key = vec![0xaau8; 20];
        let data = vec![0xddu8; 50];

        let expected = hex::decode(
            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b\
             2a5ab39dc13814b94e3ab6e101a34f27",
        )
        .unwrap();

        let mut mac = hmac::HmacSha384::new_from_slice(&key).unwrap();
        mac.update(&data);
        let result = mac.finalize();
        assert_eq!(result.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha384_rfc4231_case4() {
        // Test Case 4
        // Key  = 0x01 0x02 .. 0x19 (25 bytes)
        // Data = 0xcd repeated 50 times
        let key: Vec<u8> = (0x01..=0x19).collect();
        let data = vec![0xcdu8; 50];

        let expected = hex::decode(
            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e\
             6801dd23c4a7d679ccf8a386c674cffb",
        )
        .unwrap();

        let mut mac = hmac::HmacSha384::new_from_slice(&key).unwrap();
        mac.update(&data);
        let result = mac.finalize();
        assert_eq!(result.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha384_rfc4231_case6() {
        // Test Case 6
        // Key  = 0xaa repeated 131 times (key > block_size, so it gets hashed)
        // Data = "Test Using Larger Than Block-Size Key - Hash Key First"
        let key = vec![0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";

        let expected = hex::decode(
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6\
             0c2ef6ab4030fe8296248df163f44952",
        )
        .unwrap();

        let mut mac = hmac::HmacSha384::new_from_slice(&key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        assert_eq!(result.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha384_rfc4231_case7() {
        // Test Case 7
        // Key  = 0xaa repeated 131 times
        // Data = "This is a test using a larger than block-size key and a
        //         larger than block-size data. ..."
        let key = vec![0xaau8; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

        let expected = hex::decode(
            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5\
             a678cc31e799176d3860e6110c46523e",
        )
        .unwrap();

        let mut mac = hmac::HmacSha384::new_from_slice(&key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        assert_eq!(result.as_ref(), expected.as_slice());
    }

    // -----------------------------------------------------------------------
    // HMAC-SHA-384 streaming test
    // -----------------------------------------------------------------------

    #[test]
    fn test_hmac_sha384_streaming() {
        // Verify streaming update produces the same result as single-shot.
        let key = b"streaming test key";
        let data = b"Hello, World! This is a streaming test.";

        // Single-shot
        let mut mac1 = hmac::HmacSha384::new_from_slice(key).unwrap();
        mac1.update(data);
        let result1 = mac1.finalize().into_bytes();

        // Streaming byte-by-byte
        let mut mac2 = hmac::HmacSha384::new_from_slice(key).unwrap();
        for &b in data.iter() {
            mac2.update(&[b]);
        }
        let result2 = mac2.finalize().into_bytes();

        assert_eq!(result1, result2);
    }

    // -----------------------------------------------------------------------
    // HMAC-SHA-384 convenience function test
    // -----------------------------------------------------------------------

    #[test]
    fn test_hmac_sha384_convenience_fn() {
        // Use RFC 4231 Case 1 to verify the convenience function.
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let expected = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6";
        let result = hmac::hmac_sha384(&key, data);
        assert_eq!(hex::encode(&result), expected);
    }

    // -----------------------------------------------------------------------
    // Consistency tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha384_deterministic() {
        let data = b"deterministic test input 12345";
        let d1 = sha384(data);
        let d2 = sha384(data);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_sha384_different_inputs_different_outputs() {
        let d1 = sha384(b"input one");
        let d2 = sha384(b"input two");
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_sha384_convenience_no_result() {
        // Verify the convenience function returns a plain array, not Result.
        let digest: [u8; 48] = sha384(b"test");
        assert_eq!(digest.len(), 48);
    }

    #[test]
    fn test_hmac_sha384_empty_data() {
        let key = b"key";
        let mut mac = hmac::HmacSha384::new_from_slice(key).unwrap();
        mac.update(b"");
        let result = mac.finalize();
        assert_eq!(result.as_ref().len(), 48);
    }

    #[test]
    fn test_hmac_sha384_empty_key() {
        // Empty key is valid for HMAC (zero-padded to block size).
        let mut mac = hmac::HmacSha384::new_from_slice(b"").unwrap();
        mac.update(b"test");
        let result = mac.finalize();
        assert_eq!(result.as_ref().len(), 48);
    }

    #[test]
    fn test_hmac_sha384_into_bytes_to_vec() {
        let key = b"key";
        let mut mac = hmac::HmacSha384::new_from_slice(key).unwrap();
        mac.update(b"data");
        let output = mac.finalize();

        // Test AsRef
        let _slice: &[u8] = output.as_ref();
        assert_eq!(_slice.len(), 48);

        // Test to_vec via AsRef (consumer pattern from hkdf.rs)
        let vec = output.into_bytes().to_vec();
        assert_eq!(vec.len(), 48);
    }

    #[test]
    fn test_hmac_error_display() {
        let err = hmac::HmacError::InvalidKeyLength(vec![]);
        let msg = format!("{}", err);
        assert!(msg.contains("HMAC-SHA-384"));
    }
}
