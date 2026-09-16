//! MetaMUI SHA-512 — Pure Rust implementation of SHA-512 (FIPS 180-4)
//! and HMAC-SHA-512 (RFC 2104 / RFC 4231).
//!
//! This module provides:
//! - [`sha512`] convenience function returning `[u8; 64]`
//! - [`MetaMUISha512`] struct with fallible `hash()` method
//! - [`hmac`] submodule with [`hmac::HmacSha512`] for HMAC-SHA-512
//!
//! No external cryptographic dependencies.
//!
//! Re-exported from [`metamui_sha2::sha512`].

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::string::String;

use core::fmt;

// ---------------------------------------------------------------------------
// SHA-512 round constants (FIPS 180-4 Section 4.2.3)
// First 80 primes, cube root fractional parts as 64-bit words
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
// Initial hash values (FIPS 180-4 Section 5.3.5)
// First 8 primes, square root fractional parts as 64-bit words
// ---------------------------------------------------------------------------
const H0: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

// ---------------------------------------------------------------------------
// SHA-512 Error
// ---------------------------------------------------------------------------

/// Errors that can occur during SHA-512 hashing.
#[derive(Debug, Clone)]
pub enum Sha512Error {
    /// The input data could not be processed.
    HashingFailed(String),
}

impl fmt::Display for Sha512Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Sha512Error::HashingFailed(msg) => write!(f, "SHA-512 hashing failed: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Sha512Error {}

// ---------------------------------------------------------------------------
// Internal streaming state
// ---------------------------------------------------------------------------

/// SHA-512 streaming hasher for incremental (multi-step) hashing.
///
/// ```
/// use metamui_sha2::sha512::Sha512Hasher;
///
/// let mut hasher = Sha512Hasher::new();
/// hasher.update(b"hello ");
/// hasher.update(b"world");
/// let digest = hasher.finalize();
/// assert_eq!(digest.len(), 64);
/// ```
pub struct Sha512Hasher {
    /// Working hash values H0..H7
    state: [u64; 8],
    /// Partial-block buffer (128 bytes = one SHA-512 block)
    buffer: [u8; 128],
    /// How many bytes are currently buffered
    buffer_len: usize,
    /// Total number of message bytes ingested (for padding)
    total_len: u128,
}

impl Sha512Hasher {
    /// Create a fresh state with the FIPS 180-4 initial hash values.
    pub fn new() -> Self {
        Self::with_initial_state(H0)
    }

    /// Create a state under a caller-supplied initial hash value. SHA-512/224
    /// and SHA-512/256 are this compression function under the §5.3.6
    /// constants with the output truncated (see `sha512t.rs`).
    pub(crate) fn with_initial_state(state: [u64; 8]) -> Self {
        Self {
            state,
            buffer: [0u8; 128],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Feed more data into the hash.
    pub fn update(&mut self, data: &[u8]) {
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

    /// Finalize: apply FIPS 180-4 padding and return the 64-byte digest.
    pub fn finalize(mut self) -> [u8; 64] {
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

        // Produce the final digest from state words.
        let mut digest = [0u8; 64];
        for (i, &word) in self.state.iter().enumerate() {
            digest[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// SHA-512 block compression function (80 rounds).
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

/// Compute the SHA-512 digest of `data`, returning a 64-byte array.
///
/// This is a one-shot convenience wrapper. It never fails.
///
/// ```
/// let digest = metamui_sha2::sha512::sha512(b"abc");
/// assert_eq!(digest.len(), 64);
/// ```
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut state = Sha512Hasher::new();
    state.update(data);
    state.finalize()
}

// ---------------------------------------------------------------------------
// Public struct wrapper
// ---------------------------------------------------------------------------

/// Reusable SHA-512 hasher.
///
/// ```
/// use metamui_sha2::sha512::MetaMUISha512;
///
/// let hasher = MetaMUISha512::new();
/// let digest = hasher.hash(b"abc").unwrap();
/// assert_eq!(digest.len(), 64);
/// ```
pub struct MetaMUISha512;

impl MetaMUISha512 {
    /// Create a new `MetaMUISha512` instance.
    pub fn new() -> Self {
        Self
    }

    /// Hash `data` and return the 64-byte SHA-512 digest.
    pub fn hash(&self, data: &[u8]) -> Result<[u8; 64], Sha512Error> {
        Ok(sha512(data))
    }

    /// Return the algorithm name.
    pub fn algorithm_name(&self) -> &'static str {
        "SHA-512"
    }

    /// Return the output size in bytes (64 for SHA-512).
    pub fn output_size(&self) -> usize {
        64
    }

    /// Return the block size in bytes (128 for SHA-512).
    pub fn block_size(&self) -> usize {
        128
    }
}

impl Default for MetaMUISha512 {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HMAC-SHA-512 submodule (RFC 2104 / RFC 4231)
// ---------------------------------------------------------------------------

/// HMAC-SHA-512 implementation per RFC 2104.
pub mod hmac {
    use super::*;

    /// Block size for SHA-512 in bytes.
    const BLOCK_SIZE: usize = 128;

    // -----------------------------------------------------------------------
    // HMAC Error
    // -----------------------------------------------------------------------

    /// Errors that can occur during HMAC-SHA-512 operations.
    #[derive(Debug, Clone)]
    pub enum HmacError {
        /// The provided key was invalid (should not happen for HMAC, but
        /// included for API completeness).
        InvalidKeyLength(String),
    }

    impl fmt::Display for HmacError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                HmacError::InvalidKeyLength(msg) => {
                    write!(f, "HMAC-SHA-512 invalid key: {}", msg)
                }
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for HmacError {}

    // -----------------------------------------------------------------------
    // HMAC Output
    // -----------------------------------------------------------------------

    /// The output of an HMAC-SHA-512 computation (64 bytes).
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
    // HmacSha512
    // -----------------------------------------------------------------------

    /// Streaming HMAC-SHA-512 computation.
    ///
    /// Usage:
    /// ```
    /// use metamui_sha2::sha512::hmac::HmacSha512;
    ///
    /// let mut mac = HmacSha512::new_from_slice(b"secret key").unwrap();
    /// mac.update(b"message part 1");
    /// mac.update(b"message part 2");
    /// let result = mac.finalize();
    /// let bytes = result.into_bytes();
    /// assert_eq!(bytes.len(), 64);
    /// ```
    pub struct HmacSha512 {
        /// The SHA-512 state that has already ingested `(key XOR ipad)`.
        inner_state: Sha512Hasher,
        /// The pre-computed `(key XOR opad)` block — needed at finalization.
        outer_key_pad: [u8; BLOCK_SIZE],
    }

    impl HmacSha512 {
        /// Create a new HMAC-SHA-512 instance from a key of arbitrary length.
        ///
        /// Per RFC 2104:
        /// - If `key.len() > BLOCK_SIZE`, the key is first hashed with SHA-512.
        /// - The key is then zero-padded to `BLOCK_SIZE` bytes.
        pub fn new_from_slice(key: &[u8]) -> Result<Self, HmacError> {
            // Derive the block-sized key.
            let mut key_block = [0u8; BLOCK_SIZE];
            if key.len() > BLOCK_SIZE {
                let hashed = sha512(key);
                key_block[..64].copy_from_slice(&hashed);
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
            let mut inner_state = Sha512Hasher::new();
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

        /// Finalize the HMAC and return the 64-byte tag.
        ///
        /// This consumes `self` — no further updates are possible.
        pub fn finalize(mut self) -> HmacOutput {
            // inner_hash = SHA-512( (key XOR ipad) || message )
            let inner_hash = self.inner_state.finalize();

            // outer_hash = SHA-512( (key XOR opad) || inner_hash )
            let mut outer_state = Sha512Hasher::new();
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

    /// Convenience function: compute HMAC-SHA-512 in one shot.
    pub fn hmac_sha512(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha512::new_from_slice(key).unwrap();
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
    // SHA-512 test vectors (FIPS 180-4 / NIST)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha512_abc() {
        // NIST FIPS 180-4 example: SHA-512("abc")
        let expected = hex::decode(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        )
        .unwrap();

        let digest = sha512(b"abc");
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_empty() {
        // SHA-512("")
        let expected = hex::decode(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        )
        .unwrap();

        let digest = sha512(b"");
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_448_bits() {
        // SHA-512("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        let expected = hex::decode(
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335\
             96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
        )
        .unwrap();

        let digest = sha512(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_896_bits() {
        // SHA-512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn
        //          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
        let expected = hex::decode(
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        )
        .unwrap();

        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let digest = sha512(input);
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_one_million_a() {
        // SHA-512 of one million 'a' characters
        let expected = hex::decode(
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
             de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        )
        .unwrap();

        // Feed in chunks to exercise the streaming path.
        let mut state = Sha512Hasher::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            state.update(&chunk);
        }
        let digest = state.finalize();
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_struct_api() {
        let hasher = MetaMUISha512::new();
        let digest = hasher.hash(b"abc").unwrap();

        let expected = hex::decode(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        )
        .unwrap();

        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_default_trait() {
        let hasher = MetaMUISha512::default();
        let digest = hasher.hash(b"abc").unwrap();
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn test_sha512_convenience_no_result() {
        // Verify the convenience function returns a plain array, not Result.
        let digest: [u8; 64] = sha512(b"test");
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn test_sha512_error_display() {
        let err = Sha512Error::HashingFailed("test error".into());
        let msg = format!("{}", err);
        assert!(msg.contains("test error"));
    }

    // -----------------------------------------------------------------------
    // Multi-block / boundary tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha512_exactly_one_block() {
        // 128 bytes — exactly one SHA-512 block
        let data = [0x61u8; 128]; // 128 'a' characters
        let digest = sha512(&data);
        assert_eq!(digest.len(), 64);
        // Verify determinism
        assert_eq!(digest, sha512(&data));
    }

    #[test]
    fn test_sha512_just_over_one_block() {
        let data = [0x62u8; 129]; // 129 bytes
        let digest = sha512(&data);
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn test_sha512_padding_boundary_112() {
        // 112 bytes: padding fits in the same block (112 + 1 + 15 = 128? No,
        // 112 + 1 = 113 > 112, so we need a second block for the length.)
        // Actually: 128 - 16 = 112. If buffer_len == 112 after appending 0x80
        // that means buffer_len was 111 before. Let's test 111 bytes.
        let data = [0x63u8; 111];
        let d1 = sha512(&data);
        assert_eq!(d1.len(), 64);

        // And 112 bytes (needs second block for length).
        let data2 = [0x63u8; 112];
        let d2 = sha512(&data2);
        assert_eq!(d2.len(), 64);
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_sha512_streaming_equivalence() {
        let data = b"The quick brown fox jumps over the lazy dog";

        // One-shot
        let one_shot = sha512(data);

        // Streaming: byte-by-byte
        let mut state = Sha512Hasher::new();
        for &byte in data.iter() {
            state.update(&[byte]);
        }
        let streaming = state.finalize();

        assert_eq!(one_shot, streaming);
    }

    // -----------------------------------------------------------------------
    // HMAC-SHA-512 test vectors (RFC 4231)
    // -----------------------------------------------------------------------

    #[test]
    fn test_hmac_sha512_rfc4231_case1() {
        // Test Case 1
        // Key  = 0x0b repeated 20 times
        // Data = "Hi There"
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";

        let expected = hex::decode(
            "87aa7cdea5ef619d4ff0b4241a1d6cb0\
             2379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4\
             be9d914eeb61f1702e696c203a126854",
        )
        .unwrap();

        let mut mac = hmac::HmacSha512::new_from_slice(&key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        assert_eq!(result.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha512_rfc4231_case2() {
        // Test Case 2
        // Key  = "Jefe"
        // Data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";

        let expected = hex::decode(
            "164b7a7bfcf819e2e395fbe73b56e0a3\
             87bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fd\
             caeab1a34d4a6b4b636e070a38bce737",
        )
        .unwrap();

        let mut mac = hmac::HmacSha512::new_from_slice(key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        assert_eq!(result.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha512_rfc4231_case3() {
        // Test Case 3
        // Key  = 0xaa repeated 20 times
        // Data = 0xdd repeated 50 times
        let key = vec![0xaau8; 20];
        let data = vec![0xddu8; 50];

        let expected = hex::decode(
            "fa73b0089d56a284efb0f0756c890be9\
             b1b5dbdd8ee81a3655f83e33b2279d39\
             bf3e848279a722c806b485a47e67c807\
             b946a337bee8942674278859e13292fb",
        )
        .unwrap();

        let mut mac = hmac::HmacSha512::new_from_slice(&key).unwrap();
        mac.update(&data);
        let result = mac.finalize();
        assert_eq!(result.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha512_rfc4231_case4() {
        // Test Case 4
        // Key  = 0x01 0x02 .. 0x19 (25 bytes)
        // Data = 0xcd repeated 50 times
        let key: Vec<u8> = (0x01..=0x19).collect();
        let data = vec![0xcdu8; 50];

        let expected = hex::decode(
            "b0ba465637458c6990e5a8c5f61d4af7\
             e576d97ff94b872de76f8050361ee3db\
             a91ca5c11aa25eb4d679275cc5788063\
             a5f19741120c4f2de2adebeb10a298dd",
        )
        .unwrap();

        let mut mac = hmac::HmacSha512::new_from_slice(&key).unwrap();
        mac.update(&data);
        let result = mac.finalize();
        assert_eq!(result.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha512_rfc4231_case6() {
        // Test Case 6
        // Key  = 0xaa repeated 131 times (key > block_size, so it gets hashed)
        // Data = "Test Using Larger Than Block-Size Key - Hash Key First"
        let key = vec![0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";

        let expected = hex::decode(
            "80b24263c7c1a3ebb71493c1dd7be8b4\
             9b46d1f41b4aeec1121b013783f8f352\
             6b56d037e05f2598bd0fd2215d6a1e52\
             95e64f73f63f0aec8b915a985d786598",
        )
        .unwrap();

        let mut mac = hmac::HmacSha512::new_from_slice(&key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        assert_eq!(result.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha512_rfc4231_case7() {
        // Test Case 7
        // Key  = 0xaa repeated 131 times
        // Data = "This is a test using a larger than block-size key and a
        //         larger than block-size data. ..."
        let key = vec![0xaau8; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

        let expected = hex::decode(
            "e37b6a775dc87dbaa4dfa9f96e5e3ffd\
             debd71f8867289865df5a32d20cdc944\
             b6022cac3c4982b10d5eeb55c3e4de15\
             134676fb6de0446065c97440fa8c6a58",
        )
        .unwrap();

        let mut mac = hmac::HmacSha512::new_from_slice(&key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        assert_eq!(result.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha512_streaming() {
        // Verify streaming update produces the same result as single-shot.
        let key = b"streaming test key";
        let data = b"Hello, World! This is a streaming test.";

        // Single-shot
        let mut mac1 = hmac::HmacSha512::new_from_slice(key).unwrap();
        mac1.update(data);
        let result1 = mac1.finalize().into_bytes();

        // Streaming byte-by-byte
        let mut mac2 = hmac::HmacSha512::new_from_slice(key).unwrap();
        for &b in data.iter() {
            mac2.update(&[b]);
        }
        let result2 = mac2.finalize().into_bytes();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_hmac_sha512_empty_data() {
        let key = b"key";
        let mut mac = hmac::HmacSha512::new_from_slice(key).unwrap();
        mac.update(b"");
        let result = mac.finalize();
        assert_eq!(result.as_ref().len(), 64);
    }

    #[test]
    fn test_hmac_sha512_empty_key() {
        // Empty key is valid for HMAC (zero-padded to block size).
        let mut mac = hmac::HmacSha512::new_from_slice(b"").unwrap();
        mac.update(b"test");
        let result = mac.finalize();
        assert_eq!(result.as_ref().len(), 64);
    }

    #[test]
    fn test_hmac_sha512_into_bytes_to_vec() {
        let key = b"key";
        let mut mac = hmac::HmacSha512::new_from_slice(key).unwrap();
        mac.update(b"data");
        let output = mac.finalize();

        // Test AsRef
        let _slice: &[u8] = output.as_ref();
        assert_eq!(_slice.len(), 64);

        // Test to_vec via AsRef (consumer pattern from hkdf.rs)
        let vec = output.into_bytes().to_vec();
        assert_eq!(vec.len(), 64);
    }

    #[test]
    fn test_hmac_error_display() {
        let err = hmac::HmacError::InvalidKeyLength("too short".into());
        let msg = format!("{}", err);
        assert!(msg.contains("too short"));
    }

    // -----------------------------------------------------------------------
    // Consistency tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha512_deterministic() {
        let data = b"deterministic test input 12345";
        let d1 = sha512(data);
        let d2 = sha512(data);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_sha512_different_inputs_different_outputs() {
        let d1 = sha512(b"input one");
        let d2 = sha512(b"input two");
        assert_ne!(d1, d2);
    }
}
