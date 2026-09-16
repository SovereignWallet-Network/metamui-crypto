// MetaMUI SHA-256 Implementation (FIPS 180-4)
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! SHA-256 cryptographic hash function (FIPS 180-4) with HMAC-SHA-256 (RFC 2104).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use core::fmt;

// FIPS 180-4, Section 4.2.2: SHA-256 Constants
// These are the first 32 bits of the fractional parts of the cube roots
// of the first 64 prime numbers (2..311).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// FIPS 180-4, Section 5.3.3: SHA-256 Initial Hash Values
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 output size in bytes.
pub const SHA256_OUTPUT_SIZE: usize = 32;

/// SHA-256 block size in bytes.
pub const SHA256_BLOCK_SIZE: usize = 64;

/// Error type for SHA-256 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sha256Error {
    /// The input data could not be processed.
    InvalidInput(&'static str),
    /// An internal error occurred during hashing.
    InternalError(&'static str),
}

impl fmt::Display for Sha256Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Sha256Error::InvalidInput(msg) => write!(f, "SHA-256 invalid input: {}", msg),
            Sha256Error::InternalError(msg) => write!(f, "SHA-256 internal error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Sha256Error {}

// ---- FIPS 180-4 Section 4.1.2: SHA-256 Functions ----

#[inline(always)]
const fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
const fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
const fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
const fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
const fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
const fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

// ---------------------------------------------------------------------------
// Internal streaming state
// ---------------------------------------------------------------------------

/// Internal SHA-256 state for incremental (streaming) hashing.
pub(crate) struct Sha256State {
    h: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256State {
    /// Initialize with the FIPS 180-4 initial hash values.
    pub(crate) fn new() -> Self {
        Self::with_initial_state(H0)
    }

    /// Initialize with a caller-supplied initial hash value. SHA-224 is this
    /// compression function under the §5.3.2 constants (see `sha224.rs`).
    pub(crate) fn with_initial_state(h: [u32; 8]) -> Self {
        Self {
            h,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Feed more data into the hash.
    pub(crate) fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

        // If there is buffered data, try to fill the buffer to a full block.
        if self.buffer_len > 0 {
            let space = 64 - self.buffer_len;
            let to_copy = if data.len() < space { data.len() } else { space };
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == 64 {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }

        // Process as many full 64-byte blocks as possible directly from `data`.
        while offset + 64 <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            self.process_block(&block);
            offset += 64;
        }

        // Buffer the remaining bytes (< 64).
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize: apply FIPS 180-4 padding and return the 32-byte digest.
    pub(crate) fn finalize(mut self) -> [u8; 32] {
        let msg_len_bits = self.total_len.wrapping_mul(8);

        // Append the 0x80 byte.
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If there is not enough room for the 8-byte length field,
        // pad this block with zeros, compress, and start a new block.
        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffer_len = 0;
            self.buffer = [0u8; 64];
        }

        // Pad with zeros up to byte 56.
        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        // Append 64-bit big-endian message length.
        self.buffer[56..64].copy_from_slice(&msg_len_bits.to_be_bytes());
        let block = self.buffer;
        self.process_block(&block);

        // Produce the final digest from state words.
        let mut output = [0u8; 32];
        for (i, &word) in self.h.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    /// Process a single 512-bit (64-byte) block.
    /// FIPS 180-4, Section 6.2.2: SHA-256 Hash Computation
    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];

        for t in 0..16 {
            w[t] = u32::from_be_bytes([
                block[t * 4],
                block[t * 4 + 1],
                block[t * 4 + 2],
                block[t * 4 + 3],
            ]);
        }

        for t in 16..64 {
            w[t] = small_sigma1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(small_sigma0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        for t in 0..64 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

// ---------------------------------------------------------------------------
// Public convenience function
// ---------------------------------------------------------------------------

/// Compute the SHA-256 digest of `data`, returning a 32-byte array.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = Sha256State::new();
    state.update(data);
    state.finalize()
}

// ---------------------------------------------------------------------------
// Public streaming hasher
// ---------------------------------------------------------------------------

/// Incremental SHA-256: feed the message in pieces, then `finalize`.
///
/// This is the type the in-tree signature schemes (SLH-DSA, XMSS, LMS,
/// Falcon, RSA-PSS) hash with; it mirrors [`crate::sha512::Sha512Hasher`].
///
/// ```
/// use metamui_sha2::sha256::Sha256Hasher;
///
/// let mut hasher = Sha256Hasher::new();
/// hasher.update(b"ab");
/// hasher.update(b"c");
/// assert_eq!(hasher.finalize(), metamui_sha2::sha256(b"abc"));
/// ```
pub struct Sha256Hasher(Sha256State);

impl Sha256Hasher {
    /// Create a fresh state with the FIPS 180-4 initial hash values.
    pub fn new() -> Self {
        Self(Sha256State::new())
    }

    /// Feed more data into the hash.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finalize: apply FIPS 180-4 padding and return the 32-byte digest.
    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize()
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public struct wrapper
// ---------------------------------------------------------------------------

/// MetaMUI SHA-256 hasher providing a struct-based API.
pub struct MetaMUISha256;

impl MetaMUISha256 {
    /// Create a new `MetaMUISha256` instance.
    pub fn new() -> Self {
        Self
    }

    /// Compute the SHA-256 hash of the given data.
    pub fn hash(&self, data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        Ok(sha256(data))
    }

    /// Return the algorithm name.
    pub fn algorithm_name(&self) -> &'static str {
        "SHA-256"
    }

    /// Return the output size in bytes.
    pub fn output_size(&self) -> usize {
        SHA256_OUTPUT_SIZE
    }

    /// Return the block size in bytes.
    pub fn block_size(&self) -> usize {
        SHA256_BLOCK_SIZE
    }
}

impl Default for MetaMUISha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MetaMUISha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MetaMUISha256(output_size={})", self.output_size())
    }
}

impl fmt::Debug for MetaMUISha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetaMUISha256")
            .field("algorithm", &self.algorithm_name())
            .field("output_size", &self.output_size())
            .field("block_size", &self.block_size())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// HMAC-SHA-256 (RFC 2104 / RFC 4231)
// ---------------------------------------------------------------------------

/// HMAC-SHA-256 implementation per RFC 2104.
pub mod hmac {
    use super::*;

    /// Block size for SHA-256 in bytes.
    const BLOCK_SIZE: usize = 64;

    /// Errors that can occur during HMAC-SHA-256 operations.
    #[derive(Debug, Clone)]
    pub enum HmacError {
        /// The provided key was invalid.
        InvalidKeyLength(Vec<u8>),
    }

    impl fmt::Display for HmacError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                HmacError::InvalidKeyLength(_) => {
                    write!(f, "HMAC-SHA-256 invalid key")
                }
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for HmacError {}

    /// The output of an HMAC-SHA-256 computation (32 bytes).
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

    /// Streaming HMAC-SHA-256 computation.
    pub struct HmacSha256 {
        inner_state: Sha256State,
        outer_key_pad: [u8; BLOCK_SIZE],
    }

    impl HmacSha256 {
        /// Create a new HMAC-SHA-256 instance from a key of arbitrary length.
        pub fn new_from_slice(key: &[u8]) -> Result<Self, HmacError> {
            let mut key_block = [0u8; BLOCK_SIZE];
            if key.len() > BLOCK_SIZE {
                let hashed = sha256(key);
                key_block[..32].copy_from_slice(&hashed);
            } else {
                key_block[..key.len()].copy_from_slice(key);
            }

            let mut inner_key_pad = [0u8; BLOCK_SIZE];
            let mut outer_key_pad = [0u8; BLOCK_SIZE];
            for i in 0..BLOCK_SIZE {
                inner_key_pad[i] = key_block[i] ^ 0x36;
                outer_key_pad[i] = key_block[i] ^ 0x5c;
            }

            for b in key_block.iter_mut() {
                *b = 0;
            }

            let mut inner_state = Sha256State::new();
            inner_state.update(&inner_key_pad);

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

        /// Finalize the HMAC and return the 32-byte tag.
        pub fn finalize(mut self) -> HmacOutput {
            let inner_hash = self.inner_state.finalize();

            let mut outer_state = Sha256State::new();
            outer_state.update(&self.outer_key_pad);
            outer_state.update(&inner_hash);
            let result = outer_state.finalize();

            for b in self.outer_key_pad.iter_mut() {
                *b = 0;
            }

            HmacOutput {
                bytes: result.to_vec(),
            }
        }
    }

    /// Convenience function: compute HMAC-SHA-256 in one shot.
    pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
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

    // ---- FIPS 180-4 / NIST test vectors ----

    #[test]
    fn test_sha256_abc() {
        let digest = sha256(b"abc");
        assert_eq!(
            hex::encode(digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_empty() {
        let digest = sha256(b"");
        assert_eq!(
            hex::encode(digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_448_bits() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let digest = sha256(input);
        assert_eq!(
            hex::encode(digest),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_sha256_896_bits() {
        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let digest = sha256(input);
        assert_eq!(
            hex::encode(digest),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    fn test_sha256_one_million_a() {
        let input = vec![b'a'; 1_000_000];
        let digest = sha256(&input);
        assert_eq!(
            hex::encode(digest),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    // ---- Struct-based API tests ----

    #[test]
    fn test_metamui_sha256_hash() {
        let hasher = MetaMUISha256::new();
        let digest = hasher.hash(b"abc").unwrap();
        assert_eq!(
            hex::encode(digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_metamui_sha256_default() {
        let hasher = MetaMUISha256::default();
        let digest = hasher.hash(b"abc").unwrap();
        assert_eq!(
            hex::encode(digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_metamui_sha256_metadata() {
        let hasher = MetaMUISha256::new();
        assert_eq!(hasher.algorithm_name(), "SHA-256");
        assert_eq!(hasher.output_size(), 32);
        assert_eq!(hasher.block_size(), 64);
    }

    #[test]
    fn test_metamui_sha256_display() {
        let hasher = MetaMUISha256::new();
        assert_eq!(format!("{}", hasher), "MetaMUISha256(output_size=32)");
    }

    #[test]
    fn test_metamui_sha256_debug() {
        let hasher = MetaMUISha256::new();
        let debug_str = format!("{:?}", hasher);
        assert!(debug_str.contains("MetaMUISha256"));
        assert!(debug_str.contains("SHA-256"));
    }

    // ---- Consistency tests ----

    #[test]
    fn test_convenience_matches_struct() {
        let data = b"consistency check";
        let digest1 = sha256(data);
        let digest2 = MetaMUISha256::new().hash(data).unwrap();
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_deterministic() {
        let data = b"determinism test";
        let d1 = sha256(data);
        let d2 = sha256(data);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_different_inputs_different_outputs() {
        let d1 = sha256(b"hello");
        let d2 = sha256(b"world");
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_single_byte() {
        let digest = sha256(&[0x00]);
        assert_eq!(
            hex::encode(digest),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    #[test]
    fn test_exactly_55_bytes() {
        let data = [0xAA; 55];
        let digest = sha256(&data);
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_exactly_56_bytes() {
        let data = [0xBB; 56];
        let digest = sha256(&data);
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_exactly_64_bytes() {
        let data = [0xCC; 64];
        let digest = sha256(&data);
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_exactly_119_bytes() {
        let data = [0xDD; 119];
        let digest = sha256(&data);
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_exactly_120_bytes() {
        let data = [0xEE; 120];
        let digest = sha256(&data);
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn test_large_input() {
        let data = vec![0xFF; 10240];
        let digest = sha256(&data);
        assert_eq!(digest.len(), 32);
    }

    // ---- Streaming tests ----

    #[test]
    fn test_streaming_equivalence() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let one_shot = sha256(data);

        let mut state = Sha256State::new();
        for &byte in data.iter() {
            state.update(&[byte]);
        }
        let streaming = state.finalize();

        assert_eq!(one_shot, streaming);
    }

    // ---- Error type tests ----

    #[test]
    fn test_sha256_error_display() {
        let err = Sha256Error::InvalidInput("test error");
        assert_eq!(format!("{}", err), "SHA-256 invalid input: test error");

        let err = Sha256Error::InternalError("internal issue");
        assert_eq!(format!("{}", err), "SHA-256 internal error: internal issue");
    }

    #[test]
    fn test_sha256_error_equality() {
        let err1 = Sha256Error::InvalidInput("msg");
        let err2 = Sha256Error::InvalidInput("msg");
        let err3 = Sha256Error::InternalError("msg");
        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_sha256_error_clone() {
        let err = Sha256Error::InvalidInput("cloned");
        let err2 = err.clone();
        assert_eq!(err, err2);
    }

    // ---- HMAC-SHA-256 tests (RFC 4231) ----

    #[test]
    fn test_hmac_sha256_rfc4231_case1() {
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

        let mut mac = hmac::HmacSha256::new_from_slice(&key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        assert_eq!(hex::encode(result.as_ref()), expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

        let mut mac = hmac::HmacSha256::new_from_slice(key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        assert_eq!(hex::encode(result.as_ref()), expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case3() {
        let key = vec![0xaau8; 20];
        let data = vec![0xddu8; 50];
        let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

        let mut mac = hmac::HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&data);
        let result = mac.finalize();
        assert_eq!(hex::encode(result.as_ref()), expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case4() {
        let key: Vec<u8> = (0x01..=0x19).collect();
        let data = vec![0xcdu8; 50];
        let expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";

        let mut mac = hmac::HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&data);
        let result = mac.finalize();
        assert_eq!(hex::encode(result.as_ref()), expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case6() {
        let key = vec![0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

        let mut mac = hmac::HmacSha256::new_from_slice(&key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        assert_eq!(hex::encode(result.as_ref()), expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case7() {
        let key = vec![0xaau8; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        let expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";

        let mut mac = hmac::HmacSha256::new_from_slice(&key).unwrap();
        mac.update(data);
        let result = mac.finalize();
        assert_eq!(hex::encode(result.as_ref()), expected);
    }

    #[test]
    fn test_hmac_sha256_streaming() {
        let key = b"streaming test key";
        let data = b"Hello, World! This is a streaming test.";

        let mut mac1 = hmac::HmacSha256::new_from_slice(key).unwrap();
        mac1.update(data);
        let result1 = mac1.finalize().into_bytes();

        let mut mac2 = hmac::HmacSha256::new_from_slice(key).unwrap();
        for &b in data.iter() {
            mac2.update(&[b]);
        }
        let result2 = mac2.finalize().into_bytes();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_hmac_sha256_convenience_fn() {
        let key = vec![0x0bu8; 20];
        let data = b"Hi There";
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        let result = hmac::hmac_sha256(&key, data);
        assert_eq!(hex::encode(&result), expected);
    }
}
