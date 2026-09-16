// MetaMUI SHA-224 Implementation
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! SHA-224 (FIPS 180-4 §5.3.2, §6.3).
//!
//! SHA-224 is the SHA-256 compression function started from its own initial
//! hash value, with the digest truncated to the leftmost 224 bits. It is here
//! for the FIPS 204 / FIPS 205 pre-hash table (`metamui-prehash-oids`); no
//! in-tree scheme uses it as a primary hash.

use crate::sha256::Sha256State;

/// Initial hash values (FIPS 180-4 Section 5.3.2): the second 32 bits of the
/// fractional parts of the square roots of the ninth through sixteenth primes.
const H0: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

/// Output size of SHA-224 in bytes.
pub const SHA224_OUTPUT_SIZE: usize = 28;

/// Incremental SHA-224.
///
/// ```
/// use metamui_sha2::sha224::Sha224Hasher;
///
/// let mut hasher = Sha224Hasher::new();
/// hasher.update(b"abc");
/// assert_eq!(hasher.finalize(), metamui_sha2::sha224(b"abc"));
/// ```
pub struct Sha224Hasher(Sha256State);

impl Sha224Hasher {
    /// Create a fresh state with the §5.3.2 initial hash values.
    pub fn new() -> Self {
        Self(Sha256State::with_initial_state(H0))
    }

    /// Feed more data into the hash.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finalize: apply FIPS 180-4 padding and return the 28-byte digest
    /// (the leftmost 224 bits of the eight state words, §6.3 step 4).
    pub fn finalize(self) -> [u8; SHA224_OUTPUT_SIZE] {
        let full = self.0.finalize();
        let mut out = [0u8; SHA224_OUTPUT_SIZE];
        out.copy_from_slice(&full[..SHA224_OUTPUT_SIZE]);
        out
    }
}

impl Default for Sha224Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the SHA-224 digest of `data`, returning a 28-byte array.
pub fn sha224(data: &[u8]) -> [u8; SHA224_OUTPUT_SIZE] {
    let mut hasher = Sha224Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-4 examples (NIST CSRC "SHA-224 examples") and RFC 3874 §3.
    #[test]
    fn empty_message() {
        assert_eq!(
            hex::encode(sha224(b"")),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            hex::encode(sha224(b"abc")),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }

    #[test]
    fn two_block_message() {
        assert_eq!(
            hex::encode(sha224(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let mut msg = [0u8; 1000];
        for (i, b) in msg.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut h = Sha224Hasher::new();
        for chunk in msg.chunks(37) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), sha224(&msg));
    }
}
