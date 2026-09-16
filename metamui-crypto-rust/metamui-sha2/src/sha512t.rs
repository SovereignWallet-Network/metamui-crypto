// MetaMUI SHA-512/224 and SHA-512/256 Implementation
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Author: Phantom Seokgu Yun (@phantomcoco) <phantom@metamui.id>
// Repository: https://github.com/SovereignWallet-Network/metamui-crypto

//! SHA-512/224 and SHA-512/256 (FIPS 180-4 §5.3.6, §6.6, §6.7).
//!
//! Both are the SHA-512 compression function started from the §5.3.6 initial
//! hash values (themselves derived by SHA-512 with the IV XOR `a5a5…a5` over
//! the strings `"SHA-512/224"` and `"SHA-512/256"`, §5.3.6.1–2), with the
//! digest truncated to the leftmost t bits. They are here for the FIPS 204 /
//! FIPS 205 pre-hash table (`metamui-prehash-oids`).

use crate::sha512::Sha512Hasher;

/// Initial hash values for SHA-512/224 (FIPS 180-4 Section 5.3.6.1).
const H0_224: [u64; 8] = [
    0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
    0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1,
];

/// Initial hash values for SHA-512/256 (FIPS 180-4 Section 5.3.6.2).
const H0_256: [u64; 8] = [
    0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
    0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2,
];

/// Output size of SHA-512/224 in bytes.
pub const SHA512_224_OUTPUT_SIZE: usize = 28;
/// Output size of SHA-512/256 in bytes.
pub const SHA512_256_OUTPUT_SIZE: usize = 32;

macro_rules! sha512_t {
    ($(#[$doc:meta])* $hasher:ident, $oneshot:ident, $iv:ident, $out:expr, $name:literal) => {
        $(#[$doc])*
        pub struct $hasher(Sha512Hasher);

        impl $hasher {
            #[doc = concat!("Create a fresh ", $name, " state.")]
            pub fn new() -> Self {
                Self(Sha512Hasher::with_initial_state($iv))
            }

            /// Feed more data into the hash.
            pub fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }

            #[doc = concat!("Finalize: apply FIPS 180-4 padding and return the leftmost ", stringify!($out), " bytes.")]
            pub fn finalize(self) -> [u8; $out] {
                let full = self.0.finalize();
                let mut out = [0u8; $out];
                out.copy_from_slice(&full[..$out]);
                out
            }
        }

        impl Default for $hasher {
            fn default() -> Self {
                Self::new()
            }
        }

        #[doc = concat!("Compute the ", $name, " digest of `data`.")]
        pub fn $oneshot(data: &[u8]) -> [u8; $out] {
            let mut hasher = $hasher::new();
            hasher.update(data);
            hasher.finalize()
        }
    };
}

sha512_t!(
    /// Incremental SHA-512/224.
    Sha512_224Hasher, sha512_224, H0_224, SHA512_224_OUTPUT_SIZE, "SHA-512/224"
);
sha512_t!(
    /// Incremental SHA-512/256.
    Sha512_256Hasher, sha512_256, H0_256, SHA512_256_OUTPUT_SIZE, "SHA-512/256"
);

#[cfg(test)]
mod tests {
    use super::*;

    // NIST CSRC "SHA-512/224 examples" and "SHA-512/256 examples".
    const TWO_BLOCK: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    #[test]
    fn sha512_224_vectors() {
        assert_eq!(
            hex::encode(sha512_224(b"")),
            "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
        );
        assert_eq!(
            hex::encode(sha512_224(b"abc")),
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
        );
        assert_eq!(
            hex::encode(sha512_224(TWO_BLOCK)),
            "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9"
        );
    }

    #[test]
    fn sha512_256_vectors() {
        assert_eq!(
            hex::encode(sha512_256(b"")),
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
        );
        assert_eq!(
            hex::encode(sha512_256(b"abc")),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
        );
        assert_eq!(
            hex::encode(sha512_256(TWO_BLOCK)),
            "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a"
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let mut a = Sha512_224Hasher::new();
        let mut b = Sha512_256Hasher::new();
        for chunk in TWO_BLOCK.chunks(13) {
            a.update(chunk);
            b.update(chunk);
        }
        assert_eq!(a.finalize(), sha512_224(TWO_BLOCK));
        assert_eq!(b.finalize(), sha512_256(TWO_BLOCK));
    }
}
