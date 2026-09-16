//! The pre-hash algorithm table shared by HashML-DSA (FIPS 204 §5.4.1) and
//! HashSLH-DSA (FIPS 205 §10.2.2): the ACVP `hashAlg` names, the DER-encoded
//! OIDs that prefix `PH(M)` in `M'`, and the digests themselves (SHAKE-128 →
//! 256 bits, SHAKE-256 → 512 bits, as both standards fix).
//!
//! One table, one consumer per scheme: `metamui-slhdsa` re-exports
//! [`PreHashAlgorithm`] unchanged and `metamui-dilithium` builds
//! `hash_sign_with` / `hash_verify_with` on it, so the two FIPS pre-hash
//! surfaces can no longer drift apart.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;

/// A pre-hash algorithm for HashML-DSA (FIPS 204 Algorithm 4) and HashSLH-DSA
/// (FIPS 205 Algorithm 24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreHashAlgorithm {
    /// SHA-224 (28-byte output)
    Sha224,
    /// SHA-256 (32-byte output)
    Sha256,
    /// SHA-384 (48-byte output)
    Sha384,
    /// SHA-512 (64-byte output)
    Sha512,
    /// SHA-512/224 (28-byte output)
    Sha512_224,
    /// SHA-512/256 (32-byte output)
    Sha512_256,
    /// SHA3-224 (28-byte output)
    Sha3_224,
    /// SHA3-256 (32-byte output)
    Sha3_256,
    /// SHA3-384 (48-byte output)
    Sha3_384,
    /// SHA3-512 (64-byte output)
    Sha3_512,
    /// SHAKE-128 (32-byte output)
    Shake128,
    /// SHAKE-256 (64-byte output)
    Shake256,
}

impl PreHashAlgorithm {
    /// Parse from ACVP test vector hashAlg string
    pub fn from_acvp_str(s: &str) -> Option<Self> {
        match s {
            "SHA2-224" => Some(Self::Sha224),
            "SHA2-256" => Some(Self::Sha256),
            "SHA2-384" => Some(Self::Sha384),
            "SHA2-512" => Some(Self::Sha512),
            "SHA2-512/224" => Some(Self::Sha512_224),
            "SHA2-512/256" => Some(Self::Sha512_256),
            "SHA3-224" => Some(Self::Sha3_224),
            "SHA3-256" => Some(Self::Sha3_256),
            "SHA3-384" => Some(Self::Sha3_384),
            "SHA3-512" => Some(Self::Sha3_512),
            "SHAKE-128" => Some(Self::Shake128),
            "SHAKE-256" => Some(Self::Shake256),
            _ => None,
        }
    }

    /// DER-encoded OID for the hash algorithm
    pub fn oid(&self) -> &'static [u8; 11] {
        match self {
            Self::Sha256     => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            Self::Sha384     => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
            Self::Sha512     => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
            Self::Sha224     => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
            Self::Sha512_224 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05],
            Self::Sha512_256 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06],
            Self::Sha3_224   => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07],
            Self::Sha3_256   => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
            Self::Sha3_384   => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
            Self::Sha3_512   => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A],
            Self::Shake128   => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B],
            Self::Shake256   => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C],
        }
    }

    /// Compute the pre-hash digest of a message.
    ///
    /// SHAKE-128 and SHAKE-256 produce the fixed 256- and 512-bit outputs
    /// FIPS 204 §5.4.1 / FIPS 205 §10.2.2 prescribe for PH(M).
    pub fn hash(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha224 => metamui_sha2::sha224(message).to_vec(),
            Self::Sha256 => metamui_sha2::sha256(message).to_vec(),
            Self::Sha384 => metamui_sha2::sha384(message).to_vec(),
            Self::Sha512 => metamui_sha2::sha512(message).to_vec(),
            Self::Sha512_224 => metamui_sha2::sha512_224(message).to_vec(),
            Self::Sha512_256 => metamui_sha2::sha512_256(message).to_vec(),
            Self::Sha3_224 => metamui_sha3::sha3_224(message).to_vec(),
            Self::Sha3_256 => metamui_sha3::sha3_256(message).to_vec(),
            Self::Sha3_384 => metamui_sha3::sha3_384(message).to_vec(),
            Self::Sha3_512 => metamui_sha3::sha3_512(message).to_vec(),
            Self::Shake128 => metamui_shake::shake128(message, 32),
            Self::Shake256 => metamui_shake::shake256(message, 64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_acvp_name_round_trips_to_a_distinct_oid() {
        let names = ["SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256",
                     "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256"];
        let mut seen = Vec::new();
        for n in names {
            let a = PreHashAlgorithm::from_acvp_str(n).unwrap();
            assert!(!seen.contains(&a.oid()[10]), "{n}: duplicate OID");
            seen.push(a.oid()[10]);
            assert_eq!(&a.oid()[..10], &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02]);
        }
        assert_eq!(PreHashAlgorithm::from_acvp_str("MD5"), None);
        assert_eq!(PreHashAlgorithm::Shake128.hash(b"").len(), 32);
        assert_eq!(PreHashAlgorithm::Shake256.hash(b"").len(), 64);
    }

    /// PH("abc") for every row against an independent oracle (Python
    /// hashlib over OpenSSL), so a wrong initial-value constant in one of the
    /// truncated SHA-2 variants cannot hide behind a self-consistent
    /// sign/verify round trip.
    #[test]
    fn every_row_hashes_abc_like_the_oracle() {
        let expected = [
            ("SHA2-224", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
            ("SHA2-256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("SHA2-384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
            ("SHA2-512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            ("SHA2-512/224", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"),
            ("SHA2-512/256", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),
            ("SHA3-224", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
            ("SHA3-256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
            ("SHA3-384", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"),
            ("SHA3-512", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
            ("SHAKE-128", "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"),
            ("SHAKE-256", "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"),
        ];
        for (name, hex) in expected {
            let got: alloc::string::String = PreHashAlgorithm::from_acvp_str(name)
                .unwrap()
                .hash(b"abc")
                .iter()
                .map(|b| alloc::format!("{:02x}", b))
                .collect();
            assert_eq!(got, hex, "{name}");
        }
    }
}
