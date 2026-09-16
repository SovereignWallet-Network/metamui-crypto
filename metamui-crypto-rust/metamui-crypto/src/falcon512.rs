//! Falcon-512 in its two NIST Round-3 wire encodings.
//!
//! | profile | signature | header |
//! |---|---|---|
//! | `falcon-512.r3-compressed` | variable, 42 ..= 752 bytes | `0x39` |
//! | `falcon-512.r3-padded` | exactly 666 bytes | `0x39` |
//!
//! Keys are shared by both profiles: public key 897 bytes with header `0x09`,
//! secret key 1281 bytes with header `0x59`. A signature produced in one
//! profile is **not** valid in the other: the types [`CompressedSignature`]
//! and [`PaddedSignature`] are distinct so the mistake does not compile.
//!
//! The backend is `metamui-falcon512`, gated byte-for-byte against the NIST
//! Round-3 Falcon KAT (compressed) and the PQClean `falcon-padded-512` KAT
//! (padded); the tests of this crate replay both through this module.

use core::fmt;

use metamui_falcon512 as backend;
use metamui_falcon512::sizes::{self, falcon512 as f512};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{expect_header, expect_len, Error, LengthRule};

/// Public key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = f512::PUBLIC_KEY;
/// Secret key length in bytes.
pub const SECRET_KEY_BYTES: usize = f512::SECRET_KEY;
/// Exact length of a padded-profile signature.
pub const PADDED_SIGNATURE_BYTES: usize = f512::SIG_PADDED;
/// Largest compressed-profile signature the encoding admits.
pub const COMPRESSED_SIGNATURE_MAX_BYTES: usize = f512::SIG_COMPRESSED_MAX;
/// Smallest structurally possible compressed-profile signature:
/// header, 40-byte nonce and at least one byte of Golomb-Rice payload.
/// Real signatures are far longer; this is a parse floor, not a security bound.
pub const COMPRESSED_SIGNATURE_MIN_BYTES: usize = sizes::SIG_PREFIX_LEN + 1;
/// Nonce length inside every signature.
pub const NONCE_BYTES: usize = sizes::NONCE_LEN;

/// Format header of a public key (`0x00 | logn`, logn = 9).
pub const PUBLIC_KEY_HEADER: u8 = 0x09;
/// Format header of a secret key (`0x50 | logn`).
pub const SECRET_KEY_HEADER: u8 = 0x59;
/// Format header of a signature in either profile (`0x30 | logn`).
pub const SIGNATURE_HEADER: u8 = 0x39;

const WHAT_PK: &str = "falcon-512 public key";
const WHAT_SK: &str = "falcon-512 secret key";
const WHAT_SIG_C: &str = "falcon-512 compressed signature";
const WHAT_SIG_P: &str = "falcon-512 padded signature";

/// A Falcon-512 public key (897 bytes, header `0x09`).
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_BYTES]);

/// A Falcon-512 secret key (1281 bytes, header `0x59`). Zeroized on drop;
/// `Debug` prints no key material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Box<[u8; SECRET_KEY_BYTES]>);

/// A signature in the `falcon-512.r3-compressed` profile.
#[derive(Clone, PartialEq, Eq)]
pub struct CompressedSignature(Vec<u8>);

/// A signature in the `falcon-512.r3-padded` profile (exactly 666 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct PaddedSignature(Box<[u8; PADDED_SIGNATURE_BYTES]>);

/// A freshly generated key pair.
pub struct KeyPair {
    /// The public key.
    pub public_key: PublicKey,
    /// The secret key.
    pub secret_key: SecretKey,
}

impl PublicKey {
    /// Parse the NIST encoding. Exactly 897 bytes, header `0x09`, and the
    /// coefficients must decode.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        expect_len(WHAT_PK, bytes, PUBLIC_KEY_BYTES)?;
        expect_header(WHAT_PK, bytes, PUBLIC_KEY_HEADER)?;
        // Decode once so a key that cannot be used fails here, not at verify.
        backend::PublicKey::from_bytes(bytes).map_err(|_| Error::MalformedKey { what: WHAT_PK })?;
        let mut out = [0u8; PUBLIC_KEY_BYTES];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// The NIST encoding.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.0
    }

    fn inner(&self) -> Result<backend::PublicKey, Error> {
        backend::PublicKey::from_bytes(&self.0).map_err(|_| Error::MalformedKey { what: WHAT_PK })
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "falcon512::PublicKey({} bytes)", PUBLIC_KEY_BYTES)
    }
}

impl SecretKey {
    /// Parse the NIST encoding. Exactly 1281 bytes, header `0x59`, and the
    /// polynomials must decode.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        expect_len(WHAT_SK, bytes, SECRET_KEY_BYTES)?;
        expect_header(WHAT_SK, bytes, SECRET_KEY_HEADER)?;
        backend::PrivateKey::from_bytes(bytes).map_err(|_| Error::MalformedKey { what: WHAT_SK })?;
        let mut out = Box::new([0u8; SECRET_KEY_BYTES]);
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// The NIST encoding. The caller owns the copy it makes from this slice.
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_BYTES] {
        &self.0
    }

    fn inner(&self) -> Result<backend::PrivateKey, Error> {
        backend::PrivateKey::from_bytes(&self.0[..]).map_err(|_| Error::MalformedKey { what: WHAT_SK })
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("falcon512::SecretKey(<redacted>)")
    }
}

impl CompressedSignature {
    /// Parse a compressed-profile signature: header `0x39`, 42 ..= 752 bytes.
    /// Whether the Golomb-Rice payload is well formed for the message is
    /// decided by [`verify_compressed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < COMPRESSED_SIGNATURE_MIN_BYTES || bytes.len() > COMPRESSED_SIGNATURE_MAX_BYTES {
            return Err(Error::InvalidLength {
                what: WHAT_SIG_C,
                expected: LengthRule::Between {
                    min: COMPRESSED_SIGNATURE_MIN_BYTES,
                    max: COMPRESSED_SIGNATURE_MAX_BYTES,
                },
                actual: bytes.len(),
            });
        }
        expect_header(WHAT_SIG_C, bytes, SIGNATURE_HEADER)?;
        Ok(Self(bytes.to_vec()))
    }

    /// The encoded signature.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for CompressedSignature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for CompressedSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "falcon512::CompressedSignature({} bytes)", self.0.len())
    }
}

impl PaddedSignature {
    /// Parse a padded-profile signature: exactly 666 bytes, header `0x39`.
    /// Non-zero padding is rejected by [`verify_padded`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        expect_len(WHAT_SIG_P, bytes, PADDED_SIGNATURE_BYTES)?;
        expect_header(WHAT_SIG_P, bytes, SIGNATURE_HEADER)?;
        let mut out = Box::new([0u8; PADDED_SIGNATURE_BYTES]);
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// The encoded signature.
    pub fn as_bytes(&self) -> &[u8; PADDED_SIGNATURE_BYTES] {
        &self.0
    }
}

impl TryFrom<&[u8]> for PaddedSignature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for PaddedSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "falcon512::PaddedSignature({} bytes)", PADDED_SIGNATURE_BYTES)
    }
}

fn map_sign_err(e: backend::Falcon512Error) -> Error {
    Error::SigningFailed {
        reason: match e {
            backend::Falcon512Error::LdlSigmaOutOfBand => "key outside sampler sigma band",
            backend::Falcon512Error::SignatureTooLong => "signature exceeded the profile length",
            _ => "backend",
        },
    }
}

/// Generate a key pair from caller-supplied cryptographic randomness.
pub fn generate_keypair<R: RngCore + CryptoRng + Send>(rng: &mut R) -> Result<KeyPair, Error> {
    let kp = backend::generate_keypair(rng).map_err(|_| Error::KeyGenerationFailed { reason: "backend" })?;
    let public_key = PublicKey::from_bytes(&kp.public_key.to_bytes())?;
    let secret_key = SecretKey::from_bytes(&kp.private_key.to_bytes())?;
    Ok(KeyPair { public_key, secret_key })
}

/// Sign in the `falcon-512.r3-compressed` profile.
///
/// The output is a function of `(message, secret_key, rng stream)`; a
/// caller that supplies a seeded `CryptoRng` gets a reproducible signature,
/// which is that caller's decision, not the library's.
pub fn sign_compressed<R: RngCore + CryptoRng>(
    secret_key: &SecretKey,
    message: &[u8],
    rng: &mut R,
) -> Result<CompressedSignature, Error> {
    let sk = secret_key.inner()?;
    let sig = backend::sign(message, &sk, rng).map_err(map_sign_err)?;
    // The backend is gated against upstream; re-checking the frame here turns
    // a backend regression into a typed error instead of a malformed value.
    CompressedSignature::from_bytes(&sig)
        .map_err(|_| Error::SigningFailed { reason: "backend produced an out-of-profile signature" })
}

/// Sign in the `falcon-512.r3-padded` profile (exactly 666 bytes).
pub fn sign_padded<R: RngCore + CryptoRng>(
    secret_key: &SecretKey,
    message: &[u8],
    rng: &mut R,
) -> Result<PaddedSignature, Error> {
    let sk = secret_key.inner()?;
    let sig = backend::sign_padded(message, &sk, rng).map_err(map_sign_err)?;
    PaddedSignature::from_bytes(&sig)
        .map_err(|_| Error::SigningFailed { reason: "backend produced an out-of-profile signature" })
}

/// Verify a `falcon-512.r3-compressed` signature. Any failure — wrong key,
/// tampered payload, trailing bytes — is [`Error::InvalidSignature`].
pub fn verify_compressed(
    public_key: &PublicKey,
    message: &[u8],
    signature: &CompressedSignature,
) -> Result<(), Error> {
    let pk = public_key.inner()?;
    match backend::verify(message, signature.as_bytes(), &pk) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(Error::InvalidSignature),
    }
}

/// Verify a `falcon-512.r3-padded` signature. Non-zero padding bytes are a
/// verification failure, as in the PQClean `falcon-padded-512` verifier.
pub fn verify_padded(
    public_key: &PublicKey,
    message: &[u8],
    signature: &PaddedSignature,
) -> Result<(), Error> {
    let pk = public_key.inner()?;
    match backend::verify_padded(message, &signature.as_bytes()[..], &pk) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(Error::InvalidSignature),
    }
}

/// [`generate_keypair`] with operating-system randomness.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn generate_keypair_os() -> Result<KeyPair, Error> {
    generate_keypair(&mut crate::os_rng()?)
}

/// [`sign_compressed`] with operating-system randomness.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn sign_compressed_os(secret_key: &SecretKey, message: &[u8]) -> Result<CompressedSignature, Error> {
    sign_compressed(secret_key, message, &mut crate::os_rng()?)
}

/// [`sign_padded`] with operating-system randomness.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn sign_padded_os(secret_key: &SecretKey, message: &[u8]) -> Result<PaddedSignature, Error> {
    sign_padded(secret_key, message, &mut crate::os_rng()?)
}
