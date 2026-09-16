//! ML-KEM-768 (FIPS 203) with the standard byte encodings.
//!
//! | boundary | bytes |
//! |---|---|
//! | encapsulation key (`ek`) | 1184 |
//! | decapsulation key (`dk`) | 2400 |
//! | ciphertext (`c`) | 1088 |
//! | shared secret (`K`) | 32 |
//!
//! [`EncapsulationKey::from_bytes`] applies the FIPS 203 §7.2 modulus check
//! and [`DecapsulationKey::from_bytes`] the §7.3 hash check, so a key that
//! the standard says must be rejected never reaches an operation.
//! Decapsulation never fails on a malformed-but-well-sized ciphertext: FIPS
//! 203 implicit rejection returns a pseudorandom secret, exactly as the
//! standard requires.
//!
//! The shared secret is the raw KEM output. Deriving a session key from it,
//! binding transcript context, or authenticating a channel is the caller's
//! protocol, which this crate does not define.

use core::fmt;

use metamui_mlkem::mlkem768 as backend;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{expect_len, Error};

/// Encapsulation (public) key length.
pub const ENCAPSULATION_KEY_BYTES: usize = 1184;
/// Decapsulation (secret) key length.
pub const DECAPSULATION_KEY_BYTES: usize = 2400;
/// Ciphertext length.
pub const CIPHERTEXT_BYTES: usize = 1088;
/// Shared secret length.
pub const SHARED_SECRET_BYTES: usize = 32;

const WHAT_EK: &str = "ml-kem-768 encapsulation key";
const WHAT_DK: &str = "ml-kem-768 decapsulation key";
const WHAT_CT: &str = "ml-kem-768 ciphertext";

/// An ML-KEM-768 encapsulation key (FIPS 203 `ek`).
#[derive(Clone, PartialEq, Eq)]
pub struct EncapsulationKey([u8; ENCAPSULATION_KEY_BYTES]);

/// An ML-KEM-768 decapsulation key (FIPS 203 `dk`). Zeroized on drop;
/// `Debug` prints no key material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DecapsulationKey(Box<[u8; DECAPSULATION_KEY_BYTES]>);

/// An ML-KEM-768 ciphertext (FIPS 203 `c`).
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext([u8; CIPHERTEXT_BYTES]);

/// The 32-byte KEM output. Zeroized on drop, compared in constant time,
/// `Debug` prints no material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; SHARED_SECRET_BYTES]);

/// A freshly generated key pair.
pub struct KeyPair {
    /// The encapsulation key.
    pub encapsulation_key: EncapsulationKey,
    /// The decapsulation key.
    pub decapsulation_key: DecapsulationKey,
}

impl EncapsulationKey {
    /// Parse `ek`: exactly 1184 bytes and every coefficient below `q`
    /// (FIPS 203 §7.2 encapsulation key check).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        expect_len(WHAT_EK, bytes, ENCAPSULATION_KEY_BYTES)?;
        if !backend::validate_encapsulation_key(bytes) {
            return Err(Error::MalformedKey { what: WHAT_EK });
        }
        let mut out = [0u8; ENCAPSULATION_KEY_BYTES];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// The FIPS 203 encoding.
    pub fn as_bytes(&self) -> &[u8; ENCAPSULATION_KEY_BYTES] {
        &self.0
    }
}

impl TryFrom<&[u8]> for EncapsulationKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mlkem768::EncapsulationKey({} bytes)", ENCAPSULATION_KEY_BYTES)
    }
}

impl DecapsulationKey {
    /// Parse `dk`: exactly 2400 bytes and the embedded `H(ek)` must match
    /// (FIPS 203 §7.3 decapsulation key check).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        expect_len(WHAT_DK, bytes, DECAPSULATION_KEY_BYTES)?;
        if !backend::validate_decapsulation_key(bytes) {
            return Err(Error::MalformedKey { what: WHAT_DK });
        }
        let mut out = Box::new([0u8; DECAPSULATION_KEY_BYTES]);
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// The FIPS 203 encoding. The caller owns the copy it makes from this slice.
    pub fn as_bytes(&self) -> &[u8; DECAPSULATION_KEY_BYTES] {
        &self.0
    }
}

impl TryFrom<&[u8]> for DecapsulationKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mlkem768::DecapsulationKey(<redacted>)")
    }
}

impl Ciphertext {
    /// Parse `c`: exactly 1088 bytes. No further structure is checked; a
    /// well-sized but invalid ciphertext is implicitly rejected by
    /// [`decapsulate`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        expect_len(WHAT_CT, bytes, CIPHERTEXT_BYTES)?;
        let mut out = [0u8; CIPHERTEXT_BYTES];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// The FIPS 203 encoding.
    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_BYTES] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Ciphertext {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mlkem768::Ciphertext({} bytes)", CIPHERTEXT_BYTES)
    }
}

impl SharedSecret {
    /// The raw 32-byte secret. Copy it into a key-derivation input and let
    /// this value drop.
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
        &self.0
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SharedSecret {}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mlkem768::SharedSecret(<redacted>)")
    }
}

/// ML-KEM.KeyGen (FIPS 203 Alg. 19) from caller-supplied cryptographic
/// randomness: the backend draws `d` then `z` (32 bytes each) from `rng`.
pub fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> Result<KeyPair, Error> {
    let kp = backend::generate_keypair(rng).map_err(|_| Error::KeyGenerationFailed { reason: "backend" })?;
    let encapsulation_key = EncapsulationKey::from_bytes(kp.public_key.as_slice())?;
    let decapsulation_key = DecapsulationKey::from_bytes(kp.private_key.as_slice())?;
    Ok(KeyPair { encapsulation_key, decapsulation_key })
}

/// ML-KEM.Encaps (FIPS 203 Alg. 20): the backend draws the 32-byte `m` from
/// `rng`.
pub fn encapsulate<R: RngCore + CryptoRng>(
    encapsulation_key: &EncapsulationKey,
    rng: &mut R,
) -> Result<(Ciphertext, SharedSecret), Error> {
    let ek = backend::PublicKey::from_bytes(encapsulation_key.0);
    let (ct, ss) = backend::encapsulate(&ek, rng).map_err(|_| Error::EncapsulationFailed { reason: "backend" })?;
    let ciphertext = Ciphertext::from_bytes(ct.as_slice())?;
    Ok((ciphertext, SharedSecret(*ss.as_bytes())))
}

/// ML-KEM.Decaps (FIPS 203 Alg. 21). Never fails for a well-sized
/// ciphertext: an invalid one yields the implicit-rejection secret.
pub fn decapsulate(decapsulation_key: &DecapsulationKey, ciphertext: &Ciphertext) -> Result<SharedSecret, Error> {
    let dk = backend::PrivateKey::from_bytes(*decapsulation_key.0);
    let ct = backend::Ciphertext::from_bytes(ciphertext.0);
    let ss = backend::decapsulate(&dk, &ct).map_err(|_| Error::MalformedKey { what: WHAT_DK })?;
    Ok(SharedSecret(*ss.as_bytes()))
}

/// [`generate_keypair`] with operating-system randomness.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn generate_keypair_os() -> Result<KeyPair, Error> {
    generate_keypair(&mut crate::os_rng()?)
}

/// [`encapsulate`] with operating-system randomness.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub fn encapsulate_os(encapsulation_key: &EncapsulationKey) -> Result<(Ciphertext, SharedSecret), Error> {
    encapsulate(encapsulation_key, &mut crate::os_rng()?)
}
