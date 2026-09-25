//! Public, byte-oriented facade over the SMAUG-T **v1.2.0** KEM (the KpqC
//! standard, CryptoLab reference). This is the API consumers should link;
//! `crate::SmaugT` is a thin newtype facade over it with the same bytes.
//!
//! Key/ciphertext byte layouts are exactly the reference `crypto_kem_*` ones,
//! so keys interoperate with every other binding's v1.2.0 port and with the
//! `test-vectors/smaug-t/v1.2.0-kat/` oracle (see `tests/public_api_v1_2_0.rs`).

use std::fmt;
use std::vec::Vec;

use rand_core::RngCore;

use super::kem::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
#[cfg(feature = "kat-internal")]
use super::kem::{enc_internal, keypair_internal};
use super::params::{Mode, Params, SHARED_SECRET_BYTES};
#[cfg(feature = "kat-internal")]
use super::params::{CRYPTO_BYTES, T_BYTES};

/// Length errors of the byte API and of the reference-named `crypto_kem_*`
/// functions. All inputs and output buffers are length-checked before any
/// arithmetic runs; the KEM itself never fails (implicit rejection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmaugV1Error {
    InvalidPublicKeyLength { expected: usize, got: usize },
    InvalidSecretKeyLength { expected: usize, got: usize },
    InvalidCiphertextLength { expected: usize, got: usize },
    InvalidMessageLength { expected: usize, got: usize },
    /// The shared-secret output buffer of a `crypto_kem_*` call.
    InvalidSharedSecretLength { expected: usize, got: usize },
    /// A key-generation input of a `crypto_kem_keypair_internal` call: the
    /// implicit-rejection key `d` or the IND-CPA seed.
    InvalidSeedLength { expected: usize, got: usize },
    /// `keygen_from_seed` was given an empty seed, which would expand to one
    /// fixed keypair. The C and Python bindings refuse it the same way.
    EmptySeed,
}

impl fmt::Display for SmaugV1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKeyLength { expected, got } => write!(f, "SMAUG-T public key must be {expected} bytes, got {got}"),
            Self::InvalidSecretKeyLength { expected, got } => write!(f, "SMAUG-T secret key must be {expected} bytes, got {got}"),
            Self::InvalidCiphertextLength { expected, got } => write!(f, "SMAUG-T ciphertext must be {expected} bytes, got {got}"),
            Self::InvalidMessageLength { expected, got } => write!(f, "SMAUG-T encapsulation message must be {expected} bytes, got {got}"),
            Self::InvalidSharedSecretLength { expected, got } => write!(f, "SMAUG-T shared secret buffer must be {expected} bytes, got {got}"),
            Self::InvalidSeedLength { expected, got } => write!(f, "SMAUG-T key-generation seed must be {expected} bytes, got {got}"),
            Self::EmptySeed => write!(f, "SMAUG-T key-generation seed must not be empty"),
        }
    }
}

impl std::error::Error for SmaugV1Error {}

/// SMAUG-T v1.2.0 KEM for one parameter set.
#[derive(Clone, Copy, Debug)]
pub struct SmaugTV1 {
    mode: Mode,
    p: &'static Params,
}

impl SmaugTV1 {
    /// Instance for a parameter set (`Mode1`/`Mode3`/`Mode5` = NIST levels
    /// 1/3/5, `ModeT` = TiMER).
    pub const fn new(mode: Mode) -> Self {
        SmaugTV1 { mode, p: Params::for_mode(mode) }
    }

    /// `1`, `3`, `5` → the NIST-level sets; anything else is `None`. TiMER is
    /// reachable only through `new(Mode::ModeT)` so a numeric level can never
    /// select it by accident.
    pub const fn from_level(level: u8) -> Option<Self> {
        match level {
            1 => Some(Self::new(Mode::Mode1)),
            3 => Some(Self::new(Mode::Mode3)),
            5 => Some(Self::new(Mode::Mode5)),
            _ => None,
        }
    }

    pub const fn mode(&self) -> Mode {
        self.mode
    }
    pub const fn params(&self) -> &'static Params {
        self.p
    }
    pub const fn public_key_bytes(&self) -> usize {
        self.p.publickey_bytes()
    }
    pub const fn secret_key_bytes(&self) -> usize {
        self.p.kem_secretkey_bytes()
    }
    pub const fn ciphertext_bytes(&self) -> usize {
        self.p.ciphertext_bytes()
    }
    pub const fn shared_secret_bytes(&self) -> usize {
        SHARED_SECRET_BYTES
    }
    /// Length of the encapsulation message `mu` (`msg_bytes`; 32, or 16 for TiMER).
    pub const fn message_bytes(&self) -> usize {
        self.p.msg_bytes
    }

    /// Randomized key generation. Returns `(public_key, secret_key)`.
    pub fn keygen<R: RngCore>(&self, rng: &mut R) -> (Vec<u8>, Vec<u8>) {
        let mut pk = vec![0u8; self.public_key_bytes()];
        let mut sk = vec![0u8; self.secret_key_bytes()];
        crypto_kem_keypair(self.p, &mut pk, &mut sk, rng).expect(SIZED_FROM_PARAMS);
        (pk, sk)
    }

    /// Deterministic key generation from the reference's two inputs: the
    /// implicit-rejection key `d` (`T_BYTES`) and the IND-CPA seed
    /// (`CRYPTO_BYTES`). This is what the NIST KAT flow calls.
    ///
    /// Compiled only with the `kat-internal` feature: an application is never
    /// offered a seed.
    #[cfg(feature = "kat-internal")]
    pub fn keygen_internal(&self, d: &[u8; T_BYTES], seed: &[u8; CRYPTO_BYTES]) -> (Vec<u8>, Vec<u8>) {
        let mut pk = vec![0u8; self.public_key_bytes()];
        let mut sk = vec![0u8; self.secret_key_bytes()];
        keypair_internal(self.p, &mut pk, &mut sk, d, seed).expect(SIZED_FROM_PARAMS);
        (pk, sk)
    }

    /// Deterministic key generation from a non-empty seed of any length:
    /// `SHAKE-256(seed)` → `d ‖ inner_seed` (`T_BYTES + CRYPTO_BYTES` bytes),
    /// then [`keygen_internal`](Self::keygen_internal). This is the C
    /// binding's `metamui_smaugt_keypair_from_seed`, which the Python binding
    /// calls, and C#'s `SmaugT.GenerateKeyPair(seed)`; the same seed gives the
    /// same keypair in all of them (`tests/seed_keygen_test.rs` pins it).
    ///
    /// An empty seed is [`SmaugV1Error::EmptySeed`]: it would expand to one
    /// fixed, publicly computable keypair, and the C binding refuses it too.
    ///
    /// Compiled only with the `kat-internal` feature: seeded key generation
    /// exists for conformance gates and fixture generators, and an
    /// application is never offered a seed.
    #[cfg(feature = "kat-internal")]
    pub fn keygen_from_seed(&self, seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SmaugV1Error> {
        if seed.is_empty() {
            return Err(SmaugV1Error::EmptySeed);
        }
        let mut buf = [0u8; T_BYTES + CRYPTO_BYTES];
        super::hash::shake256(&mut buf, seed);
        let mut d = [0u8; T_BYTES];
        let mut inner = [0u8; CRYPTO_BYTES];
        d.copy_from_slice(&buf[..T_BYTES]);
        inner.copy_from_slice(&buf[T_BYTES..]);
        Ok(self.keygen_internal(&d, &inner))
    }

    /// Randomized encapsulation. Returns `(ciphertext, shared_secret)`.
    pub fn encapsulate<R: RngCore>(&self, public_key: &[u8], rng: &mut R) -> Result<(Vec<u8>, Vec<u8>), SmaugV1Error> {
        let mut ct = vec![0u8; self.ciphertext_bytes()];
        let mut ss = vec![0u8; SHARED_SECRET_BYTES];
        crypto_kem_enc(self.p, &mut ct, &mut ss, public_key, rng)?;
        Ok((ct, ss))
    }

    /// Deterministic encapsulation from the reference's message `mu`
    /// (`message_bytes()` long). This is what the NIST KAT flow calls.
    ///
    /// Compiled only with the `kat-internal` feature: an application is never
    /// offered the encapsulation message.
    #[cfg(feature = "kat-internal")]
    pub fn encapsulate_internal(&self, public_key: &[u8], mu: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SmaugV1Error> {
        let mut ct = vec![0u8; self.ciphertext_bytes()];
        let mut ss = vec![0u8; SHARED_SECRET_BYTES];
        enc_internal(self.p, &mut ct, &mut ss, public_key, mu)?;
        Ok((ct, ss))
    }

    /// Decapsulation (NIST argument order: secret key, ciphertext). The v1.2.0
    /// secret key embeds the public key, so no separate `pk` is needed.
    /// Implicit rejection: a malformed-but-correct-length ciphertext yields a
    /// pseudorandom secret, never an error.
    pub fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SmaugV1Error> {
        let mut ss = vec![0u8; SHARED_SECRET_BYTES];
        crypto_kem_dec(self.p, &mut ss, ciphertext, secret_key)?;
        Ok(ss)
    }
}

/// `keygen` and `keygen_internal` size both output buffers from the
/// parameter set and take `d`/`seed` as fixed-size arrays, so the length
/// checks inside cannot fail there; no caller-controlled length reaches them.
const SIZED_FROM_PARAMS: &str = "SMAUG-T keygen buffers are sized from the parameter set";
