// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// Licensed under the Apache License, Version 2.0

//! SMAUG-T — Module-LWR key encapsulation (KpqC competition winner).
//!
//! One implementation, one wire format: the **v1.2.0 standard KEM**, byte-exact
//! to the CryptoLab reference vectors (`test-vectors/smaug-t/v1.2.0-kat/*.json`,
//! converted from the authors' `.rsp` files)
//! and to the nine other language bindings.
//!
//! ## Which API to use
//!
//! * [`SmaugTV1`] — the reference-shaped API, taking and returning `Vec<u8>`
//!   and selected by [`SmaugV1Mode`]. Prefer it for new code.
//! * [`SmaugT`] — the same algorithm behind this crate's newtypes
//!   ([`PublicKey`], [`SecretKey`], [`Ciphertext`], [`SharedSecret`]), for
//!   callers that want the typed surface. It is a thin facade; there is no
//!   behavioural difference.
//!
//! Sizes are 672/832/672 (Level 1), 1088/1312/992 (Level 3) and
//! 1440/1728/1376 (Level 5), as public key / secret key / ciphertext. TiMER is
//! reachable only as [`SmaugV1Mode::ModeT`] or [`SecurityLevel::LevelT`], never
//! through a numeric level, so it cannot be selected by accident.
//!
//! ## History
//!
//! Until 2026-09 `SmaugT` routed to a 2023 draft core with power-of-two moduli
//! (q=1024/2048) whose wire format matched no other binding and whose Level-1
//! message-recovery rate sat near 85–90 %. A conformant KEM has negligible
//! decapsulation failure. That core, its SIMD/GPU/parallel backends and its
//! `test-vectors/smaug-t/upstream-kat/` regression net are deleted; `SmaugT`
//! now means the standard, and its `decapsulate` takes the NIST argument pair
//! `(secret_key, ciphertext)` rather than the old `(ct, sk, pk)` triple — an
//! arity change, so a stale caller fails to compile instead of silently
//! changing bytes on the wire.
//!
//! There is no "SMAUG-T v4.0"; this banner claimed one for a year. This crate
//! implements reference implementation v1.2.0 (specification v260521,
//! 2026-05-21), which fixed the v1.1.1 discrete-Gaussian tape unpacking bug
//! (`src/dg.c`); every key and ciphertext byte differs from v1.1.1.
//!
//! ## Mathematical foundation
//!
//! Module Learning With Rounding over structured polynomial rings with sparse
//! secret keys, with the Fujisaki-Okamoto transform and implicit rejection for
//! IND-CCA2 security.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use metamui_smaug_t::{SmaugTV1, SmaugV1Mode};
//! use rand_core::OsRng;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let smaug = SmaugTV1::new(SmaugV1Mode::Mode3);
//! let (public_key, secret_key) = smaug.keygen(&mut OsRng);
//! let (ciphertext, ss_alice) = smaug.encapsulate(&public_key, &mut OsRng)?;
//! let ss_bob = smaug.decapsulate(&secret_key, &ciphertext)?;
//! assert_eq!(ss_alice, ss_bob);
//! # Ok(())
//! # }
//! ```

// Link the wasm32 `getrandom` backend. This crate is a cdylib, so cargo links
// it for wasm32 and that link needs `__getrandom_custom` resolved; the
// definition lives in `metamui-getrandom-unavailable`. An unreferenced
// dependency is never loaded, and therefore never linked, so the import is
// what pulls the rlib in — `as _` because only its linkage is wanted.
#[cfg(target_arch = "wasm32")]
use metamui_getrandom_unavailable as _;

use rand_core::OsRng;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The v1.2.0 (KpqC standard) KEM, in the shape of the upstream reference.
pub mod smaug_v1_2_0;

pub use smaug_v1_2_0::{Mode as SmaugV1Mode, SmaugTV1, SmaugV1Error};

#[cfg(feature = "serde_feature")]
use serde::{Deserialize, Serialize};

/// SMAUG-T parameter sets.
///
/// `Level1`/`Level3`/`Level5` are the NIST-level sets. `LevelT` is TiMER, which
/// [`SmaugTV1::from_level`] deliberately refuses to select from a number; it is
/// named here for the same reason, so it can only be chosen on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde_feature", derive(Serialize, Deserialize))]
#[repr(u32)]
pub enum SecurityLevel {
    /// Level 1: 128-bit security (NIST Level 1)
    Level1 = 1,
    /// Level 3: 192-bit security (NIST Level 3)
    Level3 = 3,
    /// Level 5: 256-bit security (NIST Level 5)
    Level5 = 5,
    /// TiMER — the compact set, not a NIST level.
    LevelT = 0,
}

impl SecurityLevel {
    /// The `smaug_v1_2_0` mode this level selects.
    pub const fn mode(self) -> SmaugV1Mode {
        match self {
            SecurityLevel::Level1 => SmaugV1Mode::Mode1,
            SecurityLevel::Level3 => SmaugV1Mode::Mode3,
            SecurityLevel::Level5 => SmaugV1Mode::Mode5,
            SecurityLevel::LevelT => SmaugV1Mode::ModeT,
        }
    }
}

// Re-export for backward compatibility
pub use SecurityLevel as SmaugLevel;

/// SMAUG-T error types
#[derive(Error, Debug)]
pub enum SmaugError {
    #[error("Invalid parameters")]
    InvalidParams,

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Memory allocation failed")]
    MemoryError,

    #[error("Decapsulation failed")]
    DecapsulationFailed,

    #[error("FFI error: {0}")]
    FfiError(String),
}

impl From<SmaugV1Error> for SmaugError {
    fn from(e: SmaugV1Error) -> Self {
        SmaugError::InvalidInput(e.to_string())
    }
}

/// SMAUG-T public key
#[derive(Clone)]
pub struct PublicKey(pub Vec<u8>);

impl PublicKey {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// SMAUG-T secret key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub Vec<u8>);

impl SecretKey {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// SMAUG-T ciphertext
#[derive(Clone)]
pub struct Ciphertext(pub Vec<u8>);

impl Ciphertext {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Shared secret (32 bytes)
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

impl SharedSecret {
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SharedSecret {}

/// SMAUG-T v1.2.0 behind this crate's newtypes.
///
/// A thin facade over [`SmaugTV1`] — same algorithm, same bytes. Use whichever
/// surface suits the caller.
pub struct SmaugT {
    level: SecurityLevel,
    inner: SmaugTV1,
}

impl SmaugT {
    /// Create an instance for `level`.
    pub fn new(level: SecurityLevel) -> Result<Self, SmaugError> {
        Ok(Self { level, inner: SmaugTV1::new(level.mode()) })
    }

    /// The parameter set this instance uses.
    pub fn level(&self) -> SecurityLevel {
        self.level
    }

    /// The underlying reference-shaped API.
    pub fn v1(&self) -> &SmaugTV1 {
        &self.inner
    }

    /// Generate a keypair from operating-system randomness.
    pub fn keygen(&self) -> Result<(PublicKey, SecretKey), SmaugError> {
        let (pk, sk) = self.inner.keygen(&mut OsRng);
        Ok((PublicKey(pk), SecretKey(sk)))
    }

    /// Generate a keypair deterministically from `seed`.
    ///
    /// The seed expansion is the cross-binding convention shared with the
    /// Python, Go, Java, Kotlin, C# and TypeScript ports; it is **not** the
    /// NIST KAT DRBG. For byte-equality against the reference vectors
    /// use [`SmaugTV1::keygen_internal`].
    ///
    /// Compiled only with the `kat-internal` feature: seeded key generation
    /// exists for conformance gates and fixture generators, and an
    /// application is never offered a seed.
    #[cfg(feature = "kat-internal")]
    pub fn keygen_from_seed(&self, seed: &[u8; 32]) -> Result<(PublicKey, SecretKey), SmaugError> {
        let (pk, sk) = self.inner.keygen_from_seed(seed);
        Ok((PublicKey(pk), SecretKey(sk)))
    }

    /// Encapsulate to `public_key`, returning the ciphertext and shared secret.
    pub fn encapsulate(
        &self,
        public_key: &PublicKey,
    ) -> Result<(Ciphertext, SharedSecret), SmaugError> {
        let (ct, ss) = self.inner.encapsulate(&public_key.0, &mut OsRng)?;
        Ok((Ciphertext(ct), Self::shared_secret(ss)?))
    }

    /// Recover the shared secret.
    ///
    /// NIST argument order: the secret key embeds the public key, so no
    /// separate public key is taken. The pre-2026-09 signature was
    /// `decapsulate(&Ciphertext, &SecretKey, &PublicKey)`; a caller written
    /// against it fails to compile rather than silently changing wire bytes.
    pub fn decapsulate(
        &self,
        secret_key: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> Result<SharedSecret, SmaugError> {
        let ss = self.inner.decapsulate(&secret_key.0, &ciphertext.0)?;
        Self::shared_secret(ss)
    }

    /// Expected public key length for this level.
    pub fn public_key_size(&self) -> usize {
        self.inner.public_key_bytes()
    }

    /// Expected secret key length for this level.
    pub fn secret_key_size(&self) -> usize {
        self.inner.secret_key_bytes()
    }

    /// Expected ciphertext length for this level.
    pub fn ciphertext_size(&self) -> usize {
        self.inner.ciphertext_bytes()
    }

    fn shared_secret(bytes: Vec<u8>) -> Result<SharedSecret, SmaugError> {
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            SmaugError::InvalidInput(format!(
                "shared secret is {} bytes, expected 32",
                bytes.len()
            ))
        })?;
        Ok(SharedSecret(arr))
    }
}
