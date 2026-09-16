//! The single error type of the facade.
//!
//! Errors name *what* was wrong (which boundary, which length rule, which
//! header byte) so a caller can report a malformed input precisely. A failed
//! signature verification is deliberately opaque: [`Error::InvalidSignature`]
//! carries no detail about *why* the signature was rejected.

use core::fmt;

/// A length constraint on a byte boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthRule {
    /// Exactly this many bytes.
    Exactly(usize),
    /// Any length in the inclusive range.
    Between {
        /// Inclusive lower bound.
        min: usize,
        /// Inclusive upper bound.
        max: usize,
    },
}

impl fmt::Display for LengthRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LengthRule::Exactly(n) => write!(f, "exactly {n} bytes"),
            LengthRule::Between { min, max } => write!(f, "between {min} and {max} bytes"),
        }
    }
}

/// Every failure the facade reports.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The requested profile identifier is not one this facade implements.
    ///
    /// This is also the answer for profiles that exist in the release catalog
    /// but are not admitted to the facade yet: nothing is substituted.
    UnsupportedProfile {
        /// The identifier as the caller supplied it.
        requested: alloc::string::String,
    },
    /// A byte boundary had the wrong length.
    InvalidLength {
        /// Which boundary (`"falcon-512 public key"`, `"ml-kem-768 ciphertext"`, …).
        what: &'static str,
        /// The rule the input had to satisfy.
        expected: LengthRule,
        /// The length actually supplied.
        actual: usize,
    },
    /// A byte boundary had the wrong format header byte.
    InvalidHeader {
        /// Which boundary.
        what: &'static str,
        /// The header byte the profile requires.
        expected: u8,
        /// The header byte actually supplied.
        actual: u8,
    },
    /// The bytes had the right length and header but do not decode to a key
    /// of this profile (for example an out-of-range coefficient, or an
    /// ML-KEM decapsulation key whose embedded hash does not match).
    MalformedKey {
        /// Which key.
        what: &'static str,
    },
    /// The signature does not verify under the given key and message.
    ///
    /// Intentionally carries no reason.
    InvalidSignature,
    /// Signing failed in the backend (for example the key is outside the
    /// sampler's sigma band after the backend's retry budget).
    SigningFailed {
        /// Backend reason, for diagnostics only.
        reason: &'static str,
    },
    /// Key generation failed in the backend.
    KeyGenerationFailed {
        /// Backend reason, for diagnostics only.
        reason: &'static str,
    },
    /// The operating-system randomness source refused a request, so an
    /// `*_os` entry point did nothing.
    EntropyUnavailable,
    /// Encapsulation failed in the backend.
    EncapsulationFailed {
        /// Backend reason, for diagnostics only.
        reason: &'static str,
    },
}

extern crate alloc;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedProfile { requested } => {
                write!(f, "unsupported profile {requested:?}")
            }
            Error::InvalidLength { what, expected, actual } => {
                write!(f, "{what}: expected {expected}, got {actual}")
            }
            Error::InvalidHeader { what, expected, actual } => {
                write!(f, "{what}: expected header 0x{expected:02x}, got 0x{actual:02x}")
            }
            Error::MalformedKey { what } => write!(f, "{what}: malformed"),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::SigningFailed { reason } => write!(f, "signing failed: {reason}"),
            Error::KeyGenerationFailed { reason } => write!(f, "key generation failed: {reason}"),
            Error::EntropyUnavailable => write!(f, "operating-system randomness unavailable"),
            Error::EncapsulationFailed { reason } => write!(f, "encapsulation failed: {reason}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
