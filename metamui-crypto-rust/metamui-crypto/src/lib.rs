//! MetaMUI Crypto — the public facade.
//!
//! This crate is the small entry surface over the validated algorithm crates
//! in this workspace. It exposes **explicit profiles** — a profile is one
//! algorithm, one parameter set and one wire encoding, named by the same
//! identifier the release catalog uses (`falcon-512.r3-compressed`,
//! `falcon-512.r3-padded`, `ml-kem-768`) — and nothing else:
//!
//! * no algorithm is selected by default, by number, or by string prefix;
//! * every byte boundary (key, signature, ciphertext, shared secret) is a typed
//!   value whose constructor checks the exact length and the format header;
//! * verification returns `Result<(), Error>`, never a boolean;
//! * every operation that needs randomness takes a caller-supplied
//!   `RngCore + CryptoRng`; there is no deterministic, seeded or
//!   known-answer-test entry point in this crate (the `*_os` helpers under the
//!   `std` feature draw from the operating system);
//! * secret material is zeroized on drop and never printed by `Debug`;
//! * no KEM/KDF/AEAD composition is offered: `mlkem768::SharedSecret` is a
//!   raw 32-byte KEM output, not a session key or an authenticated channel.
//!
//! The encodings each profile pins are documented on its module
//! ([`falcon512`], [`mlkem768`]) and in `README.md`. Algorithms outside the
//! three profiles above are reachable only through their own crates until
//! they are admitted here.
//!
//! ```
//! use metamui_crypto::{falcon512, mlkem768, Profile};
//!
//! let mut rng = rand::rngs::OsRng;
//! // Falcon-512, Round-3 padded profile: fixed 666-byte signatures.
//! let kp = falcon512::generate_keypair(&mut rng)?;
//! let sig = falcon512::sign_padded(&kp.secret_key, b"hello", &mut rng)?;
//! falcon512::verify_padded(&kp.public_key, b"hello", &sig)?;
//!
//! // ML-KEM-768: raw FIPS 203 encapsulation.
//! let kem = mlkem768::generate_keypair(&mut rng)?;
//! let (ct, ss_sender) = mlkem768::encapsulate(&kem.encapsulation_key, &mut rng)?;
//! let ss_receiver = mlkem768::decapsulate(&kem.decapsulation_key, &ct)?;
//! assert_eq!(ss_sender, ss_receiver);
//!
//! // Profiles are selected explicitly and unknown ones are refused.
//! assert_eq!(Profile::parse("ml-kem-768")?, Profile::MlKem768);
//! assert!(Profile::parse("ml-kem-512").is_err());
//! # Ok::<(), metamui_crypto::Error>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
pub mod falcon512;
pub mod mlkem768;
pub mod profile;

pub use error::{Error, LengthRule};
pub use profile::{Kind, Profile};
pub use rand_core::{CryptoRng, RngCore};

/// Probe the operating-system randomness source and hand it back.
///
/// `OsRng::fill_bytes` aborts the process when the source fails; the `*_os`
/// entry points probe with `try_fill_bytes` first so an unavailable source
/// is reported as [`Error::EntropyUnavailable`] before any key material is
/// derived. A failure after a successful probe still aborts rather than
/// continuing with short randomness — failing closed is the contract.
#[cfg(feature = "std")]
pub(crate) fn os_rng() -> Result<rand::rngs::OsRng, Error> {
    use rand_core::RngCore as _;
    let mut rng = rand::rngs::OsRng;
    let mut probe = [0u8; 8];
    rng.try_fill_bytes(&mut probe).map_err(|_| Error::EntropyUnavailable)?;
    Ok(rng)
}

/// Check that `bytes` has exactly `expected` bytes.
pub(crate) fn expect_len(what: &'static str, bytes: &[u8], expected: usize) -> Result<(), Error> {
    if bytes.len() != expected {
        return Err(Error::InvalidLength {
            what,
            expected: LengthRule::Exactly(expected),
            actual: bytes.len(),
        });
    }
    Ok(())
}

/// Check that the first byte of `bytes` is the format header `expected`.
///
/// Callers check the length first, so `bytes` is never empty here; an empty
/// slice is still reported as a header mismatch rather than a panic.
pub(crate) fn expect_header(what: &'static str, bytes: &[u8], expected: u8) -> Result<(), Error> {
    match bytes.first() {
        Some(&actual) if actual == expected => Ok(()),
        Some(&actual) => Err(Error::InvalidHeader { what, expected, actual }),
        None => Err(Error::InvalidLength {
            what,
            expected: LengthRule::Between { min: 1, max: usize::MAX },
            actual: 0,
        }),
    }
}
