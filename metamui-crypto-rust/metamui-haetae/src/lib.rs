//! HAETAE: the KpqC lattice-based signature scheme
//!
//! A port of the official HAETAE v1.2.0 reference implementation (Team
//! HAETAE, CryptoLab), transcribed function for function so that keys and
//! signatures match the reference byte-for-byte. The crate compiles one
//! parameter set at a time:
//!
//! - HAETAE-2: NIST category 1 (feature: haetae2, the default)
//! - HAETAE-3: NIST category 3 (feature: haetae3)
//! - HAETAE-5: NIST category 5 (feature: haetae5)
//!
//! The seeded entry points the upstream KAT harness replays —
//! `sign::crypto_sign_keypair_internal(seed)` and
//! `sign::crypto_sign_signature_internal(.., rnd, ..)` — are compiled only
//! with the `kat-internal` feature; an application is never offered a seed.
//! `api::KeyPair`, `api::SigningKey` and `api::VerifyingKey` are the
//! application surface.
//!
//! # Example
//!
//! ```rust,ignore
//! use metamui_haetae::{KeyPair, Error};
//!
//! let keypair = KeyPair::generate()?;
//! let signature = keypair.sign(b"hello")?;
//! keypair.verify(b"hello", &signature)?;
//! # Ok::<(), Error>(())
//! ```

// HAETAE is an internal PQC algorithm crate containing many
// spec-defined constants and polynomial-arithmetic fields whose names
// match the HAETAE spec directly (params.rs, signing.rs, sampling.rs).
// Re-enable `#![warn(missing_docs)]` once the public API surface is
// stabilized and the audit-review pass has annotated the spec-level
// constants.
#![allow(missing_docs)]
// Note: unsafe code is used by the rANS entropy coder (rans_byte.rs,
// encoding.rs), a transcription of the reference's pointer-walking coder.
#![deny(clippy::all)]

// Compile-time check: Ensure exactly one security level is enabled
#[cfg(all(feature = "haetae2", feature = "haetae3"))]
compile_error!("Cannot enable both haetae2 and haetae3. Choose one security level.");

#[cfg(all(feature = "haetae2", feature = "haetae5"))]
compile_error!("Cannot enable both haetae2 and haetae5. Choose one security level.");

#[cfg(all(feature = "haetae3", feature = "haetae5"))]
compile_error!("Cannot enable both haetae3 and haetae5. Choose one security level.");

#[cfg(not(any(feature = "haetae2", feature = "haetae3", feature = "haetae5")))]
compile_error!("At least one security level (haetae2, haetae3, or haetae5) must be enabled.");

pub mod params;
pub mod reduce;
pub mod poly;
pub mod ntt;
pub mod fft;
pub mod polyvec;
pub mod sampling;
pub mod shake;
pub mod polymat;
pub mod packing;
pub mod randombytes;
pub mod fixpoint;
pub mod polyfix;
pub mod sign;
pub mod rans_byte;
pub mod encoding;
pub mod api;

// Re-export commonly used types and constants
pub use params::{SecurityLevel, N, Q, DQ, SEEDBYTES, CRHBYTES};
pub use poly::Poly;
pub use fft::Complex;
pub use polyvec::{PolyVecK, PolyVecL, PolyVecM};

// Re-export high-level API types
pub use api::{KeyPair, SigningKey, VerifyingKey, ExpandedVerifyingKey, Signature, Error};
