//! MetaMUI SHAKE XOF Family: SHAKE-128 and SHAKE-256
//!
//! Pure Rust implementations of the SHAKE extendable-output functions
//! (FIPS 202) based on the Keccak-f[1600] sponge construction.
//!
//! # Usage
//!
//! ```
//! use metamui_shake::{shake128, shake256};
//!
//! let output_128 = shake128(b"input", 32);
//! let output_256 = shake256(b"input", 32);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod cshake;
pub mod keccak;
pub mod kmac;
pub mod shake128;
pub mod shake256;

// Top-level convenience re-exports
pub use cshake::{cshake128, cshake256, Cshake128, Cshake256};
pub use keccak::{keccak_f1600, KeccakReader, KeccakSponge};
pub use kmac::{kmac128, kmac256, kmacxof128, kmacxof256, Kmac128, Kmac256};
pub use shake128::{shake128, Shake128, Shake128Reader};
pub use shake256::{shake256, Shake256, Shake256Reader};
