// MetaMUI Blake2b - backend hook
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The one-shot BLAKE2b-512 backend.
//!
//! Portable scalar code, the same on every target: this crate has no SIMD,
//! assembly or GPU path and no CPU-feature detection, so a digest is computed
//! by the same arithmetic wherever it is produced.
//!
//! # Backend hook
//!
//! The one-shot BLAKE2b-512 entry points (`blake2b_512`, `blake2b_512_hex`,
//! `MetaMUIBlake2b512::hash`) go through the [`Blake2bBackend`] that
//! [`backend`] returns. The default is [`PORTABLE`], the streaming hasher of
//! this crate run over the whole input. A separate crate may install another
//! backend once, with [`install`], before the first one-shot hash of the
//! process; after that the choice is fixed and `install` returns `Err`. A
//! backend must compute the same bytes as [`PORTABLE`] (it is an
//! implementation of the same function, not a different algorithm). This crate
//! ships no other backend.
//!
//! The streaming [`Blake2bHasher`](crate::Blake2bHasher), the 256- and 384-bit
//! outputs, the variable-length and keyed entry points do not consult the
//! backend; they are always the portable code.

use std::sync::OnceLock;

use crate::Blake2b512Hash;

/// A one-shot BLAKE2b-512 implementation.
#[derive(Clone, Copy)]
pub struct Blake2bBackend {
    /// A short name for diagnostics, e.g. `"portable"`.
    pub name: &'static str,
    /// Unkeyed BLAKE2b-512 of the whole input.
    pub blake2b_512: fn(&[u8]) -> Blake2b512Hash,
}

impl core::fmt::Debug for Blake2bBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Blake2bBackend").field("name", &self.name).finish()
    }
}

/// The portable backend: [`Blake2bHasher`](crate::Blake2bHasher) over the
/// whole input. The default, and the oracle any other backend is measured
/// against.
pub static PORTABLE: Blake2bBackend = Blake2bBackend {
    name: "portable",
    blake2b_512: crate::blake2b::native_blake2b512,
};

static BACKEND: OnceLock<&'static Blake2bBackend> = OnceLock::new();

/// The backend in use. Fixes the choice on first call.
pub fn backend() -> &'static Blake2bBackend {
    BACKEND.get_or_init(|| &PORTABLE)
}

/// Install `b` as the process-wide backend.
///
/// Succeeds once, and only before the first call of [`backend`] (which every
/// one-shot BLAKE2b-512 hash makes). Afterwards it returns `Err` with the
/// backend that is in use, and that one stays: a digest must not depend on
/// which call came first.
pub fn install(b: &'static Blake2bBackend) -> Result<(), &'static Blake2bBackend> {
    match BACKEND.set(b) {
        Ok(()) => Ok(()),
        Err(_) => Err(backend()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_portable_and_a_later_install_is_refused() {
        assert_eq!(backend().name, "portable");
        static OTHER: Blake2bBackend = Blake2bBackend {
            name: "other",
            blake2b_512: crate::blake2b::native_blake2b512,
        };
        let refused = install(&OTHER).expect_err("install after first use must be refused");
        assert_eq!(refused.name, "portable");
        assert_eq!(backend().name, "portable");
    }
}
