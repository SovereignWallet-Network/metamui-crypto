// MetaMUI BLAKE3 - backend hook
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The backend hook of the many-input and tree paths.
//!
//! Every code path in this crate is portable Rust, the same on every target:
//! there is no SIMD, assembly or GPU path and no CPU-feature detection. The
//! single-message API (`hash`, `keyed_hash`, `Hasher`, [`crate::MetaMUIBlake3`])
//! runs the compression function in [`crate::blake3`] directly and has no
//! hook. The two operations that an accelerated implementation would
//! vectorise across inputs go through the [`Backend`] that [`backend`]
//! returns:
//!
//! * [`Backend::hash_many`] — the 32-byte BLAKE3 digest of each of several
//!   independent inputs (behind [`hash_many`], `batch::batch_hash` and
//!   `parallel::ParallelHasher::hash_many`);
//! * [`Backend::chunk_cvs`] — the chaining value of each of several
//!   consecutive chunks of one message, for the tree hash in `parallel`.
//!
//! The default is [`PORTABLE`], the implementations in [`portable`]. A
//! separate crate may install another backend once, with [`install`], before
//! the first many-input operation of the process; after that the choice is
//! fixed and `install` returns `Err` with the backend in use, which stays. A
//! backend must reproduce the portable output exactly, for every input: it is
//! an implementation of the same function, not a different one. The official
//! vectors in `tests/kat_vectors.rs` run through the dispatching functions,
//! so a backend installed before that gate is measured by it. This crate
//! ships no other backend.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::blake3;
use crate::HASH_SIZE;

/// Function-pointer table of the two many-input operations.
///
/// Both write into a caller-provided output slice of the same length as the
/// input slice; a backend must not assume any alignment of the inputs.
pub struct Backend {
    /// A short name for diagnostics, e.g. `"portable"`.
    pub name: &'static str,
    /// `out[i]` = BLAKE3 (unkeyed, 32-byte) of `inputs[i]`.
    pub hash_many: fn(inputs: &[&[u8]], out: &mut [[u8; HASH_SIZE]]),
    /// `out[i]` = the chaining value of chunk `first_counter + i`, whose
    /// bytes are `chunks[i]` (at most 1024, only the last may be shorter),
    /// compressed with `key` and the mode `flags` (0, `KEYED_HASH`,
    /// `DERIVE_KEY_*`) and never `ROOT`.
    pub chunk_cvs: fn(chunks: &[&[u8]], key: &[u32; 8], flags: u32, first_counter: u64, out: &mut [[u32; 8]]),
}

impl core::fmt::Debug for Backend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Backend").field("name", &self.name).finish()
    }
}

/// The portable implementations, the default backend and the oracle any
/// other backend is measured against.
pub mod portable {
    use super::*;

    /// One [`crate::blake3::Blake3Hasher`] per input.
    pub fn hash_many(inputs: &[&[u8]], out: &mut [[u8; HASH_SIZE]]) {
        assert_eq!(inputs.len(), out.len(), "hash_many: output length");
        for (input, slot) in inputs.iter().zip(out.iter_mut()) {
            *slot = blake3::native_blake3(input);
        }
    }

    /// [`crate::blake3::chunk_cv`] per chunk.
    pub fn chunk_cvs(chunks: &[&[u8]], key: &[u32; 8], flags: u32, first_counter: u64, out: &mut [[u32; 8]]) {
        assert_eq!(chunks.len(), out.len(), "chunk_cvs: output length");
        for (i, (chunk, slot)) in chunks.iter().zip(out.iter_mut()).enumerate() {
            *slot = blake3::chunk_cv(chunk, key, first_counter + i as u64, flags);
        }
    }
}

/// The portable backend: [`portable`], field by field.
pub static PORTABLE: Backend = Backend {
    name: "portable",
    hash_many: portable::hash_many,
    chunk_cvs: portable::chunk_cvs,
};

// An atomic pointer rather than `OnceLock` so the hook exists under
// `no_std` too; there is nothing to install there, so it only ever holds
// `PORTABLE`, but the code is the same on every target.
static BACKEND: AtomicPtr<Backend> = AtomicPtr::new(core::ptr::null_mut());

/// The backend in use: what [`install`] set, or [`PORTABLE`].
///
/// The first call fixes the choice for the rest of the process.
#[inline]
pub fn backend() -> &'static Backend {
    let p = BACKEND.load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: only `set` stores here, and only `&'static Backend`.
        return unsafe { &*p };
    }
    match set(&PORTABLE) {
        Ok(()) => &PORTABLE,
        Err(b) => b,
    }
}

fn set(b: &'static Backend) -> Result<(), &'static Backend> {
    let new = b as *const Backend as *mut Backend;
    match BACKEND.compare_exchange(core::ptr::null_mut(), new, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(()),
        // SAFETY: as in `backend`.
        Err(prev) => Err(unsafe { &*prev }),
    }
}

/// Install `b` as the process-wide backend.
///
/// Succeeds once, and only before the first call of [`backend`] (which every
/// many-input operation makes). Afterwards it returns `Err` with the backend
/// that is in use, and that one stays: a digest must not depend on which
/// call came first.
pub fn install(b: &'static Backend) -> Result<(), &'static Backend> {
    set(b)
}

/// `hash_many` of the installed backend (see [`backend`]).
#[inline]
pub fn hash_many(inputs: &[&[u8]], out: &mut [[u8; HASH_SIZE]]) {
    (backend().hash_many)(inputs, out)
}

/// `chunk_cvs` of the installed backend (see [`backend`]).
#[inline]
pub fn chunk_cvs(chunks: &[&[u8]], key: &[u32; 8], flags: u32, first_counter: u64, out: &mut [[u32; 8]]) {
    (backend().chunk_cvs)(chunks, key, flags, first_counter, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_is_the_default_and_install_is_refused_after_first_use() {
        // Any earlier test in this binary may already have fixed the backend;
        // either way it is the portable one, because nothing here installs another.
        assert_eq!(backend().name, "portable");
        static OTHER: Backend = Backend { name: "other", ..PORTABLE };
        assert_eq!(install(&OTHER).unwrap_err().name, "portable");
        assert_eq!(backend().name, "portable");
    }

    #[test]
    fn wrappers_reach_the_portable_functions() {
        let inputs: [&[u8]; 3] = [b"", b"abc", &[7u8; 5000]];
        let mut out = [[0u8; HASH_SIZE]; 3];
        hash_many(&inputs, &mut out);
        for (input, digest) in inputs.iter().zip(out.iter()) {
            assert_eq!(digest, &blake3::native_blake3(input));
        }

        let data = [0x5au8; 2500];
        let chunks: [&[u8]; 3] = [&data[..1024], &data[1024..2048], &data[2048..]];
        let mut cvs = [[0u32; 8]; 3];
        chunk_cvs(&chunks, &blake3::IV, 0, 0, &mut cvs);
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(cvs[i], blake3::chunk_cv(chunk, &blake3::IV, i as u64, 0));
        }
    }
}
