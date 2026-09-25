//! Compatibility shim matching the `blake3` crate (crates.io) API.
//!
//! Consumers can replace `blake3 = "1.5"` with `metamui-blake3` and then:
//! ```ignore
//! // In Cargo.toml:  blake3 = { package = "metamui-blake3", ... }
//! //   -OR-
//! // In source:      use metamui_blake3::compat as blake3;
//!
//! let h = blake3::hash(b"data");
//! let bytes: [u8; 32] = h.into();
//! ```
//!
//! This module re-exports types and free functions that mirror the API of
//! `blake3` v1.x from crates.io so that call sites require zero changes.

use crate::{Blake3Hash, Blake3Key, MetaMUIBlake3};

// ============================================================================
// Hash output type (mirrors `blake3::Hash`)
// ============================================================================

/// BLAKE3 hash output, API-compatible with `blake3::Hash`.
#[derive(Clone, PartialEq, Eq)]
pub struct Hash(Blake3Hash);

impl Hash {
    /// Get a reference to the hash bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        // Safety: Blake3Hash inner is `[u8; 32]`, we cast the slice reference
        // to a fixed-size array reference.
        self.0.as_bytes().try_into().expect("Blake3Hash is always 32 bytes")
    }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Hash({})", self.0.to_hex())
    }
}

impl core::fmt::Display for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0.to_hex())
    }
}

impl From<Hash> for [u8; 32] {
    fn from(h: Hash) -> [u8; 32] {
        h.0.to_bytes()
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

// ============================================================================
// Free functions (mirrors `blake3::hash`, `blake3::keyed_hash`)
// ============================================================================

/// Hash the given input bytes, returning a [`Hash`](struct@Hash).
///
/// Drop-in replacement for `blake3::hash()`.
pub fn hash(input: &[u8]) -> Hash {
    Hash(MetaMUIBlake3::new().hash(input))
}

/// Compute a keyed hash of the given input bytes, returning a [`Hash`](struct@Hash).
///
/// Drop-in replacement for `blake3::keyed_hash()`.
pub fn keyed_hash(key: &[u8; 32], input: &[u8]) -> Hash {
    Hash(MetaMUIBlake3::hash_keyed(&Blake3Key::new(*key), input))
}

// ============================================================================
// Hasher (mirrors `blake3::Hasher`)
// ============================================================================

/// Incremental BLAKE3 hasher, API-compatible with `blake3::Hasher`.
pub struct Hasher(MetaMUIBlake3);

impl Hasher {
    /// Create a new `Hasher` for the default hash function.
    pub fn new() -> Self {
        Hasher(MetaMUIBlake3::new())
    }

    /// Create a new keyed `Hasher`.
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Hasher(MetaMUIBlake3::new_keyed(&Blake3Key::new(*key)))
    }

    /// Create a new `Hasher` for key derivation.
    pub fn new_derive_key(context: &str) -> Self {
        Hasher(MetaMUIBlake3::new_derive_key(context))
    }

    /// Add input bytes to the hash state.
    pub fn update(&mut self, input: &[u8]) -> &mut Self {
        self.0.update(input);
        self
    }

    /// Finalize the hash state and return the [`Hash`](struct@Hash) output.
    pub fn finalize(&self) -> Hash {
        Hash(self.0.finalize())
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_matches_metamui_blake3() {
        let data = b"hello world";
        let compat_hash = hash(data);
        let native_hash = MetaMUIBlake3::new().hash(data);
        assert_eq!(compat_hash.as_bytes(), native_hash.as_bytes());
    }

    #[test]
    fn test_hash_into_array() {
        let h = hash(b"test");
        let arr: [u8; 32] = h.into();
        assert_eq!(&arr, hash(b"test").as_bytes());
    }

    #[test]
    fn test_keyed_hash_works() {
        let key = [42u8; 32];
        let h = keyed_hash(&key, b"data");
        assert_ne!(h.as_bytes(), hash(b"data").as_bytes());
    }

    #[test]
    fn test_hasher_incremental() {
        let mut hasher = Hasher::new();
        hasher.update(b"hello ").update(b"world");
        let incremental = hasher.finalize();
        let direct = hash(b"hello world");
        assert_eq!(incremental.as_bytes(), direct.as_bytes());
    }

    #[test]
    fn test_hasher_keyed() {
        let key = [1u8; 32];
        let mut hasher = Hasher::new_keyed(&key);
        hasher.update(b"data");
        let h = hasher.finalize();
        let direct = keyed_hash(&key, b"data");
        assert_eq!(h.as_bytes(), direct.as_bytes());
    }
}
