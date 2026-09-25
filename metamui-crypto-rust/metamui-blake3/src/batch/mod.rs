// BLAKE3 batch API
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd.
// Licensed under the Apache License, Version 2.0

//! Batches of up to 16 independent messages, hashed through the installed
//! [`crate::backend`] (portable unless another was installed). The output
//! is the ordinary BLAKE3 digest of each message.

mod error;
#[cfg(feature = "lthash")]
mod lthash;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::String};

pub use error::Blake3BatchError;
#[cfg(feature = "lthash")]
pub use lthash::{Blake3LtHash, lthash_batch, BLAKE3_LTHASH_SIZE};

/// Digest size in bytes.
pub const BLAKE3_HASH_SIZE: usize = 32;
/// Messages per [`Blake3Batch`].
pub const BLAKE3_AVX512_BATCH_SIZE: usize = 16;

/// BLAKE3 hash output (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Blake3Hash([u8; BLAKE3_HASH_SIZE]);

impl Blake3Hash {
    /// Create a new Blake3Hash from bytes
    pub fn from_bytes(bytes: [u8; BLAKE3_HASH_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the hash as a byte slice
    pub fn as_bytes(&self) -> &[u8; BLAKE3_HASH_SIZE] {
        &self.0
    }

    /// Get the hash as a hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self, Blake3BatchError> {
        let bytes = hex::decode(s).map_err(|_| Blake3BatchError::InvalidHex)?;
        if bytes.len() != BLAKE3_HASH_SIZE {
            return Err(Blake3BatchError::InvalidHashSize);
        }
        let mut hash = [0u8; BLAKE3_HASH_SIZE];
        hash.copy_from_slice(&bytes);
        Ok(Self(hash))
    }
}

impl AsRef<[u8]> for Blake3Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; BLAKE3_HASH_SIZE]> for Blake3Hash {
    fn from(bytes: [u8; BLAKE3_HASH_SIZE]) -> Self {
        Self(bytes)
    }
}



/// Batch hasher for up to 16 messages simultaneously
///
/// # Example
///
/// ```
/// use metamui_blake3::batch::Blake3Batch;
///
/// let mut batch = Blake3Batch::new();
/// batch.add_message(b"Hello, World!");
/// batch.add_message(b"BLAKE3 is fast!");
///
/// let hashes = batch.finalize().unwrap();
/// println!("Hash 1: {}", hashes[0].to_hex());
/// println!("Hash 2: {}", hashes[1].to_hex());
/// ```
pub struct Blake3Batch {
    messages: Vec<Vec<u8>>,
}

impl Blake3Batch {
    /// Create a new batch hasher
    pub fn new() -> Self {
        Self {
            messages: Vec::with_capacity(BLAKE3_AVX512_BATCH_SIZE),
        }
    }

    /// Add a message to the batch
    ///
    /// Returns an error if batch is full (16 messages)
    pub fn add_message(&mut self, message: &[u8]) -> Result<(), Blake3BatchError> {
        if self.messages.len() >= BLAKE3_AVX512_BATCH_SIZE {
            return Err(Blake3BatchError::BatchFull);
        }
        self.messages.push(message.to_vec());
        Ok(())
    }

    /// Get the number of messages in the batch
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Clear the batch
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Finalize and compute hashes for all messages
    ///
    /// Runs the installed backend's `hash_many` (see [`crate::backend`]);
    /// with no backend installed, that is the portable implementation.
    ///
    /// Returns a vector of Blake3Hash values, one for each message.
    pub fn finalize(&self) -> Result<Vec<Blake3Hash>, Blake3BatchError> {
        if self.messages.is_empty() {
            return Err(Blake3BatchError::EmptyBatch);
        }

        let refs: Vec<&[u8]> = self.messages.iter().map(|v| v.as_slice()).collect();
        let mut raw = vec![[0u8; BLAKE3_HASH_SIZE]; refs.len()];
        crate::backend::hash_many(&refs, &mut raw);

        Ok(raw.into_iter().map(Blake3Hash::from).collect())
    }
}

impl Default for Blake3Batch {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch hash multiple messages
///
/// Any number of messages, hashed sixteen at a time through the installed
/// backend.
///
/// # Example
///
/// ```
/// use metamui_blake3::batch::batch_hash;
///
/// let messages = vec![
///     b"Message 1".as_slice(),
///     b"Message 2".as_slice(),
///     b"Message 3".as_slice(),
/// ];
///
/// let hashes = batch_hash(&messages).unwrap();
/// for (i, hash) in hashes.iter().enumerate() {
///     println!("Hash {}: {}", i, hash.to_hex());
/// }
/// ```
pub fn batch_hash(messages: &[&[u8]]) -> Result<Vec<Blake3Hash>, Blake3BatchError> {
    if messages.is_empty() {
        return Err(Blake3BatchError::EmptyBatch);
    }

    // Process in batches of 16
    let mut all_hashes = Vec::with_capacity(messages.len());

    for chunk in messages.chunks(BLAKE3_AVX512_BATCH_SIZE) {
        let mut batch = Blake3Batch::new();
        for msg in chunk {
            batch.add_message(msg)?;
        }
        let hashes = batch.finalize()?;
        all_hashes.extend(hashes);
    }

    Ok(all_hashes)
}

/// Batch hash multiple messages (owned version)
///
/// Same as `batch_hash` but takes owned data.
pub fn batch_hash_owned(messages: Vec<Vec<u8>>) -> Result<Vec<Blake3Hash>, Blake3BatchError> {
    let refs: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();
    batch_hash(&refs)
}

// NOTE: LtHash functions moved to lthash.rs module (opt-in feature)
// Use: `use metamui_blake3::batch::lthash_batch;` with feature = "lthash"

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let hash = Blake3Hash::from_bytes([0u8; BLAKE3_HASH_SIZE]);
        assert_eq!(hash.as_bytes().len(), BLAKE3_HASH_SIZE);
    }

    #[test]
    fn test_blake3_hash_hex() {
        let hash = Blake3Hash::from_bytes([0u8; BLAKE3_HASH_SIZE]);
        let hex = hash.to_hex();
        assert_eq!(hex.len(), BLAKE3_HASH_SIZE * 2);
        let parsed = Blake3Hash::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_batch_new() {
        let batch = Blake3Batch::new();
        assert_eq!(batch.len(), 0);
        assert!(batch.is_empty());
    }

    #[test]
    fn test_batch_add_message() {
        let mut batch = Blake3Batch::new();
        batch.add_message(b"test").unwrap();
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_batch_full() {
        let mut batch = Blake3Batch::new();
        for i in 0..16 {
            batch.add_message(format!("message {}", i).as_bytes()).unwrap();
        }
        assert_eq!(batch.len(), 16);

        // 17th message should fail
        let result = batch.add_message(b"overflow");
        assert!(matches!(result, Err(Blake3BatchError::BatchFull)));
    }

    #[test]
    fn test_batch_hash_single() {
        let messages = vec![b"Hello, BLAKE3!".as_slice()];
        let hashes = batch_hash(&messages).unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].as_bytes().len(), BLAKE3_HASH_SIZE);
    }

    #[test]
    fn test_batch_hash_multiple() {
        let messages = vec![
            b"Message 1".as_slice(),
            b"Message 2".as_slice(),
            b"Message 3".as_slice(),
        ];
        let hashes = batch_hash(&messages).unwrap();
        assert_eq!(hashes.len(), 3);

        // All hashes should be different
        assert_ne!(hashes[0], hashes[1]);
        assert_ne!(hashes[1], hashes[2]);
        assert_ne!(hashes[0], hashes[2]);
    }

    #[test]
    fn test_batch_hash_full() {
        let msg_vecs: Vec<Vec<u8>> = (0..16)
            .map(|i| format!("Message {}", i).into_bytes())
            .collect();
        let messages: Vec<&[u8]> = msg_vecs.iter().map(|v| v.as_slice()).collect();

        let hashes = batch_hash(&messages).unwrap();
        assert_eq!(hashes.len(), 16);
    }

    #[test]
    fn test_batch_hash_deterministic() {
        let messages = vec![b"test".as_slice()];
        let hashes1 = batch_hash(&messages).unwrap();
        let hashes2 = batch_hash(&messages).unwrap();
        assert_eq!(hashes1[0], hashes2[0]);
    }

}
