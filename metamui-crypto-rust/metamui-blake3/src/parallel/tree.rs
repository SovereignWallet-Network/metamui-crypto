// MetaMUI Blake3 Parallel Tree Hashing
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.
// Licensed under the Apache License, Version 2.0

//! Multi-threaded BLAKE3 tree hashing of one message
//!
//! BLAKE3 hashes a message as a binary tree over 1 KiB chunks, so the chunks
//! of a large message can be compressed independently and their chaining
//! values merged afterwards. [`hash`] and [`hash_keyed`] do exactly that:
//! the chunk chaining values come from the installed [`crate::backend`]'s
//! `chunk_cvs` (the portable implementation unless another was installed),
//! on Rayon's pool, and the parents are merged level by level. The digest is
//! the ordinary BLAKE3 digest — the same bytes as [`crate::hash`] — and the
//! official vectors (`tests/kat_vectors.rs`) check it on every case.
//!
//! # Example
//!
//! ```rust
//! let large_data = vec![0u8; 10_000_000];
//! let hash = metamui_blake3::parallel::hash(&large_data);
//! assert_eq!(&hash, metamui_blake3::hash(&large_data).as_bytes());
//! ```

use crate::blake3::{self, Blake3Hasher, CHUNK_LEN, IV, KEYED_HASH, ROOT};
use crate::HASH_SIZE;

use rayon::prelude::*;

/// Chunk size for Blake3 tree hashing (1024 bytes)
pub const CHUNK_SIZE: usize = CHUNK_LEN;

/// Minimum data size to use parallelization (16 KB)
/// Below this threshold, single-threaded is faster due to overhead
const PARALLEL_THRESHOLD: usize = 16 * 1024;

/// Chunks handed to one `chunk_cvs` call of the backend; a Rayon task each.
const BATCH_CHUNKS: usize = 16;

fn words_to_bytes(cv: &[u32; 8]) -> [u8; HASH_SIZE] {
    let mut out = [0u8; HASH_SIZE];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&cv[i].to_le_bytes());
    }
    out
}

/// Chaining values of every chunk of `data` (at least two chunks), in order,
/// through the backend; `data.len() > CHUNK_LEN`.
fn chunk_cvs(data: &[u8], key: &[u32; 8], flags: u32, parallel: bool) -> Vec<[u32; 8]> {
    let chunks: Vec<&[u8]> = data.chunks(CHUNK_LEN).collect();
    let mut cvs = vec![[0u32; 8]; chunks.len()];
    let batch = |(i, (chunks, out)): (usize, (&[&[u8]], &mut [[u32; 8]]))| {
        crate::backend::chunk_cvs(chunks, key, flags, (i * BATCH_CHUNKS) as u64, out);
    };
    if parallel {
        chunks
            .par_chunks(BATCH_CHUNKS)
            .zip(cvs.par_chunks_mut(BATCH_CHUNKS))
            .enumerate()
            .for_each(batch);
    } else {
        chunks
            .chunks(BATCH_CHUNKS)
            .zip(cvs.chunks_mut(BATCH_CHUNKS))
            .enumerate()
            .for_each(batch);
    }
    cvs
}

/// Merge one level of the tree: adjacent pairs become parents, an odd last
/// node is carried up unchanged. `root` marks the final merge of two nodes.
fn merge_level(level: &[[u32; 8]], key: &[u32; 8], flags: u32, parallel: bool) -> Vec<[u32; 8]> {
    let root = if level.len() == 2 { ROOT } else { 0 };
    let parent = |pair: &[[u32; 8]]| {
        if pair.len() == 2 {
            blake3::parent_cv(&pair[0], &pair[1], key, flags | root)
        } else {
            pair[0]
        }
    };
    if parallel {
        level.par_chunks(2).map(parent).collect()
    } else {
        level.chunks(2).map(parent).collect()
    }
}

/// The tree hash of `data` under `key` and the mode `flags`.
///
/// A message of at most one chunk is the root itself and goes through the
/// sequential core, which handles the root block; longer messages get their
/// chunk chaining values from the backend and are merged here. Pairing
/// adjacent nodes and carrying an odd last node upward builds the same tree
/// as the specification's "largest power of two of chunks on the left".
fn tree_hash(data: &[u8], key: &[u32; 8], flags: u32, hasher: Blake3Hasher) -> [u8; HASH_SIZE] {
    if data.len() <= CHUNK_LEN {
        let mut hasher = hasher;
        hasher.update(data);
        return hasher.finalize();
    }
    let parallel = data.len() >= PARALLEL_THRESHOLD;
    let mut level = chunk_cvs(data, key, flags, parallel);
    while level.len() > 1 {
        level = merge_level(&level, key, flags, parallel);
    }
    words_to_bytes(&level[0])
}

/// BLAKE3 of `data`, chunks hashed in parallel.
pub fn hash(data: &[u8]) -> [u8; HASH_SIZE] {
    tree_hash(data, &IV, 0, Blake3Hasher::new())
}

/// Keyed BLAKE3 of `data`, chunks hashed in parallel.
pub fn hash_keyed(data: &[u8], key: &[u8; 32]) -> [u8; HASH_SIZE] {
    let mut key_words = [0u32; 8];
    for i in 0..8 {
        key_words[i] = u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    tree_hash(data, &key_words, KEYED_HASH, Blake3Hasher::new_keyed(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MetaMUIBlake3;

    fn core(data: &[u8]) -> [u8; HASH_SIZE] {
        MetaMUIBlake3::new().hash(data).to_bytes()
    }

    #[test]
    fn empty_and_small_match_the_core() {
        for len in [0usize, 1, 63, 64, 65, 1023, 1024, 1025] {
            let data = vec![0x11u8; len];
            assert_eq!(hash(&data), core(&data), "len {len}");
        }
    }

    #[test]
    fn every_chunk_count_up_to_forty_matches_the_core() {
        // Odd counts exercise the carried node at every level; sizes above
        // PARALLEL_THRESHOLD take the Rayon path, the rest the sequential one.
        for chunks in 1..=40usize {
            for extra in [0usize, 1, 500] {
                let data: Vec<u8> = (0..chunks * CHUNK_SIZE + extra).map(|i| (i % 251) as u8).collect();
                assert_eq!(hash(&data), core(&data), "{chunks} chunks + {extra}");
            }
        }
    }

    #[test]
    fn keyed_matches_the_core() {
        let key = [0x42u8; 32];
        for len in [0usize, 5, 1024, 1025, 3000, 20 * 1024 + 7] {
            let data = vec![0x55u8; len];
            let expected = MetaMUIBlake3::hash_keyed(&crate::Blake3Key::new(key), &data);
            assert_eq!(hash_keyed(&data, &key), expected.to_bytes(), "len {len}");
        }
    }
}
