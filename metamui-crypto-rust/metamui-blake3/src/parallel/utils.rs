// MetaMUI BLAKE3 - Parallel Utilities
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.

//! High-level parallel hashing utilities
//!
//! Convenient wrappers for hashing many independent inputs. Each group of
//! inputs goes through the installed [`crate::backend`]'s `hash_many`
//! (portable unless another was installed); with the `multithreading`
//! feature the groups run on Rayon's pool.

#[cfg(feature = "multithreading")]
use rayon::prelude::*;

use crate::{MetaMUIBlake3, Blake3Hash, HASH_SIZE};

/// Inputs handed to one `hash_many` call of the backend; a Rayon task each.
const GROUP: usize = 16;

fn hash_group(inputs: &[&[u8]]) -> Vec<Blake3Hash> {
    let mut out = vec![[0u8; HASH_SIZE]; inputs.len()];
    crate::backend::hash_many(inputs, &mut out);
    out.into_iter().map(Blake3Hash::new).collect()
}

/// Parallel hasher for multi-threaded BLAKE3 operations
pub struct ParallelHasher;

impl ParallelHasher {
    /// Hash multiple independent inputs in parallel
    ///
    /// Each input is hashed on a separate thread, providing near-linear
    /// speedup with the number of CPU cores.
    ///
    /// # Arguments
    ///
    /// * `inputs` - Slice of byte slices to hash independently
    ///
    /// # Returns
    ///
    /// Vector of BLAKE3 hashes (32 bytes each)
    ///
    /// # Example
    ///
    /// ```rust
    /// use metamui_blake3::parallel::ParallelHasher;
    ///
    /// let inputs: Vec<&[u8]> = vec![b"file1", b"file2", b"file3", b"file4"];
    /// let hashes = ParallelHasher::hash_many(&inputs);
    /// assert_eq!(hashes.len(), 4);
    /// ```
    #[cfg(feature = "multithreading")]
    pub fn hash_many(inputs: &[&[u8]]) -> Vec<Blake3Hash> {
        inputs
            .par_chunks(GROUP)
            .flat_map_iter(hash_group)
            .collect()
    }

    /// Hash multiple independent inputs (fallback without Rayon)
    #[cfg(not(feature = "multithreading"))]
    pub fn hash_many(inputs: &[&[u8]]) -> Vec<Blake3Hash> {
        inputs.chunks(GROUP).flat_map(hash_group).collect()
    }

    /// Hash multiple inputs in parallel with custom thread pool
    ///
    /// # Arguments
    ///
    /// * `inputs` - Slice of byte slices to hash
    /// * `num_threads` - Number of threads to use (0 = auto-detect)
    #[cfg(feature = "multithreading")]
    pub fn hash_many_with_threads(inputs: &[&[u8]], num_threads: usize) -> Vec<Blake3Hash> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .expect("Failed to create thread pool");

        pool.install(|| Self::hash_many(inputs))
    }

    /// Hash directory of files in parallel
    ///
    /// # Arguments
    ///
    /// * `file_contents` - Vector of (filename, data) pairs
    ///
    /// # Returns
    ///
    /// Vector of (filename, hash) pairs
    #[cfg(feature = "multithreading")]
    pub fn hash_files<'a>(file_contents: &[(&'a str, &[u8])]) -> Vec<(&'a str, Blake3Hash)> {
        file_contents
            .par_iter()
            .map(|(name, data)| {
                let mut hasher = MetaMUIBlake3::new();
                hasher.update(data);
                (*name, hasher.finalize())
            })
            .collect()
    }

    /// Get optimal chunk size for parallel processing
    pub fn optimal_chunk_size() -> usize {
        #[cfg(feature = "multithreading")]
        {
            let num_cores = rayon::current_num_threads();
            // Target: Keep each core busy with ~1-2MB of data
            (1024 * 1024 * 2) / num_cores.max(1)
        }

        #[cfg(not(feature = "multithreading"))]
        {
            1024 * 1024 // 1MB default
        }
    }

    /// Check if multithreading is available
    pub fn is_parallel_enabled() -> bool {
        cfg!(feature = "multithreading")
    }

    /// Get number of threads that will be used
    #[cfg(feature = "multithreading")]
    pub fn thread_count() -> usize {
        rayon::current_num_threads()
    }

    #[cfg(not(feature = "multithreading"))]
    pub fn thread_count() -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_many_empty() {
        let inputs: Vec<&[u8]> = vec![];
        let hashes = ParallelHasher::hash_many(&inputs);
        assert_eq!(hashes.len(), 0);
    }

    #[test]
    fn test_hash_many_single() {
        let inputs = vec![b"test data".as_slice()];
        let hashes = ParallelHasher::hash_many(&inputs);

        // Should match sequential
        let sequential = MetaMUIBlake3::new().hash(b"test data");
        assert_eq!(hashes[0], sequential);
    }

    #[test]
    fn test_hash_many_multiple() {
        let inputs: Vec<&[u8]> = vec![b"input1", b"input2", b"input3", b"input4"];
        let hashes = ParallelHasher::hash_many(&inputs);

        assert_eq!(hashes.len(), 4);

        // Each should match sequential
        for (i, input) in inputs.iter().enumerate() {
            let sequential = MetaMUIBlake3::new().hash(input);
            assert_eq!(hashes[i], sequential, "Hash {} should match", i);
        }
    }

    #[test]
    fn test_determinism() {
        let inputs: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];

        let hashes1 = ParallelHasher::hash_many(&inputs);
        let hashes2 = ParallelHasher::hash_many(&inputs);

        assert_eq!(hashes1, hashes2, "Parallel hashing must be deterministic");
    }

    #[test]
    fn test_optimal_chunk_size() {
        let chunk_size = ParallelHasher::optimal_chunk_size();
        assert!(chunk_size > 0);
        assert!(chunk_size <= 2 * 1024 * 1024); // <= 2MB
    }

    #[test]
    fn test_thread_count() {
        let count = ParallelHasher::thread_count();
        assert!(count >= 1);

        #[cfg(feature = "multithreading")]
        {
            // Should match available cores (or configured limit)
            assert!(count <= num_cpus::get());
        }

        #[cfg(not(feature = "multithreading"))]
        {
            assert_eq!(count, 1);
        }
    }

    #[test]
    #[cfg(feature = "multithreading")]
    fn test_hash_files() {
        let files = vec![
            ("file1.txt", b"content of file 1".as_slice()),
            ("file2.txt", b"content of file 2".as_slice()),
            ("file3.txt", b"content of file 3".as_slice()),
        ];

        let results = ParallelHasher::hash_files(&files);

        assert_eq!(results.len(), 3);

        for (name, hash) in &results {
            assert!(files.iter().any(|(n, _)| n == name));
            assert_eq!(hash.as_bytes().len(), 32);
        }
    }

    #[test]
    fn test_large_batch() {
        // Generate 100 different inputs
        let inputs: Vec<Vec<u8>> = (0..100)
            .map(|i| vec![i as u8; 1000])
            .collect();
        let input_refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();

        let hashes = ParallelHasher::hash_many(&input_refs);

        assert_eq!(hashes.len(), 100);

        // All hashes should be unique (different inputs)
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j], "Different inputs must produce different hashes");
            }
        }
    }
}
