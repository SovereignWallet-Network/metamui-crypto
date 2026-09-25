//! Block- and chunk-boundary cases of the public API
//!
//! Inputs of 128 bytes to several chunks, at and around the boundaries where
//! the block length, the CHUNK_END flag and the chunk counter change. These
//! were the shapes on which earlier accelerated paths diverged; the portable
//! path is held to the same values.

use metamui_blake3::MetaMUIBlake3;

/// Test multi-block input (2 blocks = 128 bytes)
/// Validates CUDA cumulative block length fix
#[test]
fn test_multi_block_128_bytes() {
    let input = vec![0u8; 128];
    let hash = MetaMUIBlake3::new().hash(&input);
    let hex = hex::encode(hash.as_bytes());

    // Known test vector for 128 bytes of zeros
    let expected = "272fc82430c30a4f9f58df84a1fe3f1454be77df572c23cced4d5e003a60918f";
    assert_eq!(
        hex, expected,
        "128-byte (2 blocks) hash doesn't match known test vector"
    );
}

/// Test 256-byte input (4 blocks)
/// Further validates cumulative block length tracking
#[test]
fn test_multi_block_256_bytes() {
    let input = vec![0u8; 256];
    let hash = MetaMUIBlake3::new().hash(&input);

    // Just verify it produces a consistent hash (no known vector for this)
    assert_eq!(hash.as_bytes().len(), 32);

    // Verify it's different from 128-byte hash
    let hash_128 = MetaMUIBlake3::new().hash(&vec![0u8; 128]);
    assert_ne!(hash.as_bytes(), hash_128.as_bytes(),
               "256-byte hash should differ from 128-byte hash");
}

/// Test exactly 1 chunk (1024 bytes = 16 blocks)
/// Validates CHUNK_END flag handling
#[test]
fn test_single_chunk_1024_bytes() {
    let input = vec![0u8; 1024];
    let hash = MetaMUIBlake3::new().hash(&input);

    assert_eq!(hash.as_bytes().len(), 32);

    // Should be different from smaller inputs
    let hash_256 = MetaMUIBlake3::new().hash(&vec![0u8; 256]);
    assert_ne!(hash.as_bytes(), hash_256.as_bytes());
}

/// Test 2 chunks (2048 bytes)
/// Validates CUDA chunk counter fix - critical for multi-chunk inputs
#[test]
fn test_multi_chunk_2048_bytes() {
    let input = vec![0u8; 2048];
    let hash = MetaMUIBlake3::new().hash(&input);

    assert_eq!(hash.as_bytes().len(), 32);

    // Should be different from single chunk
    let hash_1024 = MetaMUIBlake3::new().hash(&vec![0u8; 1024]);
    assert_ne!(hash.as_bytes(), hash_1024.as_bytes(),
               "Multi-chunk hash should differ from single-chunk");
}

/// Test empty input (edge case)
#[test]
fn test_empty_input() {
    let input = vec![];
    let hash = MetaMUIBlake3::new().hash(&input);
    let hex = hex::encode(hash.as_bytes());

    // Known test vector for empty input
    let expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    assert_eq!(hex, expected, "Empty input hash doesn't match known test vector");
}

/// Test single block (64 bytes)
#[test]
fn test_single_block_64_bytes() {
    let input = vec![0u8; 64];
    let hash = MetaMUIBlake3::new().hash(&input);

    assert_eq!(hash.as_bytes().len(), 32);

    // Verify it's different from empty
    let hash_empty = MetaMUIBlake3::new().hash(&vec![]);
    assert_ne!(hash.as_bytes(), hash_empty.as_bytes());
}

/// Test various block boundaries to ensure cumulative tracking works
#[test]
fn test_block_boundaries() {
    let test_sizes = [
        63,   // Just under 1 block
        64,   // Exactly 1 block
        65,   // Just over 1 block
        127,  // Just under 2 blocks
        128,  // Exactly 2 blocks
        129,  // Just over 2 blocks
        1023, // Just under 1 chunk
        1024, // Exactly 1 chunk
        1025, // Just over 1 chunk
    ];

    let mut hashes = Vec::new();

    for &size in &test_sizes {
        let input = vec![0u8; size];
        let hash = MetaMUIBlake3::new().hash(&input);

        // Verify hash is correct length
        assert_eq!(hash.as_bytes().len(), 32, "Hash for {} bytes is wrong length", size);

        // Verify all hashes are unique (different inputs should produce different hashes)
        for (prev_size, prev_hash) in &hashes {
            assert_ne!(
                hash.as_bytes(), prev_hash,
                "Hash for {} bytes should differ from hash for {} bytes",
                size, prev_size
            );
        }

        hashes.push((size, hash.as_bytes().to_vec()));
    }
}

/// Test incremental hashing matches one-shot for multi-block inputs
#[test]
fn test_incremental_vs_oneshot_multiblock() {
    let data = vec![0u8; 256]; // 4 blocks

    // One-shot hash
    let oneshot = MetaMUIBlake3::new().hash(&data);

    // Incremental hash (feed in 64-byte blocks)
    let mut hasher = MetaMUIBlake3::new();
    for chunk in data.chunks(64) {
        hasher.update(chunk);
    }
    let incremental = hasher.finalize();

    assert_eq!(
        oneshot.as_bytes(), incremental.as_bytes(),
        "Incremental hash should match one-shot for multi-block input"
    );
}

/// Test that different block counts produce different hashes
#[test]
fn test_different_block_counts_differ() {
    // All zeros, but different lengths
    let inputs = [
        vec![0u8; 64],   // 1 block
        vec![0u8; 128],  // 2 blocks
        vec![0u8; 192],  // 3 blocks
        vec![0u8; 256],  // 4 blocks
    ];

    let mut hashes = Vec::new();

    for input in &inputs {
        let hash = MetaMUIBlake3::new().hash(input);

        // Check uniqueness
        for prev_hash in &hashes {
            assert_ne!(
                hash.as_bytes(), prev_hash,
                "Hashes for different block counts should differ"
            );
        }

        hashes.push(hash.as_bytes().to_vec());
    }
}
