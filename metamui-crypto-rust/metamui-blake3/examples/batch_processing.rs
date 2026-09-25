// MetaMUI BLAKE3 - Batch Processing Examples
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.

//! Hashing many independent inputs in one call
//!
//! `metamui_blake3::hash_many` and `batch::batch_hash` hand a whole slice of
//! inputs to the installed backend (`metamui_blake3::backend`); with no
//! backend installed, which is the case here, that is the portable
//! implementation, and every digest is the same as the one-at-a-time API
//! produces.

use metamui_blake3::{batch, hash_many, MetaMUIBlake3};
use metamui_crypto_utilities::encoding::hex;

fn main() {
    println!("=== MetaMUI BLAKE3 - Batch Processing Examples ===\n");
    println!("backend: {}\n", metamui_blake3::backend::backend().name);

    basic_batch_processing();
    hash_multiple_files();
    batch_matches_sequential();
    large_batch_example();
}

/// Example 1: several inputs, one call
fn basic_batch_processing() {
    println!("1. Basic Batch Processing");
    println!("-------------------------");

    let inputs = vec![
        b"input 1".as_slice(),
        b"input 2".as_slice(),
        b"input 3".as_slice(),
        b"input 4".as_slice(),
    ];

    let hashes = hash_many(&inputs);

    println!("Hashed {} inputs:", inputs.len());
    for (i, hash) in hashes.iter().enumerate() {
        println!("  Input {}: {}", i + 1, &hash.to_hex()[..32]);
    }
    println!();
}

/// Example 2: checksums of several files
fn hash_multiple_files() {
    println!("2. Hashing Multiple Files (Simulated)");
    println!("--------------------------------------");

    let files = vec![
        ("config.json", b"{\"version\": 1}".as_slice()),
        ("data.txt", b"Important data".as_slice()),
        ("script.sh", b"#!/bin/bash\necho hello".as_slice()),
        ("readme.md", b"# README\n\nDocumentation".as_slice()),
    ];

    let contents: Vec<&[u8]> = files.iter().map(|(_, data)| *data).collect();
    let hashes = hash_many(&contents);

    println!("File checksums:");
    for ((name, _), hash) in files.iter().zip(hashes.iter()) {
        println!("  {:12} -> {}", name, hash.to_hex());
    }
    println!();
}

/// Example 3: the batch API produces the one-at-a-time digests
fn batch_matches_sequential() {
    println!("3. Batch vs Sequential");
    println!("----------------------");

    let input_count = 16;
    let inputs: Vec<Vec<u8>> = (0..input_count)
        .map(|i| format!("test data {}", i).into_bytes())
        .collect();
    let input_refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();

    let sequential: Vec<[u8; 32]> = input_refs
        .iter()
        .map(|input| MetaMUIBlake3::new().hash(input).to_bytes())
        .collect();

    let batched = batch::batch_hash(&input_refs).expect("non-empty batch");

    for (i, (seq, batch)) in sequential.iter().zip(batched.iter()).enumerate() {
        assert_eq!(seq, batch.as_bytes(), "Hash {} must match", i);
    }
    println!("{} inputs: batch and sequential digests agree\n", input_count);
}

/// Example 4: more inputs than one `Blake3Batch` holds
fn large_batch_example() {
    println!("4. Large Batch Processing");
    println!("-------------------------");

    let batch_size: usize = 128;
    let inputs: Vec<Vec<u8>> = (0..batch_size)
        .map(|i| format!("document_{:04}.txt", i).into_bytes())
        .collect();
    let input_refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();

    let hashes = batch::batch_hash(&input_refs).expect("non-empty batch");
    println!("Hashed {} inputs", hashes.len());

    println!("\nFirst 3 hashes:");
    for (i, hash) in hashes.iter().take(3).enumerate() {
        println!("  {}: {}", i, &hex::encode(hash.as_bytes())[..32]);
    }
    println!("\nLast 3 hashes:");
    for (i, hash) in hashes.iter().enumerate().skip(batch_size - 3) {
        println!("  {}: {}", i, &hex::encode(hash.as_bytes())[..32]);
    }
    println!();
}
