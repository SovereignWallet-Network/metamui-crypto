// MetaMUI BLAKE3 - Parallel Hashing Examples
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.

//! Multi-threaded parallel hashing examples
//!
//! This example demonstrates BLAKE3's parallel hashing capabilities using Rayon.
//! Parallel hashing provides near-linear speedup with CPU core count.
//!
//! Requirements:
//! - Compile with: cargo run --example parallel_hashing --features multithreading
//!
//! Every result is the ordinary BLAKE3 digest; the parallel paths compute
//! the same bytes as the sequential one.

#[cfg(feature = "multithreading")]
use metamui_blake3::parallel::ParallelHasher;
#[cfg(feature = "multithreading")]
use metamui_blake3::{blake3_parallel, MetaMUIBlake3};

fn main() {
    #[cfg(not(feature = "multithreading"))]
    {
        println!("ERROR: This example requires the 'multithreading' feature.");
        println!("Run with: cargo run --example parallel_hashing --features multithreading");
        std::process::exit(1);
    }

    #[cfg(feature = "multithreading")]
    {
        println!("=== MetaMUI BLAKE3 - Parallel Hashing Examples ===\n");
        println!("CPU cores available: {}\n", ParallelHasher::thread_count());

        // Example 1: Parallel batch hashing
        parallel_batch_hashing();

        // Example 2: Hash large file in parallel
        parallel_large_file();

        // Example 3: Hash directory of files
        parallel_file_directory();

        // Example 4: Performance comparison
        parallel_vs_sequential();

        // Example 5: Custom thread pool
        custom_thread_pool();
    }
}

#[cfg(feature = "multithreading")]
fn parallel_batch_hashing() {
    println!("1. Parallel Batch Hashing");
    println!("-------------------------");

    // Prepare multiple inputs
    let inputs = vec![
        b"document_1.txt".as_slice(),
        b"document_2.txt".as_slice(),
        b"document_3.txt".as_slice(),
        b"document_4.txt".as_slice(),
        b"document_5.txt".as_slice(),
        b"document_6.txt".as_slice(),
        b"document_7.txt".as_slice(),
        b"document_8.txt".as_slice(),
    ];

    // Hash in parallel across multiple CPU cores
    let hashes = ParallelHasher::hash_many(&inputs);

    println!("Hashed {} inputs in parallel:", inputs.len());
    for (i, hash) in hashes.iter().enumerate() {
        let hex_str = hex::encode(hash.as_bytes());
        println!("  Input {}: {}", i + 1, &hex_str[..32]);
    }

    println!("\nEach input was hashed on a separate thread for maximum throughput.\n");
}

#[cfg(feature = "multithreading")]
fn parallel_large_file() {
    println!("2. Parallel Large File Hashing");
    println!("-------------------------------");

    // Simulate a large file (10MB)
    let large_data = vec![0x42u8; 10 * 1024 * 1024];

    use std::time::Instant;

    // Parallel hashing (uses correct BLAKE3 tree mode)
    let start = Instant::now();
    let parallel_hash = blake3_parallel::hash(&large_data);
    let parallel_time = start.elapsed();

    println!("Input size: {} MB", large_data.len() / (1024 * 1024));
    println!("Parallel hash: {}", hex::encode(&parallel_hash));
    println!("Time: {:?}", parallel_time);

    if parallel_time.as_millis() > 0 {
        let throughput = (large_data.len() as f64 / (1024.0 * 1024.0))
            / parallel_time.as_secs_f64();
        println!("Throughput: {:.1} MB/s", throughput);
    }

    println!("\nNote: Large files are split into 1KB chunks (BLAKE3 spec),");
    println!("      hashed in parallel, then combined using proper binary tree structure.\n");
}

#[cfg(feature = "multithreading")]
fn parallel_file_directory() {
    println!("3. Hash Directory of Files");
    println!("--------------------------");

    // Simulate a directory with multiple files
    let data_db = vec![0xAA; 50_000];
    let test_txt = vec![0xBB; 100_000];

    let files = vec![
        ("config.json", b"{\"version\": \"1.0\"}".as_slice()),
        ("data.db", data_db.as_slice()),
        ("script.sh", b"#!/bin/bash\necho 'Hello'".as_slice()),
        ("readme.md", b"# Project\n\nDocumentation here".as_slice()),
        ("main.rs", b"fn main() { println!(\"Hello\"); }".as_slice()),
        ("test.txt", test_txt.as_slice()),
    ];

    use std::time::Instant;
    let start = Instant::now();
    let results = ParallelHasher::hash_files(&files);
    let elapsed = start.elapsed();

    println!("Hashed {} files in parallel in {:?}:", files.len(), elapsed);
    for (name, hash) in results {
        let size = files.iter()
            .find(|(n, _)| *n == name)
            .map(|(_, data)| data.len())
            .unwrap_or(0);

        let hex_str = hex::encode(hash.as_bytes());
        println!("  {:12} ({:>7} bytes) → {}",
            name,
            size,
            &hex_str[..32]
        );
    }

    println!("\nAll files hashed concurrently on separate threads.\n");
}

#[cfg(feature = "multithreading")]
fn parallel_vs_sequential() {
    println!("4. Parallel vs Sequential Performance");
    println!("-------------------------------------");

    let num_inputs = 32;
    let input_size = 100_000; // 100KB each

    // Generate test inputs
    let inputs: Vec<Vec<u8>> = (0..num_inputs)
        .map(|i| vec![(i % 256) as u8; input_size])
        .collect();
    let input_refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();

    use std::time::Instant;

    // Sequential
    let start = Instant::now();
    let sequential_hashes: Vec<_> = input_refs.iter()
        .map(|input| {
            let hasher = MetaMUIBlake3::new();
            hasher.hash(input)
        })
        .collect();
    let sequential_time = start.elapsed();

    // Parallel
    let start = Instant::now();
    let parallel_hashes = ParallelHasher::hash_many(&input_refs);
    let parallel_time = start.elapsed();

    // Verify correctness
    for (seq, par) in sequential_hashes.iter().zip(parallel_hashes.iter()) {
        assert_eq!(seq.as_bytes(), par.as_bytes(), "Results must match");
    }

    let total_size = num_inputs * input_size;
    println!("Workload: {} inputs × {} KB = {} MB",
        num_inputs,
        input_size / 1024,
        total_size / (1024 * 1024)
    );
    println!();

    println!("Sequential:");
    println!("  Time:       {:?}", sequential_time);
    if sequential_time.as_millis() > 0 {
        let throughput = (total_size as f64 / (1024.0 * 1024.0))
            / sequential_time.as_secs_f64();
        println!("  Throughput: {:.1} MB/s", throughput);
    }

    println!("\nParallel ({} cores):", ParallelHasher::thread_count());
    println!("  Time:       {:?}", parallel_time);
    if parallel_time.as_millis() > 0 {
        let throughput = (total_size as f64 / (1024.0 * 1024.0))
            / parallel_time.as_secs_f64();
        println!("  Throughput: {:.1} MB/s", throughput);

        let speedup = sequential_time.as_secs_f64() / parallel_time.as_secs_f64();
        println!("  Speedup:    {:.2}×", speedup);
    }

    println!("\n✓ Parallel hashing verified correct\n");
}

#[cfg(feature = "multithreading")]
fn custom_thread_pool() {
    println!("5. Custom Thread Pool");
    println!("---------------------");

    let inputs = vec![
        b"input 1".as_slice(),
        b"input 2".as_slice(),
        b"input 3".as_slice(),
        b"input 4".as_slice(),
    ];

    // Use custom thread count
    let num_threads = 2;
    println!("Using {} threads (instead of default {})",
        num_threads,
        ParallelHasher::thread_count()
    );

    let hashes = ParallelHasher::hash_many_with_threads(&inputs, num_threads);

    println!("Hashed {} inputs:", hashes.len());
    for (i, hash) in hashes.iter().enumerate() {
        let hex_str = hex::encode(hash.as_bytes());
        println!("  Input {}: {}", i + 1, &hex_str[..32]);
    }

    println!("\nOptimal chunk size: {} bytes", ParallelHasher::optimal_chunk_size());
    println!("\nNote: Custom thread pools are useful for controlling CPU usage");
    println!("      in shared environments or limiting parallelism.\n");
}
