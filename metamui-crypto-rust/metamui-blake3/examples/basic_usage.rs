// MetaMUI BLAKE3 - Basic Usage Examples
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.

//! Basic BLAKE3 hashing examples
//!
//! This example demonstrates the fundamental BLAKE3 operations:
//! - One-shot hashing
//! - Incremental hashing
//! - Hash formatting

use metamui_blake3::MetaMUIBlake3;
use metamui_crypto_utilities::encoding::hex;

fn main() {
    println!("=== MetaMUI BLAKE3 - Basic Usage Examples ===\n");

    // Example 1: One-shot hashing
    basic_one_shot_hashing();

    // Example 2: Incremental hashing
    incremental_hashing();

    // Example 3: Hash formatting
    hash_formatting();

    // Example 4: Hashing different data types
    hash_different_types();

    // Example 5: Empty input
    empty_input_hash();
}

/// Example 1: One-shot hashing
///
/// The simplest way to hash data - pass it all at once
fn basic_one_shot_hashing() {
    println!("1. One-Shot Hashing");
    println!("-------------------");

    let data = b"Hello, BLAKE3!";
    let hasher = MetaMUIBlake3::new();
    let hash = hasher.hash(data);

    println!("Input:  {:?}", String::from_utf8_lossy(data));
    println!("Hash:   {}", hex::encode(hash.as_bytes()));
    println!("Length: {} bytes\n", hash.as_bytes().len());
}

/// Example 2: Incremental hashing
///
/// Hash data in chunks - useful for streaming or large files
fn incremental_hashing() {
    println!("2. Incremental Hashing");
    println!("----------------------");

    let mut hasher = MetaMUIBlake3::new();

    // Update in multiple chunks
    hasher.update(b"Hello, ");
    hasher.update(b"BLAKE3");
    hasher.update(b"!");

    let hash = hasher.finalize();

    println!("Chunks: [\"Hello, \", \"BLAKE3\", \"!\"]");
    println!("Hash:   {}", hex::encode(hash.as_bytes()));

    // Verify it matches one-shot
    let one_shot_hasher = MetaMUIBlake3::new();
    let one_shot = one_shot_hasher.hash(b"Hello, BLAKE3!");
    assert_eq!(hash.as_bytes(), one_shot.as_bytes(), "Incremental must match one-shot");
    println!("✓ Verified: Matches one-shot hashing\n");
}

/// Example 3: Hash formatting
///
/// Different ways to display and use hash output
fn hash_formatting() {
    println!("3. Hash Formatting");
    println!("------------------");

    let hasher = MetaMUIBlake3::new();
    let hash = hasher.hash(b"test");

    // Hexadecimal string (most common)
    let hex_string = hex::encode(hash.as_bytes());
    println!("Hex string:     {}", hex_string);

    // Raw bytes
    println!("Raw bytes:      {:?}", &hash.as_bytes()[..8]); // First 8 bytes

    // Base64 (requires serde feature in production)
    println!("Length:         {} bytes", hash.as_bytes().len());

    // Hash comparison
    let hasher2 = MetaMUIBlake3::new();
    let hash2 = hasher2.hash(b"test");
    let hex2 = hex::encode(hash2.as_bytes());
    println!("Equality check: {} == {} → {}\n",
        &hex_string[..16],
        &hex2[..16],
        hash.as_bytes() == hash2.as_bytes()
    );
}

/// Example 4: Hashing different data types
///
/// BLAKE3 can hash any byte sequence
fn hash_different_types() {
    println!("4. Hashing Different Data Types");
    println!("--------------------------------");

    // String
    let hasher = MetaMUIBlake3::new();
    let string_hash = hasher.hash(b"string data");
    let hex_str = hex::encode(string_hash.as_bytes());
    println!("String:  {}", &hex_str[..32]);

    // Numbers (as bytes)
    let number: u64 = 12345;
    let hasher2 = MetaMUIBlake3::new();
    let number_hash = hasher2.hash(&number.to_le_bytes());
    let hex_num = hex::encode(number_hash.as_bytes());
    println!("Number:  {}", &hex_num[..32]);

    // Binary data
    let binary = vec![0xFF, 0x00, 0xAA, 0x55];
    let hasher3 = MetaMUIBlake3::new();
    let binary_hash = hasher3.hash(&binary);
    let hex_bin = hex::encode(binary_hash.as_bytes());
    println!("Binary:  {}", &hex_bin[..32]);

    // Large data
    let large_data = vec![0x42; 10_000];
    let hasher4 = MetaMUIBlake3::new();
    let large_hash = hasher4.hash(&large_data);
    let hex_large = hex::encode(large_hash.as_bytes());
    println!("10KB:    {}", &hex_large[..32]);
    println!();
}

/// Example 5: Empty input
///
/// BLAKE3 can hash empty input (produces a specific constant hash)
fn empty_input_hash() {
    println!("5. Empty Input Hash");
    println!("-------------------");

    let hasher = MetaMUIBlake3::new();
    let empty_hash = hasher.hash(b"");

    println!("Empty input hash:");
    println!("{}", hex::encode(empty_hash.as_bytes()));
    println!("\nThis is a constant value defined by the BLAKE3 specification.\n");
}
