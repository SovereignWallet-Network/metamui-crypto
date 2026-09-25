// MetaMUI BLAKE3 - Advanced Features Examples
//
// Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.

//! Advanced BLAKE3 features
//!
//! This example demonstrates:
//! - Keyed hashing (MAC - Message Authentication Code)
//! - Key derivation (KDF - Key Derivation Function)
//! - XOF (eXtendable Output Function)
//! - Custom output lengths

use metamui_blake3::{MetaMUIBlake3, Blake3Key};
use metamui_crypto_utilities::encoding::hex;

fn main() {
    println!("=== MetaMUI BLAKE3 - Advanced Features ===\n");

    // Example 1: Keyed hashing (MAC)
    keyed_hashing_mac();

    // Example 2: Key derivation (KDF)
    key_derivation_kdf();

    // Example 3: Extended output (XOF)
    extended_output_xof();

    // Example 4: Domain separation
    domain_separation();

    // Example 5: Practical use cases
    practical_use_cases();
}

/// Example 1: Keyed hashing (MAC)
///
/// Create message authentication codes using a secret key.
/// Only parties with the same key can verify the hash.
fn keyed_hashing_mac() {
    println!("1. Keyed Hashing (MAC - Message Authentication Code)");
    println!("----------------------------------------------------");

    // Secret key (32 bytes)
    let key = Blake3Key::new([0x42u8; 32]);
    let message = b"Important message";

    // Create keyed hash (MAC)
    let hasher = MetaMUIBlake3::new_keyed(&key);
    let mac = hasher.hash(message);

    println!("Key:     {} (32 bytes)", hex::encode(&[0x42u8; 8]));
    println!("Message: {:?}", String::from_utf8_lossy(message));
    println!("MAC:     {}", hex::encode(mac.as_bytes()));

    // Verify MAC
    let verification_hasher = MetaMUIBlake3::new_keyed(&key);
    let verification_mac = verification_hasher.hash(message);
    assert_eq!(mac.as_bytes(), verification_mac.as_bytes());
    println!("\n✓ MAC verification successful");

    // Wrong key produces different MAC
    let wrong_key = Blake3Key::new([0x99u8; 32]);
    let wrong_hasher = MetaMUIBlake3::new_keyed(&wrong_key);
    let wrong_mac = wrong_hasher.hash(message);
    assert_ne!(mac.as_bytes(), wrong_mac.as_bytes());
    println!("✓ Different key produces different MAC\n");

    println!("Use cases:");
    println!("  - Message authentication");
    println!("  - API request signing");
    println!("  - Cookie integrity verification");
    println!("  - Session token validation\n");
}

/// Example 2: Key derivation (KDF)
///
/// Derive cryptographic keys from a password or master key.
fn key_derivation_kdf() {
    println!("2. Key Derivation (KDF - Key Derivation Function)");
    println!("-------------------------------------------------");

    let master_key = b"master_secret_key_material";

    // Derive different keys for different purposes
    let context1 = "metamui-blake3 2025-01-15 encryption key";
    let context2 = "metamui-blake3 2025-01-15 signing key";

    let encryption_key = MetaMUIBlake3::derive_key(context1, master_key, 32);
    let signing_key = MetaMUIBlake3::derive_key(context2, master_key, 32);

    println!("Master key: {}", hex::encode(master_key));
    println!();
    println!("Context 1: \"{}\"", context1);
    println!("Derived encryption key:");
    println!("  {}", hex::encode(&encryption_key));
    println!();
    println!("Context 2: \"{}\"", context2);
    println!("Derived signing key:");
    println!("  {}", hex::encode(&signing_key));

    // Different contexts produce different keys
    assert_ne!(encryption_key, signing_key);
    println!("\n✓ Different contexts produce different keys\n");

    println!("Use cases:");
    println!("  - Derive multiple keys from one master key");
    println!("  - Password-based key derivation");
    println!("  - Hierarchical key derivation");
    println!("  - Domain-specific key generation\n");
}

/// Example 3: Extended output (XOF)
///
/// Generate arbitrary-length outputs (not limited to 32 bytes)
fn extended_output_xof() {
    println!("3. Extended Output (XOF - eXtendable Output Function)");
    println!("-----------------------------------------------------");

    let input = b"seed data";
    let mut hasher = MetaMUIBlake3::new();
    hasher.update(input);

    // Generate different output lengths
    let output_16 = hasher.finalize_variable(16);
    let output_32 = hasher.finalize_variable(32);
    let output_64 = hasher.finalize_variable(64);
    let output_128 = hasher.finalize_variable(128);

    println!("Input: {:?}", String::from_utf8_lossy(input));
    println!();
    println!("16 bytes:  {}", hex::encode(&output_16));
    println!("32 bytes:  {}", hex::encode(&output_32));
    println!("64 bytes:  {}", hex::encode(&output_64[..32]));
    println!("           {}", hex::encode(&output_64[32..]));
    println!("128 bytes: {} ...", hex::encode(&output_128[..32]));

    // Verify that shorter output is prefix of longer output
    assert_eq!(&output_32[..16], &output_16[..]);
    assert_eq!(&output_64[..32], &output_32[..]);
    assert_eq!(&output_128[..64], &output_64[..]);
    println!("\n✓ Shorter outputs are prefixes of longer outputs\n");

    println!("Use cases:");
    println!("  - Generate encryption keys of any length");
    println!("  - Create initialization vectors (IVs)");
    println!("  - Generate nonces");
    println!("  - Derive multiple values from one hash\n");
}

/// Example 4: Domain separation
///
/// Prevent hash collisions between different applications
fn domain_separation() {
    println!("4. Domain Separation");
    println!("--------------------");

    let data = b"user_id_12345";

    // Different domains for different purposes
    let hasher1 = MetaMUIBlake3::new_derive_key("app1_user_ids");
    let hash_app1 = hasher1.hash(data);

    let hasher2 = MetaMUIBlake3::new_derive_key("app2_user_ids");
    let hash_app2 = hasher2.hash(data);

    let hasher3 = MetaMUIBlake3::new_derive_key("session_tokens");
    let hash_session = hasher3.hash(data);

    println!("Data: {:?}", String::from_utf8_lossy(data));
    println!();
    println!("Domain: app1_user_ids");
    println!("  Hash: {}", hex::encode(hash_app1.as_bytes()));
    println!();
    println!("Domain: app2_user_ids");
    println!("  Hash: {}", hex::encode(hash_app2.as_bytes()));
    println!();
    println!("Domain: session_tokens");
    println!("  Hash: {}", hex::encode(hash_session.as_bytes()));

    // All different despite same input
    assert_ne!(hash_app1.as_bytes(), hash_app2.as_bytes());
    assert_ne!(hash_app1.as_bytes(), hash_session.as_bytes());
    assert_ne!(hash_app2.as_bytes(), hash_session.as_bytes());

    println!("\n✓ Domain separation prevents collisions between applications\n");

    println!("Benefits:");
    println!("  - Prevents cross-protocol attacks");
    println!("  - Isolates different components");
    println!("  - Enables safe key reuse across domains\n");
}

/// Example 5: Practical use cases
///
/// Real-world applications of BLAKE3 features
fn practical_use_cases() {
    println!("5. Practical Use Cases");
    println!("----------------------");

    // Use case 1: API request signing
    println!("Use Case 1: API Request Signing");
    println!("--------------------------------");
    {
        let api_secret = Blake3Key::new([0x2Au8; 32]);
        let request_body = b"{\"action\":\"transfer\",\"amount\":1000}";
        let timestamp = "2025-01-15T10:30:00Z";

        let mut hasher = MetaMUIBlake3::new_keyed(&api_secret);
        hasher.update(timestamp.as_bytes());
        hasher.update(request_body);
        let signature = hasher.finalize();

        println!("Request: {}", String::from_utf8_lossy(request_body));
        println!("Timestamp: {}", timestamp);
        println!("Signature: {}", hex::encode(signature.as_bytes()));
        println!();
    }

    // Use case 2: Password-based encryption key
    println!("Use Case 2: Password-Based Encryption Key");
    println!("------------------------------------------");
    {
        let password = b"user_password_123";
        let salt = b"random_salt_value"; // In practice, use random salt

        let context = "metamui-blake3 file encryption v1";
        let mut hasher = MetaMUIBlake3::new_derive_key(context);
        hasher.update(password);
        hasher.update(salt);

        // Derive 32-byte encryption key
        let encryption_key = hasher.finalize_variable(32);

        println!("Password: {}", String::from_utf8_lossy(password));
        println!("Salt: {}", hex::encode(salt));
        println!("Encryption key: {}", hex::encode(&encryption_key));
        println!();
    }

    // Use case 3: Content-addressable storage
    println!("Use Case 3: Content-Addressable Storage");
    println!("----------------------------------------");
    {
        let file_content = b"File contents here...";

        // Hash determines storage location
        let hasher = MetaMUIBlake3::new();
        let content_hash = hasher.hash(file_content);
        let storage_key = hex::encode(content_hash.as_bytes());

        println!("File content: {} bytes", file_content.len());
        println!("Storage key: {}", &storage_key[..32]);
        println!("Full path: /storage/{}/{}/{}",
            &storage_key[..2],
            &storage_key[2..4],
            &storage_key[4..]
        );
        println!();
    }

    println!("✓ All practical examples completed successfully\n");
}
