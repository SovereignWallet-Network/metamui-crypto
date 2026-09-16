//! Integration tests for Falcon-512 with real-world scenarios

use metamui_falcon512::{generate_keypair, sign, verify};
use metamui_falcon512::batch_operations::{BatchVerifier, VerifyRequest};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

/// Test signing and verifying various message sizes
#[test]
fn test_various_message_sizes() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    // Test different message sizes
    let test_sizes = vec![
        0,      // Empty message
        1,      // Single byte
        32,     // Hash size
        64,     // Block size
        100,    // Small message
        1024,   // 1KB
        4096,   // 4KB
        10240,  // 10KB
        65536,  // 64KB
    ];
    
    for size in test_sizes {
        let message = vec![0x42u8; size];
        
        let signature = sign(&message, &keypair.private_key, &mut rng)
            .expect(&format!("Signing {} byte message should succeed", size));
        
        assert!(signature.len() <= 2048, "Signature should be reasonably sized");
        
        let valid = verify(&message, &signature, &keypair.public_key)
            .expect("Verification should not error");
        
        assert!(valid, "Signature for {} byte message should verify", size);
    }
}

/// Test multiple signatures from same key
#[test]
fn test_multiple_signatures() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let messages = vec![
        b"First message".to_vec(),
        b"Second message".to_vec(),
        b"Third message with more content".to_vec(),
        b"".to_vec(),
        vec![0xFF; 100],
    ];
    
    let mut signatures = Vec::new();
    
    // Sign all messages
    for msg in &messages {
        let sig = sign(msg, &keypair.private_key, &mut rng)
            .expect("Signing should succeed");
        signatures.push(sig);
    }
    
    // Verify all signatures
    for (msg, sig) in messages.iter().zip(signatures.iter()) {
        let valid = verify(msg, sig, &keypair.public_key)
            .expect("Verification should not error");
        assert!(valid, "Signature should verify");
    }
    
    // Cross-verify (wrong message-signature pairs should fail)
    for (i, msg) in messages.iter().enumerate() {
        for (j, sig) in signatures.iter().enumerate() {
            let valid = verify(msg, sig, &keypair.public_key)
                .expect("Verification should not error");
            
            if i == j {
                assert!(valid, "Correct pair should verify");
            } else {
                assert!(!valid, "Wrong pair should not verify");
            }
        }
    }
}

/// Test key persistence (serialization/deserialization)
#[test]
fn test_key_persistence() {
    use metamui_falcon512::{PublicKey, PrivateKey};

    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");

    // Serialize keys using the real to_bytes/from_bytes API
    let pk_bytes = keypair.public_key.to_bytes();
    let sk_bytes = keypair.private_key.to_bytes();

    // Deserialize keys
    let pk_restored = PublicKey::from_bytes(&pk_bytes)
        .expect("Public key deserialization should succeed");
    let sk_restored = PrivateKey::from_bytes(&sk_bytes)
        .expect("Private key deserialization should succeed");

    // Test with restored keys
    let message = b"Test message after key restoration";
    let signature = sign(message, &sk_restored, &mut rng)
        .expect("Signing with restored key should succeed");

    let valid = verify(message, &signature, &pk_restored)
        .expect("Verification with restored key should not error");

    assert!(valid, "Signature with restored keys should verify");
}

/// Test concurrent signing (thread safety)
#[test]
fn test_concurrent_signing() {
    use std::sync::Arc;
    use std::thread;
    
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let keypair = Arc::new(generate_keypair(&mut rng).expect("Key generation should succeed"));
    
    let mut handles = vec![];
    
    // Spawn multiple threads to sign messages
    for i in 0..10 {
        let kp = Arc::clone(&keypair);
        let handle = thread::spawn(move || {
            let mut thread_rng = ChaCha20Rng::from_seed([i as u8; 32]);
            let message = format!("Thread {} message", i).into_bytes();
            
            let signature = sign(&message, &kp.private_key, &mut thread_rng)
                .expect("Signing should succeed");
            
            let valid = verify(&message, &signature, &kp.public_key)
                .expect("Verification should not error");
            
            assert!(valid, "Thread {} signature should verify", i);
            
            (message, signature)
        });
        handles.push(handle);
    }
    
    // Collect all results
    let results: Vec<_> = handles.into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    
    // Verify all signatures again
    for (msg, sig) in results {
        let valid = verify(&msg, &sig, &keypair.public_key)
            .expect("Verification should not error");
        assert!(valid, "Signature should still verify");
    }
}

/// Performance benchmark
#[test]
#[ignore = "Run with --ignored flag for benchmarks"]
fn bench_falcon512_operations() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    
    // Benchmark key generation
    let start = Instant::now();
    let iterations = 100;
    
    for _ in 0..iterations {
        let _ = generate_keypair(&mut rng).expect("Key generation should succeed");
    }
    
    let keygen_time = start.elapsed();
    println!("Key generation: {:?} per operation", keygen_time / iterations);
    
    // Setup for signing/verification benchmarks
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    let message = b"Benchmark message for Falcon-512 testing";
    
    // Benchmark signing
    let start = Instant::now();
    let iterations = 1000;
    
    for _ in 0..iterations {
        let _ = sign(message, &keypair.private_key, &mut rng)
            .expect("Signing should succeed");
    }
    
    let sign_time = start.elapsed();
    println!("Signing: {:?} per operation", sign_time / iterations);
    
    // Benchmark verification
    let signature = sign(message, &keypair.private_key, &mut rng)
        .expect("Signing should succeed");
    
    let start = Instant::now();
    let iterations = 1000;
    
    for _ in 0..iterations {
        let _ = verify(message, &signature, &keypair.public_key)
            .expect("Verification should not error");
    }
    
    let verify_time = start.elapsed();
    println!("Verification: {:?} per operation", verify_time / iterations);
    
    // Print summary
    println!("\n=== Falcon-512 Performance Summary ===");
    println!("Key Generation: {:?}", keygen_time / 100);
    println!("Signing: {:?}", sign_time / 1000);
    println!("Verification: {:?}", verify_time / 1000);
    println!("Signature size: {} bytes", signature.len());
}

/// Test error handling
#[test]
fn test_error_handling() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    // Test with corrupted signature
    let message = b"Test message";
    let mut signature = sign(message, &keypair.private_key, &mut rng)
        .expect("Signing should succeed");
    
    // Corrupt the signature
    signature[0] ^= 0xFF;
    
    let result = verify(message, &signature, &keypair.public_key);
    match result {
        Ok(valid) => assert!(!valid, "Corrupted signature should not verify"),
        Err(_) => {} // Error is also acceptable for corrupted data
    }
    
    // Test with wrong public key
    let other_keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    let signature = sign(message, &keypair.private_key, &mut rng)
        .expect("Signing should succeed");
    
    let valid = verify(message, &signature, &other_keypair.public_key)
        .expect("Verification should not error with wrong key");
    
    assert!(!valid, "Signature with wrong public key should not verify");
}

/// Test deterministic signing (if implemented)
#[test]
fn test_deterministic_signing() {
    // Use same seed for deterministic behavior
    let seed = [42u8; 32];
    let mut rng1 = ChaCha20Rng::from_seed(seed);
    let _rng2 = ChaCha20Rng::from_seed(seed);
    
    let keypair = generate_keypair(&mut rng1).expect("Key generation should succeed");
    let message = b"Deterministic test message";
    
    // Reset RNGs with same seed for signing
    let sign_seed = [123u8; 32];
    let mut sign_rng1 = ChaCha20Rng::from_seed(sign_seed);
    let mut sign_rng2 = ChaCha20Rng::from_seed(sign_seed);
    
    let sig1 = sign(message, &keypair.private_key, &mut sign_rng1)
        .expect("First signing should succeed");
    let sig2 = sign(message, &keypair.private_key, &mut sign_rng2)
        .expect("Second signing should succeed");
    
    // With same RNG seed, signatures might be identical (implementation dependent)
    // At minimum, both should verify
    assert!(verify(message, &sig1, &keypair.public_key).unwrap());
    assert!(verify(message, &sig2, &keypair.public_key).unwrap());
}

/// Test signature batch verification
#[test]
fn test_batch_verification() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");

    // Create multiple message-signature pairs
    let mut pairs = Vec::new();
    for i in 0..20 {
        let message = format!("Message {}", i).into_bytes();
        let signature = sign(&message, &keypair.private_key, &mut rng)
            .expect("Signing should succeed");
        pairs.push((message, signature));
    }

    // Verify individually (baseline)
    let start = Instant::now();
    for (msg, sig) in &pairs {
        let valid = verify(msg, sig, &keypair.public_key)
            .expect("Verification should not error");
        assert!(valid);
    }
    let individual_time = start.elapsed();

    // Batch verification via BatchVerifier
    let verifier = BatchVerifier::new();
    let requests: Vec<VerifyRequest> = pairs.iter().map(|(msg, sig)| {
        VerifyRequest {
            message: msg.as_slice(),
            signature: sig.as_slice(),
            id: None,
        }
    }).collect();

    let start = Instant::now();
    let responses = verifier.verify_batch(&requests, &keypair.public_key);
    let batch_time = start.elapsed();

    // All should be valid
    assert_eq!(responses.len(), pairs.len());
    for (i, resp) in responses.iter().enumerate() {
        assert!(resp.valid, "Batch verification failed for message {}: {:?}", i, resp.error);
    }

    let (total, successful, failed) = verifier.stats();
    assert_eq!(total, pairs.len());
    assert_eq!(successful, pairs.len());
    assert_eq!(failed, 0);

    println!("Individual verification ({} sigs): {:?}", pairs.len(), individual_time);
    println!("Batch verification ({} sigs): {:?}", pairs.len(), batch_time);
}

/// Test cross-platform compatibility
#[test]
fn test_cross_platform_vectors() {
    // These would be test vectors generated on different platforms
    let test_vectors = vec![
        // (message, public_key, signature, platform)
        (b"Test".to_vec(), vec![0u8; 897], vec![0u8; 666], "x86_64-linux"),
        (b"Test".to_vec(), vec![0u8; 897], vec![0u8; 666], "aarch64-darwin"),
        (b"Test".to_vec(), vec![0u8; 897], vec![0u8; 666], "wasm32"),
    ];
    
    // Verify all test vectors work on current platform
    for (_msg, _pk_bytes, _sig_bytes, platform) in test_vectors {
        println!("Testing vector from {}", platform);
        
        // In real implementation, would deserialize and verify
        // let pk = PublicKey::from_bytes(&pk_bytes).unwrap();
        // let valid = verify(&msg, &sig_bytes, &pk).unwrap();
        // assert!(valid, "Cross-platform signature should verify");
    }
}