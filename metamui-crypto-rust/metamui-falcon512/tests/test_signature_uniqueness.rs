//! Tests for signature uniqueness and non-determinism in Falcon-512

use metamui_falcon512::{generate_keypair, sign, verify};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::HashSet;

/// Verify that each signature is unique even for the same message
#[test]
fn test_signature_uniqueness_same_message() {
    let mut rng = StdRng::seed_from_u64(54321);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"This is a test message that will be signed multiple times";
    let num_signatures = 50;
    
    let mut signatures = HashSet::new();
    let mut all_sigs = Vec::new();
    
    for i in 0..num_signatures {
        let signature = sign(message, &keypair.private_key, &mut rng)
            .expect(&format!("Signing should succeed (attempt {})", i));
        
        // Store for verification
        all_sigs.push(signature.clone());
        
        // Check uniqueness
        let was_new = signatures.insert(signature);
        assert!(was_new, "Found duplicate signature at iteration {}", i);
    }
    
    // Verify all signatures are valid
    for (i, sig) in all_sigs.iter().enumerate() {
        assert!(
            verify(message, sig, &keypair.public_key).unwrap(),
            "Signature {} should verify", i
        );
    }
    
    println!("Successfully generated {} unique signatures for the same message", num_signatures);
}

/// Test that different messages produce different signatures
#[test]
fn test_signature_uniqueness_different_messages() {
    let mut rng = StdRng::seed_from_u64(67890);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let messages = vec![
        b"Message 1".to_vec(),
        b"Message 2".to_vec(),
        b"Different content".to_vec(),
        b"Yet another message".to_vec(),
        b"Final test message".to_vec(),
    ];
    
    let mut signatures = HashSet::new();
    
    for (i, message) in messages.iter().enumerate() {
        let signature = sign(message, &keypair.private_key, &mut rng)
            .expect(&format!("Signing message {} should succeed", i));
        
        // Each message should produce a unique signature
        let was_new = signatures.insert(signature.clone());
        assert!(was_new, "Found duplicate signature for message {}", i);
        
        // Verify the signature
        assert!(
            verify(message, &signature, &keypair.public_key).unwrap(),
            "Signature for message {} should verify", i
        );
        
        // Verify signature doesn't work with wrong message
        for (j, other_message) in messages.iter().enumerate() {
            if i != j {
                assert!(
                    !verify(other_message, &signature, &keypair.public_key).unwrap_or(false),
                    "Signature for message {} should not verify with message {}", i, j
                );
            }
        }
    }
    
    println!("All {} messages produced unique signatures", messages.len());
}

/// Test that signatures are unpredictable
#[test]
fn test_signature_unpredictability() {
    let mut rng = StdRng::seed_from_u64(11111);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"Test message for unpredictability";
    
    // Generate multiple signatures and check their bytes differ significantly
    let mut signatures = Vec::new();
    for _ in 0..10 {
        let sig = sign(message, &keypair.private_key, &mut rng)
            .expect("Signing should succeed");
        signatures.push(sig);
    }
    
    // Compare each pair of signatures
    for i in 0..signatures.len() {
        for j in i+1..signatures.len() {
            let sig1 = &signatures[i];
            let sig2 = &signatures[j];
            
            // Count differing bytes
            let mut diff_count = 0;
            for k in 0..sig1.len().min(sig2.len()) {
                if sig1[k] != sig2[k] {
                    diff_count += 1;
                }
            }
            
            // Signatures should differ in many positions
            let diff_ratio = diff_count as f64 / sig1.len() as f64;
            assert!(
                diff_ratio > 0.3,
                "Signatures {} and {} are too similar (only {:.1}% different)",
                i, j, diff_ratio * 100.0
            );
        }
    }
    
    println!("All signature pairs show sufficient unpredictability");
}

/// Test signature entropy
#[test]
fn test_signature_entropy() {
    let mut rng = StdRng::seed_from_u64(22222);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"Test message for entropy analysis";
    let num_signatures = 100;
    
    // Collect byte frequency across all signatures
    let mut byte_frequencies = vec![0u64; 256];
    let mut total_bytes = 0u64;
    
    for _ in 0..num_signatures {
        let signature = sign(message, &keypair.private_key, &mut rng)
            .expect("Signing should succeed");
        
        for &byte in signature.iter() {
            byte_frequencies[byte as usize] += 1;
            total_bytes += 1;
        }
    }
    
    // Calculate Shannon entropy
    let mut entropy = 0.0;
    for &freq in byte_frequencies.iter() {
        if freq > 0 {
            let p = freq as f64 / total_bytes as f64;
            entropy -= p * p.log2();
        }
    }
    
    println!("Signature entropy: {:.2} bits", entropy);
    
    // Entropy should be reasonably high (not perfectly uniform due to structure)
    assert!(
        entropy > 6.0,
        "Signature entropy too low: {:.2} bits", entropy
    );
    
    // Check that no single byte value dominates
    let max_freq = *byte_frequencies.iter().max().unwrap();
    let max_ratio = max_freq as f64 / total_bytes as f64;
    assert!(
        max_ratio < 0.05,
        "Byte value distribution too skewed: max frequency {:.2}%", max_ratio * 100.0
    );
}

/// Test that small message changes produce completely different signatures
#[test]
fn test_avalanche_effect() {
    let mut rng = StdRng::seed_from_u64(33333);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message1 = b"The quick brown fox jumps over the lazy dog";
    let message2 = b"The quick brown fox jumps over the lazy fog"; // One bit difference
    
    // Generate multiple signatures for each message
    let mut sigs1 = Vec::new();
    let mut sigs2 = Vec::new();
    
    for _ in 0..5 {
        sigs1.push(sign(message1, &keypair.private_key, &mut rng).unwrap());
        sigs2.push(sign(message2, &keypair.private_key, &mut rng).unwrap());
    }
    
    // Each signature from message1 should be very different from message2 signatures
    for (i, sig1) in sigs1.iter().enumerate() {
        for (j, sig2) in sigs2.iter().enumerate() {
            let mut diff_count = 0;
            for k in 0..sig1.len().min(sig2.len()) {
                if sig1[k] != sig2[k] {
                    diff_count += 1;
                }
            }
            
            let diff_ratio = diff_count as f64 / sig1.len() as f64;
            assert!(
                diff_ratio > 0.4,
                "Avalanche effect insufficient: sigs {}/{} only {:.1}% different",
                i, j, diff_ratio * 100.0
            );
        }
    }
    
    println!("Avalanche effect confirmed: small message changes produce very different signatures");
}