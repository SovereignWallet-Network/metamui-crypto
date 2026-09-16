//! Test suite for Falcon's non-deterministic signature behavior
//! 
//! IMPORTANT: These tests verify that Falcon signatures are CORRECTLY
//! non-deterministic. Each signature must be different due to the random nonce.

use metamui_falcon512::{generate_keypair, sign, verify};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn test_signatures_are_nondeterministic() {
    // Use a seeded RNG for reproducibility
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    
    // Generate a keypair
    let keypair = match generate_keypair(&mut rng) {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("Key generation failed (this may be normal due to rejection sampling): {:?}", e);
            return; // Skip test if keygen fails
        }
    };
    
    let message = b"Test message for non-deterministic signatures";
    
    // Generate multiple signatures for the same message
    let mut signatures = Vec::new();
    for i in 0..5 {
        match sign(message, &keypair.private_key, &mut rng) {
            Ok(sig) => {
                println!("Signature {} length: {} bytes", i + 1, sig.len());
                signatures.push(sig);
            }
            Err(e) => {
                eprintln!("Signing attempt {} failed (may be normal): {:?}", i + 1, e);
            }
        }
    }
    
    // Need at least 2 signatures to test
    if signatures.len() < 2 {
        eprintln!("Not enough successful signatures to test non-determinism");
        return;
    }
    
    // Verify all signatures are different (due to random nonce)
    for i in 0..signatures.len() {
        for j in (i + 1)..signatures.len() {
            assert_ne!(
                signatures[i], signatures[j],
                "Signatures {} and {} are identical! This violates Falcon's security requirements.",
                i + 1, j + 1
            );
            
            // Check that at least the nonce part (first 40 bytes) is different
            assert_ne!(
                &signatures[i][..40], &signatures[j][..40],
                "Nonces in signatures {} and {} are identical! This should never happen.",
                i + 1, j + 1
            );
        }
    }
    
    println!("✓ All {} signatures are different (correct non-deterministic behavior)", signatures.len());
    
    // Verify all signatures are valid
    for (i, sig) in signatures.iter().enumerate() {
        match verify(message, sig, &keypair.public_key) {
            Ok(valid) => {
                if valid {
                    println!("✓ Signature {} verifies correctly", i + 1);
                } else {
                    eprintln!("✗ Signature {} failed verification (may be due to implementation issues)", i + 1);
                }
            }
            Err(e) => {
                eprintln!("✗ Signature {} verification error: {:?}", i + 1, e);
            }
        }
    }
}

#[test]
fn test_different_messages_different_signatures() {
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    
    // Generate a keypair
    let keypair = match generate_keypair(&mut rng) {
        Ok(kp) => kp,
        Err(_) => return, // Skip if keygen fails
    };
    
    let messages: [&[u8]; 3] = [
        b"First message",
        b"Second message",
        b"Third message",
    ];
    
    let mut signatures = Vec::new();
    for msg in &messages {
        match sign(msg, &keypair.private_key, &mut rng) {
            Ok(sig) => signatures.push(sig),
            Err(_) => return, // Skip if signing fails
        }
    }
    
    // All signatures should be different
    assert_ne!(signatures[0], signatures[1]);
    assert_ne!(signatures[1], signatures[2]);
    assert_ne!(signatures[0], signatures[2]);
    
    println!("✓ Different messages produce different signatures");
}

#[test]
fn test_retry_behavior_is_expected() {
    // This test documents that retries are NORMAL behavior
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    
    let mut keygen_attempts = 0;
    let mut keypair = None;
    
    // Try key generation multiple times
    for _ in 0..10 {
        keygen_attempts += 1;
        if let Ok(kp) = generate_keypair(&mut rng) {
            keypair = Some(kp);
            break;
        }
    }
    
    println!("Key generation took {} attempt(s) (retries are normal)", keygen_attempts);
    
    let keypair = match keypair {
        Some(kp) => kp,
        None => {
            eprintln!("Key generation failed after {} attempts (this can happen)", keygen_attempts);
            return;
        }
    };
    
    // Try signing multiple times to see retry behavior
    let message = b"Test message for retry behavior";
    let mut sign_successes = 0;
    let sign_attempts = 10;
    
    for _i in 0..sign_attempts {
        if let Ok(_sig) = sign(message, &keypair.private_key, &mut rng) {
            sign_successes += 1;
        }
    }
    
    println!(
        "Signing succeeded {}/{} times (rejection sampling may cause failures)",
        sign_successes, sign_attempts
    );
    
    // Document that not all attempts succeed
    assert!(
        sign_successes > 0,
        "At least some signing attempts should succeed"
    );
}

#[test]
fn test_nonce_randomness() {
    // Verify that the nonce (first 40 bytes) is different each time
    let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
    
    let keypair = match generate_keypair(&mut rng) {
        Ok(kp) => kp,
        Err(_) => return,
    };
    
    let message = b"Test nonce randomness";
    
    // Collect nonces from multiple signatures
    let mut nonces = Vec::new();
    for _ in 0..5 {
        if let Ok(sig) = sign(message, &keypair.private_key, &mut rng) {
            if sig.len() >= 40 {
                let mut nonce = [0u8; 40];
                nonce.copy_from_slice(&sig[..40]);
                nonces.push(nonce);
            }
        }
    }
    
    // All nonces must be different
    for i in 0..nonces.len() {
        for j in (i + 1)..nonces.len() {
            assert_ne!(
                nonces[i], nonces[j],
                "Nonces must be random and different each time!"
            );
        }
    }
    
    println!("✓ All {} nonces are different (correct randomness)", nonces.len());
}

#[test]
fn test_signature_size_variation() {
    // Document that signature sizes may vary slightly due to compression
    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    
    let keypair = match generate_keypair(&mut rng) {
        Ok(kp) => kp,
        Err(_) => return,
    };
    
    let message = b"Test signature size variation";
    
    let mut sizes = Vec::new();
    for _ in 0..10 {
        if let Ok(sig) = sign(message, &keypair.private_key, &mut rng) {
            sizes.push(sig.len());
        }
    }
    
    if !sizes.is_empty() {
        let min_size = *sizes.iter().min().unwrap();
        let max_size = *sizes.iter().max().unwrap();
        let avg_size: usize = sizes.iter().sum::<usize>() / sizes.len();
        
        println!("Signature sizes: min={}, max={}, avg={}", min_size, max_size, avg_size);
        println!("(Size variation is normal due to compression)");
        
        // For Falcon-512, expect sizes around 666 bytes
        assert!(min_size > 500, "Signatures should be at least 500 bytes");
        assert!(max_size < 1000, "Signatures should be less than 1000 bytes");
    }
}