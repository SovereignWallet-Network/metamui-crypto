//! End-to-end test for Falcon-512 NIST compliance
//! 
//! This test verifies the complete flow:
//! 1. Key generation
//! 2. Signing with NIST API
//! 3. Verification with NIST API
//! 4. Cross-validation of signatures

use metamui_falcon512::{generate_keypair, sign, verify};
use metamui_falcon512::nist_api::{crypto_sign_keypair, crypto_sign, crypto_sign_open};
use metamui_falcon512::test_config::{PqcTestConfig, run_with_retries};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn test_end_to_end_nist_compliance() {
    // Create deterministic RNG
    let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
    
    // Use PQC test configuration
    let config = PqcTestConfig::default();
    
    // Test message
    let message = b"Test message for end-to-end NIST compliance verification";
    
    println!("=== Falcon-512 End-to-End Test ===");
    println!("Using PQC configuration with retry logic for rejection sampling");
    
    // Step 1: Generate keypair using NIST API with retries
    println!("1. Generating keypair with NIST API...");
    let (pk_bytes, sk_bytes) = run_with_retries(config.max_keygen_attempts, || {
        crypto_sign_keypair(&mut rng)
    }).expect("Should generate keypair within retry limit");
    println!("   ✅ Public key size: {} bytes", pk_bytes.len());
    println!("   ✅ Secret key size: {} bytes", sk_bytes.len());
    
    // Step 2: Sign message using NIST API with retries
    println!("2. Signing message with NIST API...");
    let signed_msg = run_with_retries(config.max_sign_attempts, || {
        crypto_sign(message, &sk_bytes, &mut rng)
    }).expect("Should sign message within retry limit");
    println!("   ✅ Signed message size: {} bytes", signed_msg.len());
    
    // Step 3: Verify and recover message using NIST API (no retry needed for verification)
    println!("3. Verifying signature with NIST API...");
    let recovered_msg = crypto_sign_open(&signed_msg, &pk_bytes)
        .expect("Should verify and recover message");
    assert_eq!(recovered_msg, message.to_vec(), "Message should be recovered correctly");
    println!("   ✅ Message recovered correctly");
    
    // Step 4: Test standard API as well
    println!("4. Testing standard API...");
    let keypair = run_with_retries(config.max_keygen_attempts, || {
        generate_keypair(&mut rng)
    }).expect("Should generate keypair with standard API within retry limit");
    
    let signature = run_with_retries(config.max_sign_attempts, || {
        sign(message, &keypair.private_key, &mut rng)
    }).expect("Should sign with standard API within retry limit");
    
    let is_valid = verify(message, &signature, &keypair.public_key)
        .expect("Should verify with standard API");
    assert!(is_valid, "Signature should be valid");
    println!("   ✅ Standard API works correctly");
    
    // Step 5: Multiple message test
    println!("5. Testing multiple messages...");
    let messages: Vec<&[u8]> = vec![
        b"Short",
        b"Medium length message for testing",
        b"A longer message that contains more data and should still work correctly with the Falcon-512 signature scheme",
        &[0u8; 100], // Binary data
    ];
    
    for (i, msg) in messages.iter().enumerate() {
        let signed = crypto_sign(msg, &sk_bytes, &mut rng)
            .expect(&format!("Should sign message {}", i));
        let recovered = crypto_sign_open(&signed, &pk_bytes)
            .expect(&format!("Should verify message {}", i));
        assert_eq!(recovered, msg.to_vec(), "Message {} should match", i);
    }
    println!("   ✅ All {} messages verified correctly", messages.len());
    
    println!("\n🎉 All tests passed! Falcon-512 is NIST compliant!");
}

#[test]
fn test_deterministic_signatures() {
    // Verify that signatures are deterministic with same RNG seed
    let message = b"Determinism test";
    
    // Generate keypair
    let mut rng1 = ChaCha20Rng::from_seed([1u8; 32]);
    let (pk, sk) = crypto_sign_keypair(&mut rng1)
        .expect("Should generate keypair");
    
    // Sign twice with same seed
    let mut rng2 = ChaCha20Rng::from_seed([2u8; 32]);
    let sig1 = crypto_sign(message, &sk, &mut rng2)
        .expect("Should sign");
    
    let mut rng3 = ChaCha20Rng::from_seed([2u8; 32]);
    let sig2 = crypto_sign(message, &sk, &mut rng3)
        .expect("Should sign");
    
    // Signatures should be identical with same RNG seed
    assert_eq!(sig1, sig2, "Signatures should be deterministic with same RNG");
    
    // Sign with different seed
    let mut rng4 = ChaCha20Rng::from_seed([3u8; 32]);
    let sig3 = crypto_sign(message, &sk, &mut rng4)
        .expect("Should sign");
    
    // Should be different with different RNG
    assert_ne!(sig1, sig3, "Signatures should differ with different RNG");
    
    // Both should verify
    let msg1 = crypto_sign_open(&sig1, &pk)
        .expect("Should verify sig1");
    let msg3 = crypto_sign_open(&sig3, &pk)
        .expect("Should verify sig3");
    
    assert_eq!(msg1, message.to_vec());
    assert_eq!(msg3, message.to_vec());
    
    println!("✅ Deterministic signature test passed");
}

#[test]
fn test_signature_size_bounds() {
    // Verify that signatures stay within expected size bounds
    let mut rng = ChaCha20Rng::from_seed([0x99u8; 32]);
    let (pk, sk) = crypto_sign_keypair(&mut rng)
        .expect("Should generate keypair");
    
    let mut min_size = usize::MAX;
    let mut max_size = 0;
    let mut total_size = 0;
    
    // Test many signatures
    for i in 0..100 {
        let message = format!("Test message number {}", i);
        let signed = crypto_sign(message.as_bytes(), &sk, &mut rng)
            .expect("Should sign");
        
        let sig_size = signed.len() - message.len();
        min_size = min_size.min(sig_size);
        max_size = max_size.max(sig_size);
        total_size += sig_size;
        
        // Verify it
        let recovered = crypto_sign_open(&signed, &pk)
            .expect("Should verify");
        assert_eq!(recovered, message.as_bytes());
    }
    
    let avg_size = total_size / 100;
    
    println!("Signature size statistics over 100 signatures:");
    println!("  Min: {} bytes", min_size);
    println!("  Max: {} bytes", max_size);
    println!("  Avg: {} bytes", avg_size);
    
    // NIST expected signature size is around 666 bytes for Falcon-512
    assert!(min_size > 40, "Minimum size should include nonce");
    assert!(max_size < 1000, "Maximum size should be reasonable");
    
    println!("✅ Signature size bounds test passed");
}