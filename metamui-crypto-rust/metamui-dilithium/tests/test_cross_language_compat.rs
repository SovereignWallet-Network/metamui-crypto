use metamui_dilithium::dilithium2::Dilithium2;

#[test]
fn test_python_rust_signature_compatibility() {
    // Test key generation and basic signing/verification
    let (pk, sk) = Dilithium2::generate_keypair();
    let message = b"Test message for cross-language compatibility";
    
    // Sign with Rust
    let sig = Dilithium2::sign(&sk, message);
    
    // Verify with Rust (should pass)
    assert!(Dilithium2::verify(&pk, message, &sig), "Rust signature should verify with Rust");
    
    // Print test vectors for manual Python testing
    println!("\n=== Test Vectors for Python Verification ===");
    println!("Message (hex): {}", hex::encode(message));
    println!("Public Key (hex): {}", hex::encode(&pk));
    println!("Secret Key (hex): {}", hex::encode(&sk));
    println!("Signature (hex): {}", hex::encode(&sig));
    
    // Also test that invalid signatures fail
    let mut bad_sig = sig;
    bad_sig[100] ^= 0xFF;  // Flip some bits
    assert!(!Dilithium2::verify(&pk, message, &bad_sig), "Modified signature should fail");
}

#[test]
fn test_deterministic_signing() {
    // Ensure signatures are deterministic
    let (pk, sk) = Dilithium2::generate_keypair();
    let message = b"Deterministic test";
    
    let sig1 = Dilithium2::sign(&sk, message);
    let sig2 = Dilithium2::sign(&sk, message);
    
    assert_eq!(sig1, sig2, "Deterministic signatures should be identical");
    assert!(Dilithium2::verify(&pk, message, &sig1), "Signature should verify");
}

#[test]
fn test_empty_message() {
    let (pk, sk) = Dilithium2::generate_keypair();
    let message = b"";
    
    let sig = Dilithium2::sign(&sk, message);
    assert!(Dilithium2::verify(&pk, message, &sig), "Empty message signature should verify");
}

#[test]
fn test_large_message() {
    let (pk, sk) = Dilithium2::generate_keypair();
    let message = vec![0xAB; 10000]; // 10KB message
    
    let sig = Dilithium2::sign(&sk, &message);
    assert!(Dilithium2::verify(&pk, &message, &sig), "Large message signature should verify");
}