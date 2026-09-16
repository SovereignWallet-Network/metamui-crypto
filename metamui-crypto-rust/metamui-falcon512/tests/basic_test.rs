//! Basic integration test for Falcon-512

use metamui_falcon512::{generate_keypair, sign, verify, N, Q};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn test_basic_functionality() {
    // Test key generation
    let mut rng = StdRng::seed_from_u64(12345);
    let keypair = generate_keypair(&mut rng).expect("Key generation should work");
    
    // Test signing
    let message = b"Test message for Falcon-512";
    let signature = sign(message, &keypair.private_key, &mut rng).expect("Signing should work");
    
    // Falcon-512 signatures are variable size
    // Simple compression: ~2089 bytes (header + salt + 2*512*2)
    // NIST compression: ≤666 bytes
    assert!(signature.len() > 0);
    assert!(signature.len() <= 2100); // Max signature size for simple compression
    
    // Test verification
    let valid = verify(message, &signature, &keypair.public_key).expect("Verification should work");
    assert!(valid);
}

#[test]
fn test_constants() {
    assert_eq!(N, 512);
    assert_eq!(Q, 12289);
}

#[test]
fn test_wrong_signature() {
    let mut rng = StdRng::seed_from_u64(12345);
    let keypair = generate_keypair(&mut rng).expect("Key generation should work");
    
    let message = b"Test message";
    let signature = sign(message, &keypair.private_key, &mut rng).expect("Signing should work");
    
    // Verify with wrong message should fail
    let wrong_message = b"Wrong message";
    let valid = verify(wrong_message, &signature, &keypair.public_key).expect("Verification should complete");
    assert!(!valid);
}

#[test]
fn test_wrong_key() {
    let mut rng1 = StdRng::seed_from_u64(12345);
    let keypair1 = generate_keypair(&mut rng1).expect("Key generation should work");
    
    let mut rng2 = StdRng::seed_from_u64(67890);
    let keypair2 = generate_keypair(&mut rng2).expect("Key generation should work");
    
    let message = b"Test message";
    let signature = sign(message, &keypair1.private_key, &mut rng1).expect("Signing should work");
    
    // Verify with wrong public key should fail
    let valid = verify(message, &signature, &keypair2.public_key).expect("Verification should complete");
    assert!(!valid);
}
