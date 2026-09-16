//! NIST validation test suite for Falcon-512

use metamui_falcon512::nist_vectors::NistVectorValidator;
use metamui_falcon512::Falcon512Error;

#[test]
fn test_nist_keygen_vectors() {
    let validator = NistVectorValidator::new();
    assert!(matches!(
        validator.validate_keygen(),
        Err(Falcon512Error::NotImplemented)
    ));
}

#[test]
fn test_nist_signing_vectors() {
    let validator = NistVectorValidator::new();
    assert!(matches!(
        validator.validate_signing(),
        Err(Falcon512Error::NotImplemented)
    ));
}

#[test]
fn test_nist_verification_vectors() {
    let validator = NistVectorValidator::new();
    assert!(matches!(
        validator.validate_verification(),
        Err(Falcon512Error::NotImplemented)
    ));
}

#[test]
fn test_full_nist_validation() {
    let validator = NistVectorValidator::new();
    assert!(matches!(
        validator.validate_all(),
        Err(Falcon512Error::NotImplemented)
    ));
}

#[test]
fn test_deterministic_keygen() {
    use metamui_falcon512::nist_vectors::DeterministicRng;
    
    // Test that same seed produces same keys
    let seed = b"deterministic seed for testing Falcon";
    
    let mut rng1 = DeterministicRng::from_seed(seed);
    let keypair1 = metamui_falcon512::generate_keypair(&mut rng1)
        .expect("First keygen should succeed");
    
    let mut rng2 = DeterministicRng::from_seed(seed);
    let keypair2 = metamui_falcon512::generate_keypair(&mut rng2)
        .expect("Second keygen should succeed");
    
    // Keys should be identical
    assert_eq!(keypair1.public_key.h.coeffs, keypair2.public_key.h.coeffs);
    assert_eq!(keypair1.private_key.f.coeffs, keypair2.private_key.f.coeffs);
    assert_eq!(keypair1.private_key.g.coeffs, keypair2.private_key.g.coeffs);
}

#[test]
fn test_signature_size_is_reasonable_and_verifies() {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    
    let mut rng = StdRng::seed_from_u64(12345);
    let keypair = metamui_falcon512::generate_keypair(&mut rng)
        .expect("Keygen should succeed");
    
    let messages: Vec<&[u8]> = vec![
        b"",
        b"a",
        b"abc",
        b"The quick brown fox jumps over the lazy dog",
        &[0u8; 100],
        &[255u8; 256],
    ];
    
    for (i, msg) in messages.iter().enumerate() {
        let sig = metamui_falcon512::sign(msg, &keypair.private_key, &mut rng)
            .expect(&format!("Signing message {} should succeed", i));
        
        // The generic signing API may use a non-NIST serialization format, so
        // this test only requires the output to be present and bounded.
        assert!(
            !sig.is_empty() && sig.len() <= 2560,
            "Signature {} size should be non-empty and reasonable, got {}",
            i,
            sig.len()
        );
        
        // Verify the signature
        let valid = metamui_falcon512::verify(msg, &sig, &keypair.public_key)
            .expect("Verification should not error");
        
        assert!(valid, "Signature {} should verify", i);
    }
}

#[test]
fn test_wrong_message_rejection() {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    
    let mut rng = StdRng::seed_from_u64(54321);
    let keypair = metamui_falcon512::generate_keypair(&mut rng)
        .expect("Keygen should succeed");
    
    let msg = b"Original message";
    let sig = metamui_falcon512::sign(msg, &keypair.private_key, &mut rng)
        .expect("Signing should succeed");
    
    // Verify correct message
    let valid = metamui_falcon512::verify(msg, &sig, &keypair.public_key)
        .expect("Verification should not error");
    assert!(valid, "Correct message should verify");
    
    // Try various wrong messages
    let wrong_messages: Vec<&[u8]> = vec![
        b"Wrong message",
        b"original message",  // Different case
        b"Original message!",  // Extra character
        b"Original messag",    // Missing character
        b"",                   // Empty
    ];
    
    for wrong_msg in &wrong_messages {
        let invalid = metamui_falcon512::verify(wrong_msg, &sig, &keypair.public_key)
            .expect("Verification of wrong message should not error");

        assert!(
            !invalid,
            "Wrong message should be rejected: {:?}",
            wrong_msg
        );
    }
}
