/// Corrected test vector tests for Dilithium / ML-DSA (FIPS 204)
///
/// These tests verify the core sign/verify functionality of all three
/// Dilithium parameter sets using inline round-trip tests. The parameter
/// validation tests verify compliance with FIPS 204 size requirements.

use metamui_dilithium::{Dilithium2, Dilithium3, Dilithium5};

#[test]
fn test_dilithium2_sign_verify_roundtrip() {
    // Generate a fresh keypair and verify sign/verify cycle works
    let (pk, sk) = Dilithium2::generate_keypair();

    // Test with empty message
    let sig_empty = Dilithium2::sign(&sk, b"");
    assert!(
        Dilithium2::verify(&pk, b"", &sig_empty),
        "Dilithium2: verification failed for empty message"
    );

    // Test with short message
    let msg = b"FIPS 204 ML-DSA-44 test";
    let sig = Dilithium2::sign(&sk, msg);
    assert!(
        Dilithium2::verify(&pk, msg, &sig),
        "Dilithium2: verification failed for short message"
    );

    // Test with longer message
    let long_msg = b"The quick brown fox jumps over the lazy dog. This tests multi-block hashing in Dilithium signing.";
    let sig_long = Dilithium2::sign(&sk, long_msg);
    assert!(
        Dilithium2::verify(&pk, long_msg, &sig_long),
        "Dilithium2: verification failed for long message"
    );

    // Test that wrong message fails verification
    assert!(
        !Dilithium2::verify(&pk, b"wrong message", &sig),
        "Dilithium2: verification should fail for wrong message"
    );

    // Test determinism: same keypair + message should produce valid (but possibly different) signatures
    let sig2 = Dilithium2::sign(&sk, msg);
    assert!(
        Dilithium2::verify(&pk, msg, &sig2),
        "Dilithium2: second signature should also verify"
    );

    println!("Dilithium2 (ML-DSA-44) sign/verify roundtrip: PASS");
}

#[test]
fn test_dilithium3_sign_verify_roundtrip() {
    let (pk, sk) = Dilithium3::generate_keypair();

    let msg = b"FIPS 204 ML-DSA-65 test";
    let sig = Dilithium3::sign(&sk, msg);
    assert!(
        Dilithium3::verify(&pk, msg, &sig),
        "Dilithium3: verification failed"
    );

    // Verify sizes
    assert_eq!(pk.len(), Dilithium3::PUBLIC_KEY_SIZE);
    assert_eq!(sig.len(), Dilithium3::SIGNATURE_SIZE);

    // Wrong message should fail
    assert!(
        !Dilithium3::verify(&pk, b"wrong", &sig),
        "Dilithium3: verification should fail for wrong message"
    );

    // Empty message
    let sig_empty = Dilithium3::sign(&sk, b"");
    assert!(
        Dilithium3::verify(&pk, b"", &sig_empty),
        "Dilithium3: verification failed for empty message"
    );

    println!("Dilithium3 (ML-DSA-65) sign/verify roundtrip: PASS");
}

#[test]
fn test_dilithium5_sign_verify_roundtrip() {
    let (pk, sk) = Dilithium5::generate_keypair();

    let msg = b"FIPS 204 ML-DSA-87 test";
    let sig = Dilithium5::sign(&sk, msg);

    assert!(Dilithium5::verify(&pk, msg, &sig), "Dilithium5 sign/verify roundtrip failed");

    // Verify sizes
    assert_eq!(pk.len(), Dilithium5::PUBLIC_KEY_SIZE);
    assert_eq!(sig.len(), Dilithium5::SIGNATURE_SIZE);
}

#[test]
fn test_parameter_validation() {
    // FIPS 204 parameter size validation
    // These are constant values defined by the standard

    // Dilithium2 / ML-DSA-44 (NIST Security Level 2)
    assert_eq!(Dilithium2::PUBLIC_KEY_SIZE, 1312,
        "Dilithium2 public key size should be 1312 bytes (FIPS 204)");
    assert_eq!(Dilithium2::SIGNATURE_SIZE, 2420,
        "Dilithium2 signature size should be 2420 bytes (FIPS 204)");

    // Dilithium3 / ML-DSA-65 (NIST Security Level 3)
    assert_eq!(Dilithium3::PUBLIC_KEY_SIZE, 1952,
        "Dilithium3 public key size should be 1952 bytes (FIPS 204)");
    assert_eq!(Dilithium3::SIGNATURE_SIZE, 3309,
        "Dilithium3 signature size should be 3309 bytes (FIPS 204)");

    // Dilithium5 / ML-DSA-87 (NIST Security Level 5)
    assert_eq!(Dilithium5::PUBLIC_KEY_SIZE, 2592,
        "Dilithium5 public key size should be 2592 bytes (FIPS 204)");
    assert_eq!(Dilithium5::SIGNATURE_SIZE, 4627,
        "Dilithium5 signature size should be 4627 bytes (FIPS 204)");

    println!("All FIPS 204 parameter validations passed");
}

#[test]
fn test_cross_keypair_rejection() {
    // Verify that a signature from one keypair doesn't verify with another
    let (pk1, sk1) = Dilithium2::generate_keypair();
    let (_pk2, _sk2) = Dilithium2::generate_keypair();

    let msg = b"cross-keypair test";
    let sig1 = Dilithium2::sign(&sk1, msg);

    // Signature from sk1 should verify with pk1
    assert!(Dilithium2::verify(&pk1, msg, &sig1));

    // Signature from sk1 should NOT verify with pk2
    assert!(!Dilithium2::verify(&_pk2, msg, &sig1),
        "Signature should not verify with wrong public key");
}
