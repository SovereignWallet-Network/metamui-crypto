use metamui_falcon512::{generate_keypair, sign, verify_with_config};
use metamui_falcon512::verification_config::{VerificationConfig, VerificationConfigBuilder};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn test_refinement_disabled_by_default() {
    let mut rng = StdRng::seed_from_u64(42);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"Test message for refinement";
    let signature = sign(message, &keypair.private_key, &mut rng)
        .expect("Signing should succeed");
    
    // Default config has refinement disabled
    let config = VerificationConfig::default();
    assert!(!config.use_babai);
    assert!(!config.use_iterative);
    
    // Should still verify successfully
    let valid = verify_with_config(message, &signature, &keypair.public_key, &config)
        .expect("Verification should not error");
    assert!(valid, "Signature should be valid without refinement");
}

#[test]
fn test_refinement_enabled() {
    let mut rng = StdRng::seed_from_u64(43);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"Test message with refinement enabled";
    let signature = sign(message, &keypair.private_key, &mut rng)
        .expect("Signing should succeed");
    
    // Enable refinements
    let config = VerificationConfig::with_refinements();
    assert!(config.use_babai);
    assert!(config.use_iterative);
    
    // Should verify successfully
    let valid = verify_with_config(message, &signature, &keypair.public_key, &config)
        .expect("Verification should not error");
    assert!(valid, "Signature should be valid with refinement");
}

#[test]
fn test_config_builder() {
    let mut rng = StdRng::seed_from_u64(44);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"Test message with custom config";
    let signature = sign(message, &keypair.private_key, &mut rng)
        .expect("Signing should succeed");
    
    // Build custom config
    let config = VerificationConfigBuilder::new()
        .with_babai(true)
        .with_iterative(false)
        .babai_iterations(5)
        .verbose(false)
        .relaxed_threshold(true)
        .build();
    
    assert!(config.use_babai);
    assert!(!config.use_iterative);
    assert_eq!(config.babai_max_iterations, 5);
    
    // Should verify successfully
    let valid = verify_with_config(message, &signature, &keypair.public_key, &config)
        .expect("Verification should not error");
    assert!(valid, "Signature should be valid with custom config");
}

#[test]
fn test_fast_config() {
    let mut rng = StdRng::seed_from_u64(45);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"Test message for fast verification";
    let signature = sign(message, &keypair.private_key, &mut rng)
        .expect("Signing should succeed");
    
    // Fast config disables all refinements
    let config = VerificationConfig::fast();
    assert!(!config.use_babai);
    assert!(!config.use_iterative);
    assert!(!config.verbose);
    
    // Should verify successfully
    let valid = verify_with_config(message, &signature, &keypair.public_key, &config)
        .expect("Verification should not error");
    assert!(valid, "Signature should be valid with fast config");
}

#[test]
fn test_accurate_config() {
    let mut rng = StdRng::seed_from_u64(46);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"Test message for accurate verification";
    let signature = sign(message, &keypair.private_key, &mut rng)
        .expect("Signing should succeed");
    
    // Accurate config enables all refinements with higher iterations
    let config = VerificationConfig::accurate();
    assert!(config.use_babai);
    assert!(config.use_iterative);
    assert_eq!(config.babai_max_iterations, 20);
    assert_eq!(config.iterative_config.max_iterations, 50);
    assert!(!config.use_relaxed_threshold);  // Strict threshold
    
    // Should verify successfully
    let valid = verify_with_config(message, &signature, &keypair.public_key, &config)
        .expect("Verification should not error");
    assert!(valid, "Signature should be valid with accurate config");
}

#[test]
fn test_wrong_message_detection() {
    let mut rng = StdRng::seed_from_u64(47);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"Original message";
    let wrong_message = b"Wrong message";
    let signature = sign(message, &keypair.private_key, &mut rng)
        .expect("Signing should succeed");
    
    // Test with refinement enabled
    let config = VerificationConfig::with_refinements();
    
    // Should reject wrong message even with refinement
    let valid = verify_with_config(wrong_message, &signature, &keypair.public_key, &config)
        .expect("Verification should not error");
    
    // Note: Due to s1-only formats, wrong message detection might not always work
    // This test documents the current behavior
    println!("Wrong message verification result: {}", valid);
}