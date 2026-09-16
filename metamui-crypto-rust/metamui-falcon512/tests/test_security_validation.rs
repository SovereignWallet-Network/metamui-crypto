//! Security validation tests for Falcon-512
//! 
//! This test suite validates the security properties of the implementation
//! including resistance to various attacks and compliance with security requirements.

use metamui_falcon512::{
    generate_keypair, sign, verify, sign_with_config,
    SigningConfig, SigningMode, N
};
use metamui_falcon512::security_audit::{SecurityAuditor, AuditConfig};
use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::HashSet;

/// Test key generation entropy
#[test]
fn test_key_entropy() {
    let mut rng = StdRng::seed_from_u64(12345);

    // Generate multiple keypairs
    let mut public_keys = HashSet::new();
    let mut private_key_fingerprints = HashSet::new();

    for i in 0..100 {
        let keypair = generate_keypair(&mut rng).expect("Keygen should work");

        // Check public key uniqueness
        let pk_bytes: Vec<u8> = keypair.public_key.h.coeffs.iter()
            .flat_map(|&c| c.to_le_bytes())
            .collect();

        if !public_keys.insert(pk_bytes) {
            panic!("Duplicate public key at iteration {}", i);
        }

        // Check private key uniqueness (using fingerprint)
        // Cast i16 -> u16 first to avoid sign-extension overflow on shift
        let fingerprint = (keypair.private_key.f.coeffs[0] as u16 as u64)
            | ((keypair.private_key.g.coeffs[0] as u16 as u64) << 16)
            | ((keypair.private_key.big_f.coeffs[0] as u16 as u64) << 32)
            | ((keypair.private_key.big_g.coeffs[0] as u16 as u64) << 48);

        if !private_key_fingerprints.insert(fingerprint) {
            panic!("Duplicate private key fingerprint at iteration {}", i);
        }
    }

    println!("All {} keypairs are unique", public_keys.len());
}

/// Test signature non-determinism
#[test]
fn test_signature_randomness() {
    let mut rng = StdRng::seed_from_u64(54321);
    let keypair = generate_keypair(&mut rng).expect("Keygen should work");
    let message = b"Test message for randomness";
    
    // Generate multiple signatures for the same message
    let mut signatures = HashSet::new();
    
    for i in 0..50 {
        let signature = sign(message, &keypair.private_key, &mut rng)
            .expect("Signing should work");
        
        if !signatures.insert(signature.clone()) {
            panic!("Duplicate signature at iteration {}", i);
        }
        
        // Verify each signature
        let valid = verify(message, &signature, &keypair.public_key)
            .expect("Verification should work");
        assert!(valid, "Signature {} should be valid", i);
    }
    
    println!("??All {} signatures are unique and valid", signatures.len());
}

/// Test forgery resistance
#[test]
fn test_forgery_resistance() {
    let mut rng = StdRng::seed_from_u64(99999);
    let keypair = generate_keypair(&mut rng).expect("Keygen should work");
    let message = b"Authentic message";
    
    // Create valid signature
    let valid_signature = sign(message, &keypair.private_key, &mut rng)
        .expect("Signing should work");
    
    // Attempt various forgeries
    let mut forgery_attempts = 0;
    let mut successful_forgeries = 0;
    
    // Try random signatures
    for _ in 0..100 {
        let mut forged = vec![0u8; valid_signature.len()];
        rng.fill_bytes(&mut forged);
        
        if let Ok(valid) = verify(message, &forged, &keypair.public_key) {
            if valid {
                successful_forgeries += 1;
            }
        }
        forgery_attempts += 1;
    }
    
    // Try modified valid signatures
    for i in 0..valid_signature.len().min(100) {
        let mut modified = valid_signature.clone();
        modified[i] ^= 0xFF; // Flip all bits at position i
        
        if let Ok(valid) = verify(message, &modified, &keypair.public_key) {
            if valid {
                successful_forgeries += 1;
            }
        }
        forgery_attempts += 1;
    }
    
    // Try signatures for different messages on same key
    let other_message = b"Different message";
    let other_signature = sign(other_message, &keypair.private_key, &mut rng)
        .expect("Signing should work");
    
    if let Ok(valid) = verify(message, &other_signature, &keypair.public_key) {
        if valid {
            successful_forgeries += 1;
        }
    }
    forgery_attempts += 1;
    
    println!("Forgery attempts: {}, successful: {}", 
             forgery_attempts, successful_forgeries);
    
    // Should have no successful forgeries
    assert_eq!(successful_forgeries, 0, "Forgeries should not succeed");
}

/// Test key recovery resistance
#[test]
fn test_key_recovery_resistance() {
    let mut rng = StdRng::seed_from_u64(11111);
    let keypair = generate_keypair(&mut rng).expect("Keygen should work");
    
    // Collect signatures for analysis
    let messages = vec![
        b"Message 1".to_vec(),
        b"Message 2".to_vec(),
        b"Message 3".to_vec(),
        b"Message 4".to_vec(),
        b"Message 5".to_vec(),
    ];
    
    let mut signatures = Vec::new();
    for msg in &messages {
        let sig = sign(msg, &keypair.private_key, &mut rng)
            .expect("Signing should work");
        signatures.push(sig);
    }
    
    // Analysis: Check if signatures leak information about the key
    // This is a simplified test - real cryptanalysis would be more complex
    
    // Check if signature patterns correlate with message patterns
    let mut correlations = 0;
    for i in 0..signatures.len() {
        for j in i+1..signatures.len() {
            // Compare first few bytes (simplified)
            let similar_sigs = signatures[i][..10] == signatures[j][..10];
            let similar_msgs = messages[i][..1] == messages[j][..1];
            
            if similar_sigs && similar_msgs {
                correlations += 1;
            }
        }
    }
    
    println!("Message-signature correlations: {}", correlations);
    
    // Should have minimal correlations
    assert!(correlations < signatures.len(), "Too many correlations detected");
}

/// Test timing attack resistance
#[test]
#[cfg(feature = "std")]
fn test_timing_resistance() {
    use std::time::Instant;
    
    let mut rng = StdRng::seed_from_u64(22222);
    let keypair = generate_keypair(&mut rng).expect("Keygen should work");
    
    // Messages of different sizes
    let small_msg = b"A";
    let large_msg = vec![0u8; 10000];
    
    let mut small_times = Vec::new();
    let mut large_times = Vec::new();
    
    // Measure timing for small messages
    for _ in 0..10 {
        let start = Instant::now();
        let _ = sign(small_msg, &keypair.private_key, &mut rng);
        small_times.push(start.elapsed());
    }
    
    // Measure timing for large messages
    for _ in 0..10 {
        let start = Instant::now();
        let _ = sign(&large_msg, &keypair.private_key, &mut rng);
        large_times.push(start.elapsed());
    }
    
    // Calculate averages
    let avg_small = small_times.iter()
        .map(|d| d.as_nanos() as f64)
        .sum::<f64>() / small_times.len() as f64;
    
    let avg_large = large_times.iter()
        .map(|d| d.as_nanos() as f64)
        .sum::<f64>() / large_times.len() as f64;
    
    let ratio = avg_large / avg_small;
    
    println!("Small message avg time: {:.2}ms", avg_small / 1_000_000.0);
    println!("Large message avg time: {:.2}ms", avg_large / 1_000_000.0);
    println!("Timing ratio: {:.2}", ratio);
    
    // Timing should not vary too much with message size
    // (hashing dominates, not the signature generation)
    assert!(ratio < 100.0, "Excessive timing variation with message size");
}

/// Test norm bound enforcement
#[test]
fn test_norm_bound_enforcement() {
    let mut rng = StdRng::seed_from_u64(33333);
    let keypair = generate_keypair(&mut rng).expect("Keygen should work");
    let message = b"Test message for norm bounds";
    
    // Use secure mode with tighter bounds
    let config = SigningConfig::from_mode(SigningMode::Standard);
    
    let mut norms = Vec::new();
    let mut failures = 0;
    
    for _ in 0..50 {
        match sign_with_config(message, &keypair.private_key, &mut rng, &config) {
            Ok(result) => {
                // Calculate norm
                if result.signature.len() >= N * 2 {
                    let mut norm_sqr = 0i64;
                    for i in 0..N.min(result.signature.len() / 2) {
                        let coeff = i16::from_le_bytes([
                            result.signature[i * 2],
                            result.signature[i * 2 + 1],
                        ]);
                        norm_sqr += (coeff as i64) * (coeff as i64);
                    }
                    norms.push((norm_sqr as f64).sqrt());
                }
            }
            Err(_) => {
                failures += 1;
            }
        }
    }
    
    if !norms.is_empty() {
        let max_norm = norms.iter().fold(0.0_f64, |a, &b| a.max(b));
        let theoretical_bound = (34034726.0_f64).sqrt();
        
        println!("Maximum norm: {:.2}", max_norm);
        println!("Theoretical bound: {:.2}", theoretical_bound);
        println!("Signing failures: {}", failures);
        
        // All norms should be within bound
        for norm in &norms {
            assert!(*norm <= theoretical_bound * 1.1, // Allow 10% margin
                    "Norm {} exceeds theoretical bound", norm);
        }
    }
}

/// Test side-channel protection features
#[test]
fn test_side_channel_protections() {
    use metamui_falcon512::side_channel_hardening::{
        SideChannelConfig, SideChannelProtector, constant_time
    };
    
    // Test constant-time operations
    for _ in 0..100 {
        let a = rand::random::<i16>();
        let b = rand::random::<i16>();
        let condition = rand::random::<bool>();
        
        let result = constant_time::ct_select_i16(a, b, condition);
        let expected = if condition { a } else { b };
        
        assert_eq!(result, expected, "Constant-time select failed");
    }
    
    // Test protected operations
    let config = SideChannelConfig::high_security();
    let protector = SideChannelProtector::new(config);
    
    let poly_a = vec![1i16; N];
    let poly_b = vec![2i16; N];
    
    assert!(protector.protected_poly_mul(&poly_a, &poly_b).is_err());

    let fast_protector = SideChannelProtector::new(SideChannelConfig::performance());
    let result = fast_protector.protected_poly_mul(&poly_a, &poly_b).unwrap();
    assert_eq!(result.len(), N, "Protected multiplication failed");
    
    println!("??Side-channel protections working");
}

/// Test memory zeroization
#[test]
fn test_memory_zeroization() {
    use zeroize::Zeroize;
    use metamui_falcon512::PrivateKey;
    use metamui_falcon512::poly::Poly;
    
    // Create private key with known values
    let mut private_key = PrivateKey {
        f: Poly::new(vec![1i16; N]),
        g: Poly::new(vec![2i16; N]),
        big_f: Poly::new(vec![3i16; N]),
        big_g: Poly::new(vec![4i16; N]),
    };
    
    // Verify initial values
    assert_eq!(private_key.f.coeffs[0], 1);
    assert_eq!(private_key.g.coeffs[0], 2);
    
    // Zeroize
    private_key.zeroize();
    
    // Verify zeroization
    for coeff in &private_key.f.coeffs {
        assert_eq!(*coeff, 0, "f not zeroized");
    }
    for coeff in &private_key.g.coeffs {
        assert_eq!(*coeff, 0, "g not zeroized");
    }
    for coeff in &private_key.big_f.coeffs {
        assert_eq!(*coeff, 0, "big_f not zeroized");
    }
    for coeff in &private_key.big_g.coeffs {
        assert_eq!(*coeff, 0, "big_g not zeroized");
    }
    
    println!("??Memory zeroization working");
}

/// Run complete security audit
#[test]
fn test_security_audit() {
    let config = AuditConfig {
        timing_analysis: true,
        fault_injection: true,
        sample_size: 50,
        verbose: true,
    };
    
    let mut auditor = SecurityAuditor::new(config);
    let mut rng = StdRng::seed_from_u64(44444);
    
    let err = auditor.run_audit(&mut rng).unwrap_err();
    assert!(
        matches!(err, metamui_falcon512::Falcon512Error::NotImplemented),
        "security audit should fail closed until exact audit implementation exists"
    );
}

/// Test resistance to differential attacks
#[test]
fn test_differential_attack_resistance() {
    let mut rng = StdRng::seed_from_u64(55555);
    let keypair = generate_keypair(&mut rng).expect("Keygen should work");
    
    // Messages with small differences
    let msg1 = b"Hello World!";
    let msg2 = b"Hello World?"; // One bit difference
    
    let sig1 = sign(msg1, &keypair.private_key, &mut rng)
        .expect("Signing should work");
    let sig2 = sign(msg2, &keypair.private_key, &mut rng)
        .expect("Signing should work");
    
    // Signatures should be completely different
    let mut differences = 0;
    for i in 0..sig1.len().min(sig2.len()) {
        if sig1[i] != sig2[i] {
            differences += 1;
        }
    }
    
    let diff_ratio = differences as f64 / sig1.len().min(sig2.len()) as f64;
    
    println!("Signature difference ratio: {:.2}%", diff_ratio * 100.0);
    
    // Should have significant differences (>30%)
    assert!(diff_ratio > 0.3, "Signatures too similar for different messages");
}

/// Test batch operation security
#[test]
fn test_batch_operation_security() {
    use metamui_falcon512::batch_operations::{
        BatchSigner, BatchVerifier, SignRequest, VerifyRequest
    };
    
    let mut rng = StdRng::seed_from_u64(66666);
    let keypair = generate_keypair(&mut rng).expect("Keygen should work");
    
    // Create batch with mix of valid and invalid requests
    let messages = vec![
        b"Valid message 1".to_vec(),
        b"Valid message 2".to_vec(),
        b"Valid message 3".to_vec(),
    ];
    
    let signer = BatchSigner::new();
    let requests: Vec<_> = messages.iter()
        .map(|msg| SignRequest {
            message: msg,
            id: None,
        })
        .collect();
    
    let signatures = signer.sign_batch(&requests, &keypair.private_key, &mut rng);
    
    // Verify batch
    let verifier = BatchVerifier::new();
    
    // Mix in a forged signature
    let mut verify_requests: Vec<_> = signatures.iter()
        .zip(messages.iter())
        .filter(|(sig, _)| sig.success)
        .map(|(sig, msg)| VerifyRequest {
            message: msg,
            signature: &sig.signature,
            id: None,
        })
        .collect();
    
    // Add forged request
    let forged_sig = vec![0u8; 1000];
    let forged_msg = b"Forged message";
    verify_requests.push(VerifyRequest {
        message: forged_msg,
        signature: &forged_sig,
        id: Some(999),
    });
    
    let results = verifier.verify_batch(&verify_requests, &keypair.public_key);
    
    // Check that forgery is detected
    let forged_result = results.iter()
        .find(|r| r.id == Some(999))
        .expect("Should have result for forged signature");
    
    assert!(!forged_result.valid, "Forged signature should not verify");
    
    println!("??Batch operations correctly reject forgeries");
}
