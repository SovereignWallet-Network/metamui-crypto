//! Statistical validation tests for Falcon-512
//! 
//! These tests validate the probabilistic behavior of Falcon-512's
//! rejection sampling in key generation and signing operations.

use metamui_falcon512::{generate_keypair, sign, verify};
use metamui_falcon512::test_config::{PqcTestConfig, PqcTestResult};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

#[test]
fn test_keygen_success_rate() {
    let config = PqcTestConfig::for_statistical_tests();
    let mut rng = ChaCha20Rng::from_entropy();
    
    println!("=== Falcon-512 Key Generation Statistical Test ===");
    println!("Running {} iterations...", config.statistical_iterations);
    
    let start = Instant::now();
    let mut successes = 0;
    let mut total_attempts = 0;
    
    for i in 0..config.statistical_iterations {
        let mut attempts_for_this_key = 0;
        let mut success = false;
        
        for _ in 0..config.max_keygen_attempts {
            attempts_for_this_key += 1;
            total_attempts += 1;
            
            if generate_keypair(&mut rng).is_ok() {
                successes += 1;
                success = true;
                break;
            }
        }
        
        if !success && (i + 1) % 10 == 0 {
            println!("  Warning: Key generation {} failed after {} attempts", 
                     i + 1, attempts_for_this_key);
        }
    }
    
    let duration = start.elapsed();
    let result = PqcTestResult::new(
        config.statistical_iterations,
        successes,
        config.min_keygen_success_rate,
    );
    
    println!("\n📊 Key Generation Statistics:");
    println!("  Total iterations: {}", config.statistical_iterations);
    println!("  Successful: {}", successes);
    println!("  Success rate: {:.2}%", result.success_rate * 100.0);
    println!("  Average attempts per success: {:.2}", 
             total_attempts as f64 / successes as f64);
    println!("  Time: {:.2}s", duration.as_secs_f64());
    println!("  Result: {}", result.description());
    
    // Falcon-512 specification expects ~70-90% success rate for key generation
    assert!(
        result.is_pass(),
        "Key generation success rate {:.2}% is below minimum {:.2}%",
        result.success_rate * 100.0,
        config.min_keygen_success_rate * 100.0
    );
}

#[test]
fn test_signing_success_rate() {
    let config = PqcTestConfig::for_statistical_tests();
    let mut rng = ChaCha20Rng::from_entropy();
    
    println!("=== Falcon-512 Signing Statistical Test ===");
    
    // Generate a keypair for signing tests
    let keypair = (0..config.max_keygen_attempts)
        .find_map(|_| generate_keypair(&mut rng).ok())
        .expect("Should generate at least one keypair");
    
    println!("Running {} signing iterations...", config.statistical_iterations);
    
    let messages = [
        b"".as_slice(),
        b"Short message",
        b"The quick brown fox jumps over the lazy dog",
        &vec![0xAAu8; 1000],
    ];
    
    let start = Instant::now();
    let mut total_successes = 0;
    let mut total_attempts = 0;
    
    for msg_idx in 0..config.statistical_iterations {
        let message = messages[msg_idx % messages.len()];
        let mut attempts_for_this_sig = 0;
        let mut success = false;
        
        for _ in 0..config.max_sign_attempts {
            attempts_for_this_sig += 1;
            total_attempts += 1;
            
            if let Ok(signature) = sign(message, &keypair.private_key, &mut rng) {
                // Verify the signature works
                if verify(message, &signature, &keypair.public_key).unwrap_or(false) {
                    total_successes += 1;
                    success = true;
                    break;
                }
            }
        }
        
        if !success && (msg_idx + 1) % 100 == 0 {
            println!("  Warning: Signing iteration {} failed after {} attempts", 
                     msg_idx + 1, attempts_for_this_sig);
        }
    }
    
    let duration = start.elapsed();
    let result = PqcTestResult::new(
        config.statistical_iterations,
        total_successes,
        config.min_sign_success_rate,
    );
    
    println!("\n📊 Signing Statistics:");
    println!("  Total iterations: {}", config.statistical_iterations);
    println!("  Successful: {}", total_successes);
    println!("  Success rate: {:.2}%", result.success_rate * 100.0);
    println!("  Average attempts per success: {:.2}", 
             total_attempts as f64 / total_successes.max(1) as f64);
    println!("  Time: {:.2}s", duration.as_secs_f64());
    println!("  Result: {}", result.description());
    
    // Falcon-512 specification expects ~80-95% success rate for signing
    assert!(
        result.is_pass(),
        "Signing success rate {:.2}% is below minimum {:.2}%",
        result.success_rate * 100.0,
        config.min_sign_success_rate * 100.0
    );
}

#[test]
fn test_rejection_sampling_distribution() {
    let mut rng = ChaCha20Rng::from_entropy();
    
    println!("=== Falcon-512 Rejection Sampling Distribution Test ===");
    
    // Track how many attempts are needed for successful operations
    let mut keygen_attempts_histogram = vec![0u32; 20];
    let mut sign_attempts_histogram = vec![0u32; 20];
    
    // Test key generation distribution
    println!("Testing key generation attempt distribution...");
    for _ in 0..100 {
        let mut attempts = 0;
        for _ in 0..20 {
            attempts += 1;
            if generate_keypair(&mut rng).is_ok() {
                keygen_attempts_histogram[attempts.min(19) - 1] += 1;
                break;
            }
        }
    }
    
    // Generate keypair for signing tests
    let keypair = (0..10)
        .find_map(|_| generate_keypair(&mut rng).ok())
        .expect("Should generate keypair");
    
    // Test signing distribution
    println!("Testing signing attempt distribution...");
    let message = b"Test message for distribution analysis";
    for _ in 0..100 {
        let mut attempts = 0;
        for _ in 0..20 {
            attempts += 1;
            if sign(message, &keypair.private_key, &mut rng).is_ok() {
                sign_attempts_histogram[attempts.min(19) - 1] += 1;
                break;
            }
        }
    }
    
    // Print distributions
    println!("\n📊 Key Generation Attempt Distribution:");
    for (i, count) in keygen_attempts_histogram.iter().enumerate() {
        if *count > 0 {
            let bar = "█".repeat((*count as usize * 40 / 100).max(1));
            println!("  {} attempts: {:3} {}", i + 1, count, bar);
        }
    }
    
    println!("\n📊 Signing Attempt Distribution:");
    for (i, count) in sign_attempts_histogram.iter().enumerate() {
        if *count > 0 {
            let bar = "█".repeat((*count as usize * 40 / 100).max(1));
            println!("  {} attempts: {:3} {}", i + 1, count, bar);
        }
    }
    
    // Check that most operations succeed within first few attempts
    let keygen_first_three: u32 = keygen_attempts_histogram[..3.min(keygen_attempts_histogram.len())].iter().sum();
    let sign_first_three: u32 = sign_attempts_histogram[..3.min(sign_attempts_histogram.len())].iter().sum();
    
    println!("\n📊 Summary:");
    println!("  Key generation success in first 3 attempts: {}%", keygen_first_three);
    println!("  Signing success in first 3 attempts: {}%", sign_first_three);
    
    // Most operations should succeed quickly
    assert!(
        keygen_first_three >= 60,
        "Too few key generations succeeded quickly: {}%",
        keygen_first_three
    );
    assert!(
        sign_first_three >= 70,
        "Too few signings succeeded quickly: {}%",
        sign_first_three
    );
}

#[test]
#[ignore] // Long-running test, run with --ignored
fn test_extreme_statistical_validation() {
    let mut rng = ChaCha20Rng::from_entropy();
    
    println!("=== Falcon-512 Extreme Statistical Validation (10,000 iterations) ===");
    
    let iterations = 10_000;
    let mut keygen_successes = 0;
    let mut sign_successes = 0;
    
    let start = Instant::now();
    
    // Test key generation
    for i in 0..iterations {
        if generate_keypair(&mut rng).is_ok() {
            keygen_successes += 1;
        }
        
        if (i + 1) % 1000 == 0 {
            println!("  Progress: {}/{} iterations", i + 1, iterations);
        }
    }
    
    // Generate keypair for signing tests
    let keypair = (0..10)
        .find_map(|_| generate_keypair(&mut rng).ok())
        .expect("Should generate keypair");
    
    let message = b"Statistical validation message";
    
    // Test signing
    for _ in 0..iterations {
        if sign(message, &keypair.private_key, &mut rng).is_ok() {
            sign_successes += 1;
        }
    }
    
    let duration = start.elapsed();
    
    let keygen_rate = keygen_successes as f64 / iterations as f64;
    let sign_rate = sign_successes as f64 / iterations as f64;
    
    println!("\n📊 Extreme Statistical Results:");
    println!("  Iterations: {}", iterations);
    println!("  Key generation success rate: {:.4}% ({}/{})", 
             keygen_rate * 100.0, keygen_successes, iterations);
    println!("  Signing success rate: {:.4}% ({}/{})", 
             sign_rate * 100.0, sign_successes, iterations);
    println!("  Total time: {:.2}s", duration.as_secs_f64());
    println!("  Operations per second: {:.0}", 
             (iterations * 2) as f64 / duration.as_secs_f64());
    
    // With large sample size, rates should converge to expected values
    assert!(
        keygen_rate >= 0.65 && keygen_rate <= 0.95,
        "Key generation rate {:.2}% outside expected range [65%, 95%]",
        keygen_rate * 100.0
    );
    assert!(
        sign_rate >= 0.75 && sign_rate <= 0.98,
        "Signing rate {:.2}% outside expected range [75%, 98%]",
        sign_rate * 100.0
    );
}