//! Statistical analysis of rejection sampling in Falcon-512
//! 
//! This test suite analyzes:
//! - Rejection rate during signature generation
//! - Distribution of signature norms
//! - Number of attempts needed per signature
//! - Compliance with NIST requirements (max 256 attempts)

use metamui_falcon512::{generate_keypair, sign_with_config, SigningConfig, SigningMode, N};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::HashMap;

/// Statistical data for rejection sampling analysis
#[derive(Debug, Clone)]
struct SamplingStatistics {
    /// Number of successful signatures
    successful: usize,
    /// Number of failed signatures (exceeded max attempts)
    failed: usize,
    /// Distribution of attempts needed
    attempt_distribution: HashMap<usize, usize>,
    /// Signature norm distribution
    norm_distribution: Vec<f64>,
    /// Average attempts per signature
    avg_attempts: f64,
    /// Max attempts seen
    max_attempts: usize,
    /// Min attempts seen
    min_attempts: usize,
}

impl SamplingStatistics {
    fn new() -> Self {
        Self {
            successful: 0,
            failed: 0,
            attempt_distribution: HashMap::new(),
            norm_distribution: Vec::new(),
            avg_attempts: 0.0,
            max_attempts: 0,
            min_attempts: usize::MAX,
        }
    }
    
    fn add_result(&mut self, attempts: usize, norm: f64, success: bool) {
        if success {
            self.successful += 1;
            self.norm_distribution.push(norm);
            *self.attempt_distribution.entry(attempts).or_insert(0) += 1;
            self.max_attempts = self.max_attempts.max(attempts);
            self.min_attempts = self.min_attempts.min(attempts);
        } else {
            self.failed += 1;
        }
    }
    
    fn compute_averages(&mut self) {
        if self.successful > 0 {
            let total_attempts: usize = self.attempt_distribution
                .iter()
                .map(|(&attempts, &count)| attempts * count)
                .sum();
            self.avg_attempts = total_attempts as f64 / self.successful as f64;
        }
    }
    
    fn print_report(&self) {
        println!("\n=== Rejection Sampling Statistics ===");
        println!("Total signatures attempted: {}", self.successful + self.failed);
        println!("Successful: {} ({:.2}%)", 
                 self.successful, 
                 100.0 * self.successful as f64 / (self.successful + self.failed) as f64);
        println!("Failed: {} ({:.2}%)", 
                 self.failed,
                 100.0 * self.failed as f64 / (self.successful + self.failed) as f64);
        
        if self.successful > 0 {
            println!("\n--- Attempts Distribution ---");
            println!("Average attempts: {:.2}", self.avg_attempts);
            println!("Min attempts: {}", self.min_attempts);
            println!("Max attempts: {}", self.max_attempts);
            
            // Show distribution histogram
            let mut sorted_attempts: Vec<_> = self.attempt_distribution.iter().collect();
            sorted_attempts.sort_by_key(|&(attempts, _)| attempts);
            
            println!("\nAttempts histogram:");
            for (&attempts, &count) in sorted_attempts.iter().take(10) {
                let percentage = 100.0 * count as f64 / self.successful as f64;
                let bar = "█".repeat((percentage / 2.0) as usize);
                println!("  {:3} attempts: {:4} ({:5.2}%) {}", 
                         attempts, count, percentage, bar);
            }
            
            // Norm statistics
            if !self.norm_distribution.is_empty() {
                let avg_norm = self.norm_distribution.iter().sum::<f64>() 
                              / self.norm_distribution.len() as f64;
                let min_norm = self.norm_distribution.iter()
                              .fold(f64::INFINITY, |a, &b| a.min(b));
                let max_norm = self.norm_distribution.iter()
                              .fold(f64::NEG_INFINITY, |a, &b| a.max(b));
                
                println!("\n--- Norm Distribution ---");
                println!("Average norm: {:.2}", avg_norm);
                println!("Min norm: {:.2}", min_norm);
                println!("Max norm: {:.2}", max_norm);
                
                // Check against theoretical bound
                let theoretical_bound = 34034726.0_f64.sqrt(); // √34034726 ≈ 5834.2
                println!("Theoretical bound: {:.2}", theoretical_bound);
                
                let violations = self.norm_distribution.iter()
                    .filter(|&&n| n > theoretical_bound)
                    .count();
                println!("Bound violations: {} ({:.2}%)", 
                         violations,
                         100.0 * violations as f64 / self.norm_distribution.len() as f64);
            }
        }
    }
}

/// Compute the squared norm of a signature
fn compute_signature_norm(signature: &[u8]) -> f64 {
    // Parse signature to get s0 and s1
    if signature.len() < N * 4 {
        return 0.0;
    }
    
    let mut norm_squared = 0i64;
    
    // Parse s0
    for i in 0..N {
        let coeff = i16::from_le_bytes([
            signature[i * 2],
            signature[i * 2 + 1],
        ]);
        norm_squared += (coeff as i64) * (coeff as i64);
    }
    
    // Parse s1
    for i in 0..N {
        let coeff = i16::from_le_bytes([
            signature[N * 2 + i * 2],
            signature[N * 2 + i * 2 + 1],
        ]);
        norm_squared += (coeff as i64) * (coeff as i64);
    }
    
    (norm_squared as f64).sqrt()
}

#[test]
fn test_rejection_rate_standard_mode() {
    let mut rng = StdRng::seed_from_u64(42);
    let mut stats = SamplingStatistics::new();
    
    // Generate a test keypair
    let keypair = generate_keypair(&mut rng).expect("Keygen should work");
    
    // Standard mode configuration
    let config = SigningConfig::from_mode(SigningMode::Standard);
    
    // Test 100 signatures
    let num_tests = 100;
    let messages: Vec<Vec<u8>> = (0..num_tests)
        .map(|i| format!("Test message {}", i).into_bytes())
        .collect();
    
    println!("Testing {} signatures in Standard mode...", num_tests);
    
    for (i, message) in messages.iter().enumerate() {
        match sign_with_config(message, &keypair.private_key, &mut rng, &config) {
            Ok(result) => {
                let norm = compute_signature_norm(&result.signature);
                stats.add_result(result.stats.total_attempts, norm, true);
                
                if i % 10 == 0 {
                    print!(".");
                    use std::io::{self, Write};
                    io::stdout().flush().unwrap();
                }
            }
            Err(_) => {
                stats.add_result(config.max_attempts, 0.0, false);
            }
        }
    }
    println!();
    
    stats.compute_averages();
    stats.print_report();
    
    // Assertions
    assert!(stats.successful > 0, "Should have at least some successful signatures");
    assert!(stats.avg_attempts < 10.0, "Average attempts should be reasonable");
    assert!(stats.max_attempts <= config.max_attempts, "Should not exceed max attempts");
}

#[test]
fn test_rejection_rate_secure_mode() {
    let mut rng = StdRng::seed_from_u64(12345);
    let mut stats = SamplingStatistics::new();
    
    // Generate a test keypair
    let keypair = generate_keypair(&mut rng).expect("Keygen should work");
    
    // Secure mode configuration (tighter bounds)
    let config = SigningConfig::from_mode(SigningMode::Nist);
    
    // Test 50 signatures (fewer because secure mode is slower)
    let num_tests = 50;
    let messages: Vec<Vec<u8>> = (0..num_tests)
        .map(|i| format!("Secure message {}", i).into_bytes())
        .collect();
    
    println!("Testing {} signatures in Secure mode...", num_tests);
    
    for (i, message) in messages.iter().enumerate() {
        match sign_with_config(message, &keypair.private_key, &mut rng, &config) {
            Ok(result) => {
                let norm = compute_signature_norm(&result.signature);
                stats.add_result(result.stats.total_attempts, norm, true);
                
                if i % 5 == 0 {
                    print!(".");
                    use std::io::{self, Write};
                    io::stdout().flush().unwrap();
                }
            }
            Err(_) => {
                stats.add_result(config.max_attempts, 0.0, false);
            }
        }
    }
    println!();
    
    stats.compute_averages();
    stats.print_report();
    
    // Assertions for secure mode
    assert!(stats.successful > 0, "Should have at least some successful signatures");
    // Secure mode may need more attempts due to tighter bounds
    assert!(stats.avg_attempts < 50.0, "Average attempts should still be bounded");
}

#[test]
fn test_rejection_rate_fast_mode() {
    let mut rng = StdRng::seed_from_u64(54321);
    let mut stats = SamplingStatistics::new();
    
    // Generate a test keypair
    let keypair = generate_keypair(&mut rng).expect("Keygen should work");
    
    // Fast mode configuration (relaxed bounds)
    let config = SigningConfig::from_mode(SigningMode::Fast);
    
    // Test 200 signatures (more because fast mode is quicker)
    let num_tests = 200;
    let messages: Vec<Vec<u8>> = (0..num_tests)
        .map(|i| format!("Fast message {}", i).into_bytes())
        .collect();
    
    println!("Testing {} signatures in Fast mode...", num_tests);
    
    for (i, message) in messages.iter().enumerate() {
        match sign_with_config(message, &keypair.private_key, &mut rng, &config) {
            Ok(result) => {
                let norm = compute_signature_norm(&result.signature);
                stats.add_result(result.stats.total_attempts, norm, true);
                
                if i % 20 == 0 {
                    print!(".");
                    use std::io::{self, Write};
                    io::stdout().flush().unwrap();
                }
            }
            Err(_) => {
                stats.add_result(config.max_attempts, 0.0, false);
            }
        }
    }
    println!();
    
    stats.compute_averages();
    stats.print_report();
    
    // Assertions for fast mode
    assert!(stats.successful > 0, "Should have at least some successful signatures");
    assert!(stats.avg_attempts < 5.0, "Fast mode should need fewer attempts");
    assert!(stats.failed == 0 || stats.failed < stats.successful / 10, 
            "Fast mode should have very few failures");
}

#[test]
fn test_norm_distribution_consistency() {
    let mut rng = StdRng::seed_from_u64(99999);
    
    // Generate multiple keypairs
    let num_keypairs = 3;
    let keypairs: Vec<_> = (0..num_keypairs)
        .map(|_| generate_keypair(&mut rng).expect("Keygen should work"))
        .collect();
    
    let config = SigningConfig::from_mode(SigningMode::Standard);
    let message = b"Consistency test message";
    
    // Collect norms for each keypair
    let mut norms_by_key: Vec<Vec<f64>> = vec![Vec::new(); num_keypairs];
    
    println!("Testing norm distribution across {} keypairs...", num_keypairs);
    
    for (key_idx, keypair) in keypairs.iter().enumerate() {
        for _ in 0..20 {
            if let Ok(result) = sign_with_config(message, &keypair.private_key, &mut rng, &config) {
                let norm = compute_signature_norm(&result.signature);
                norms_by_key[key_idx].push(norm);
            }
        }
    }
    
    // Compare distributions
    println!("\n--- Norm Distribution by Keypair ---");
    for (i, norms) in norms_by_key.iter().enumerate() {
        if !norms.is_empty() {
            let avg = norms.iter().sum::<f64>() / norms.len() as f64;
            let min = norms.iter().fold(f64::INFINITY, |a, &b| a.min(b));
            let max = norms.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
            
            println!("Keypair {}: avg={:.2}, min={:.2}, max={:.2}, samples={}", 
                     i, avg, min, max, norms.len());
        }
    }
    
    // Check that all keypairs produce similar distributions
    let all_avgs: Vec<f64> = norms_by_key.iter()
        .filter(|n| !n.is_empty())
        .map(|norms| norms.iter().sum::<f64>() / norms.len() as f64)
        .collect();
    
    if all_avgs.len() > 1 {
        let global_avg = all_avgs.iter().sum::<f64>() / all_avgs.len() as f64;
        let max_deviation = all_avgs.iter()
            .map(|&avg| (avg - global_avg).abs() / global_avg)
            .fold(0.0, f64::max);
        
        println!("\nGlobal average norm: {:.2}", global_avg);
        println!("Max relative deviation: {:.2}%", max_deviation * 100.0);
        
        // Norms should be reasonably consistent across keypairs
        assert!(max_deviation < 0.5, "Norm distributions should be consistent");
    }
}

#[test]
fn test_deterministic_mode_consistency() {
    use metamui_falcon512::deterministic_rng::DeterministicRng;
    
    let seed = b"deterministic test seed";
    let message = b"Test message for deterministic mode";
    
    // Generate keypair with deterministic RNG
    let mut rng1 = DeterministicRng::new(seed);
    let keypair = generate_keypair(&mut rng1).expect("Keygen should work");
    
    // Sign the same message multiple times with same seed
    let mut signatures = Vec::new();
    let mut attempts = Vec::new();
    
    for i in 0..5 {
        let mut det_rng = DeterministicRng::new(seed);
        let config = SigningConfig::from_mode(SigningMode::Standard);
        
        match sign_with_config(message, &keypair.private_key, &mut det_rng, &config) {
            Ok(result) => {
                signatures.push(result.signature);
                attempts.push(result.stats.total_attempts);
                println!("Signature {}: {} attempts", i, result.stats.total_attempts);
            }
            Err(e) => {
                panic!("Deterministic signing failed: {:?}", e);
            }
        }
    }
    
    // All signatures should be identical in deterministic mode
    for i in 1..signatures.len() {
        assert_eq!(signatures[0], signatures[i], 
                   "Deterministic signatures should be identical");
        assert_eq!(attempts[0], attempts[i],
                   "Deterministic mode should use same number of attempts");
    }
    
    println!("✓ Deterministic mode produces consistent signatures");
}