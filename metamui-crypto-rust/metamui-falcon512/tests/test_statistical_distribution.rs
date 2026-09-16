//! Statistical tests for Falcon-512 signature distribution
//! 
//! These tests verify the non-deterministic nature of signatures
//! and validate the statistical properties of the distribution.

use metamui_falcon512::{generate_keypair, sign, verify, sign_with_config};
use metamui_falcon512::retry_strategy::{SigningConfig, SigningMode};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::HashSet;

/// Test that signatures are unique (non-deterministic)
#[test]
fn test_signature_uniqueness() {
    let mut rng = StdRng::seed_from_u64(12345);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"Test message for uniqueness";
    let num_signatures = 100;
    
    let mut signatures = HashSet::new();
    
    for i in 0..num_signatures {
        let signature = sign(message, &keypair.private_key, &mut rng)
            .expect(&format!("Signing should succeed (attempt {})", i));
        
        // Each signature should be unique
        assert!(
            signatures.insert(signature.clone()),
            "Duplicate signature found at iteration {}", i
        );
        
        // All signatures should verify
        assert!(
            verify(message, &signature, &keypair.public_key).unwrap(),
            "Signature {} should verify", i
        );
    }
    
    println!("Generated {} unique signatures", signatures.len());
    assert_eq!(signatures.len(), num_signatures);
}

/// Test signature norm distribution
#[test]
fn test_signature_norm_distribution() {
    let mut rng = StdRng::seed_from_u64(42);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let message = b"Test message for norm distribution";
    let num_samples = 1000;
    
    let mut norms = Vec::new();
    let mut retry_counts = Vec::new();
    
    // Use NIST mode for proper retry tracking
    let config = SigningConfig::from_mode(SigningMode::Nist);
    
    for _ in 0..num_samples {
        let result = sign_with_config(message, &keypair.private_key, &mut rng, &config)
            .expect("Signing should succeed");
        
        // Decode signature to compute norm
        let signature = result.signature;
        let norm_sq = compute_signature_norm(&keypair.public_key, message, &signature);
        norms.push(norm_sq);
        
        // Track retry statistics
        retry_counts.push(result.stats.total_attempts);
    }
    
    // Analyze norm distribution
    let mean_norm = norms.iter().sum::<i64>() as f64 / norms.len() as f64;
    let variance = norms.iter()
        .map(|&n| (n as f64 - mean_norm).powi(2))
        .sum::<f64>() / norms.len() as f64;
    let std_dev = variance.sqrt();
    
    // Analyze retry distribution
    let mean_retries = retry_counts.iter().sum::<usize>() as f64 / retry_counts.len() as f64;
    let max_retries = *retry_counts.iter().max().unwrap();
    let min_retries = *retry_counts.iter().min().unwrap();
    
    println!("Norm distribution:");
    println!("  Mean norm²: {:.2}", mean_norm);
    println!("  Std dev: {:.2}", std_dev);
    println!("  Max norm²: {}", norms.iter().max().unwrap());
    println!("  Min norm²: {}", norms.iter().min().unwrap());
    
    println!("\nRetry statistics:");
    println!("  Mean attempts: {:.2}", mean_retries);
    println!("  Max attempts: {}", max_retries);
    println!("  Min attempts: {}", min_retries);
    
    // Verify all norms are below the bound
    let bound = 34034726i64;
    for (i, &norm) in norms.iter().enumerate() {
        assert!(norm < bound, "Norm {} exceeds bound at sample {}", norm, i);
    }

    // The bound check above is ONE-SIDED and cannot fail for a too-narrow
    // sampler — signing and verification share it. #139 lived in exactly that
    // blind spot: signatures at 3.8% of the design width passed every check
    // here for as long as anyone cared to look.
    //
    // Assert the WIDTH, not just the ceiling: E||(s0,s1)||^2 = 2n*sigma^2.
    let design = 2.0 * (metamui_falcon512::constants::N as f64)
        * metamui_falcon512::constants::SIGMA
        * metamui_falcon512::constants::SIGMA;
    let ratio = mean_norm / design;
    let sigma_eff = (mean_norm / (2.0 * metamui_falcon512::constants::N as f64)).sqrt();
    println!("  Design 2n*sigma^2: {:.0}", design);
    println!("  Ratio to design:   {:.4}x", ratio);
    println!("  Effective sigma:   {:.2}", sigma_eff);

    // +/-5% over 1000 samples. The relative standard deviation of ||s||^2 on
    // 2n = 1024 degrees of freedom is sqrt(2/1024) ~ 4.4%, so the standard
    // error here is ~0.14% — this band is ~35 standard errors wide and will
    // not flake, while still catching a sampler off by more than a few percent.
    assert!(
        (0.95..=1.05).contains(&ratio),
        "Signature norm distribution is off-spec: mean {:.0} is {:.4}x the design \
         {:.0} (effective sigma {:.2} vs {}). Falcon's security argument requires \
         the emitted (s0,s1) to follow the specified discrete Gaussian; a \
         systematically narrow distribution leaks the basis across a transcript.",
        mean_norm, ratio, design, sigma_eff, metamui_falcon512::constants::SIGMA
    );

    // Restarts are governed by beta^2 = 1.21 * 2n*sigma^2, which sits 4.75
    // standard deviations out on a 1024-dof chi-square — so the rejection rate
    // is ~1e-6, not the 5-10% an earlier comment here guessed. Assert only that
    // it stays negligible; a *high* rate would mean the sampler is too wide.
    let rejection_rate = (mean_retries - 1.0) / mean_retries;
    println!("  Rejection rate: {:.4}%", rejection_rate * 100.0);
    assert!(
        (0.0..=0.05).contains(&rejection_rate),
        "Rejection rate {:.2}% is implausible for Falcon: beta is chosen so \
         restarts are ~1e-6. A high rate means signatures are landing near the \
         norm bound, i.e. the sampler is too wide.",
        rejection_rate * 100.0
    );
}

/// Test chi-square goodness of fit for Gaussian distribution
#[test]
fn test_gaussian_distribution_chi_square() {
    use metamui_falcon512::gaussian_calibrated::GaussianCalibrated;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    
    let mut rng = StdRng::seed_from_u64(789);
    let sigma = 165.7;
    let sampler = GaussianCalibrated::new(sigma);
    
    let num_samples = 10000;
    let num_bins: usize = 20;
    let max_value = (5.0 * sigma) as i32;
    let bin_width = (2 * max_value) / num_bins as i32;
    
    // Collect samples
    let mut samples = Vec::new();
    for _ in 0..num_samples {
        samples.push(sampler.sample(&mut rng));
    }
    
    // Create histogram
    let mut histogram = vec![0; num_bins];
    for &sample in &samples {
        if sample >= -max_value && sample < max_value {
            let bin = ((sample + max_value) / bin_width) as usize;
            if bin < num_bins {
                histogram[bin] += 1;
            }
        }
    }
    
    // Compute expected frequencies (approximation)
    let mut expected = vec![0.0; num_bins];
    let total_expected = num_samples as f64;
    
    for i in 0..num_bins {
        let x_low = -max_value + (i as i32) * bin_width;
        let x_high = x_low + bin_width;
        
        // Approximate Gaussian probability for this bin
        let p_low = gaussian_cdf(x_low as f64, 0.0, sigma);
        let p_high = gaussian_cdf(x_high as f64, 0.0, sigma);
        expected[i] = (p_high - p_low) * total_expected;
    }
    
    // Compute chi-square statistic
    let mut chi_square = 0.0;
    for i in 0..num_bins {
        if expected[i] > 5.0 {  // Only use bins with sufficient expected count
            let observed = histogram[i] as f64;
            let diff = observed - expected[i];
            chi_square += diff * diff / expected[i];
        }
    }
    
    println!("Chi-square statistic: {:.2}", chi_square);
    
    // Critical value for 19 degrees of freedom at 0.05 significance
    let critical_value = 30.14;  // χ²(0.05, 19)
    
    // Note: This is a loose test, may occasionally fail due to randomness
    if chi_square > critical_value {
        println!("Warning: Chi-square test failed ({:.2} > {:.2})", chi_square, critical_value);
        println!("This may be due to random variation in sampling");
    }
}

/// Test deterministic mode produces identical signatures
#[test]
fn test_deterministic_mode_reproducibility() {
    use metamui_falcon512::deterministic_rng::DeterministicRng;
    
    let seed = b"deterministic test seed";
    let keypair_seed = b"keypair seed";
    
    // Generate keypair with deterministic RNG
    let mut keygen_rng = DeterministicRng::new(keypair_seed);
    let keypair = generate_keypair(&mut keygen_rng).expect("Key generation should succeed");
    
    let message = b"Test message for deterministic mode";
    
    // Sign twice with same seed
    let mut rng1 = DeterministicRng::new(seed);
    let mut rng2 = DeterministicRng::new(seed);
    
    let sig1 = sign(message, &keypair.private_key, &mut rng1)
        .expect("First signing should succeed");
    let sig2 = sign(message, &keypair.private_key, &mut rng2)
        .expect("Second signing should succeed");
    
    // In deterministic mode, signatures should be identical
    assert_eq!(sig1, sig2, "Deterministic signatures should be identical");
    
    // Both should verify
    assert!(verify(message, &sig1, &keypair.public_key).unwrap());
    assert!(verify(message, &sig2, &keypair.public_key).unwrap());
}

/// Test rejection sampling rate
#[test]
#[ignore]  // This test takes longer to run
fn test_rejection_sampling_rate() {
    let mut rng = StdRng::seed_from_u64(999);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    
    let num_trials = 10000;
    let message = b"Test message for rejection rate";
    
    let config = SigningConfig {
        mode: SigningMode::Custom,
        max_attempts: 256,
        seed_rotation: false,
        backoff_ms: 0,
        max_backoff_ms: 0,
        track_stats: true,
    };
    
    let mut total_attempts = 0;
    let mut successful_signs = 0;
    
    for _ in 0..num_trials {
        match sign_with_config(message, &keypair.private_key, &mut rng, &config) {
            Ok(result) => {
                total_attempts += result.stats.total_attempts;
                successful_signs += 1;
            }
            Err(_) => {
                // Count failures (should be rare)
                total_attempts += config.max_attempts;
            }
        }
    }
    
    let average_attempts = total_attempts as f64 / num_trials as f64;
    let success_rate = successful_signs as f64 / num_trials as f64;
    let rejection_rate = (average_attempts - 1.0) / average_attempts;
    
    println!("Rejection sampling statistics over {} trials:", num_trials);
    println!("  Average attempts per signature: {:.2}", average_attempts);
    println!("  Success rate: {:.4}", success_rate);
    println!("  Implied rejection rate: {:.2}%", rejection_rate * 100.0);
    
    // Verify expectations
    assert!(success_rate > 0.99, "Success rate too low: {}", success_rate);

    // This asserted `rejection_rate >= 0.03`, i.e. it demanded that at least 3%
    // of signing attempts be rejected. That is wrong for Falcon in both
    // directions. beta^2 = 1.21 * 2n*sigma^2 sits 4.75 standard deviations out
    // on a 1024-degree-of-freedom chi-square, so the restart probability is on
    // the order of 1e-6 by design — the parameters are chosen precisely so
    // restarts are negligible. A lower bound of 3% could only be satisfied by a
    // sampler emitting signatures too close to the norm bound.
    assert!(rejection_rate <= 0.05,
            "Rejection rate {:.4}% too high — Falcon's beta is chosen so restarts \
             are ~1e-6; a high rate means the sampler is running too wide",
            rejection_rate * 100.0);
}

// Helper functions

/// Compute `||(s0,s1)||^2` for a NIST-format Falcon-512 signature.
///
/// # This helper used to be a no-op, and that is why #139 shipped
///
/// It previously began:
///
/// ```text
/// let n = 512;
/// if signature.len() < n * 4 { return 0; }
/// ```
///
/// then read raw little-endian `i16` pairs straight out of the buffer. Real
/// signatures are Golomb-Rice compressed to ~650 bytes, which is less than
/// `512 * 4 = 2048`, so **every** call returned 0. `test_signature_norm_distribution`
/// duly asserted that 0 was below the norm bound, printed "Mean norm²: 0.00",
/// and passed — while the signer emitted signatures at 3.8% of the design
/// width for however long nobody looked.
///
/// A distribution test that cannot fail is worse than no test: it occupies the
/// slot where a real one would go. This now decodes properly and needs the
/// public key and message to reconstruct `s0`, which is why the signature is
/// no longer enough on its own.
fn compute_signature_norm(
    pk: &metamui_falcon512::PublicKey,
    message: &[u8],
    signature: &[u8],
) -> i64 {
    use metamui_falcon512::constants::{LOGN, N, Q};

    let (nonce, s1) = metamui_falcon512::nist_encoding::decode_signature(signature, LOGN)
        .expect("a signature this crate just produced must decode");
    assert_eq!(s1.len(), N, "decoded s1 must have N coefficients");

    // c = SHAKE-256(nonce || message); s0 = c - s1*h (mod q), center-reduced.
    let c = metamui_falcon512::nist_hash::hash_to_point_nist(&nonce, message);
    let s1h = metamui_falcon512::ntt_falcon::multiply_ntt(&s1, &pk.h.coeffs);

    let mut norm_sq = 0i64;
    for i in 0..N {
        let diff = (c[i] as i32 - s1h[i] as i32).rem_euclid(Q as i32);
        let s0 = if diff >= (Q as i32 + 1) / 2 {
            diff - Q as i32
        } else {
            diff
        };
        norm_sq += (s0 as i64) * (s0 as i64) + (s1[i] as i64) * (s1[i] as i64);
    }
    norm_sq
}

/// Approximate Gaussian CDF
fn gaussian_cdf(x: f64, mean: f64, sigma: f64) -> f64 {
    
    
    let z = (x - mean) / (sigma * (2.0_f64).sqrt());
    0.5 * (1.0 + erf(z))
}

/// Error function approximation
fn erf(x: f64) -> f64 {
    // Abramowitz and Stegun approximation
    let a1 =  0.254829592;
    let a2 = -0.284496736;
    let a3 =  1.421413741;
    let a4 = -1.453152027;
    let a5 =  1.061405429;
    let p  =  0.3275911;
    
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    
    let t = 1.0 / (1.0 + p * x);
    let t2 = t * t;
    let t3 = t2 * t;
    let t4 = t3 * t;
    let t5 = t4 * t;
    
    let y = 1.0 - (((((a5 * t5 + a4 * t4) + a3 * t3) + a2 * t2) + a1 * t) * (-x * x).exp());
    
    sign * y
}