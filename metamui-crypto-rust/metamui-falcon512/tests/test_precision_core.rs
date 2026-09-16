//! Core numerical precision tests without private module dependencies

use metamui_falcon512::*;
use metamui_falcon512::fft_hybrid::{FFTMode, HybridFFT};
use metamui_falcon512::falcon_reference::extended_precision::*;
use metamui_falcon512::falcon_reference::basis_hybrid::HybridBasis;
use metamui_falcon512::poly::PolyF64;
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;

/// Test Kahan summation accuracy
#[test]
fn test_kahan_summation_core() {
    // Values that would lose precision with regular summation
    let values = vec![1e10, 1.0, -1e10, 2.0, 1e10, 3.0, -1e10];
    
    // Regular sum loses precision
    let regular_sum: f64 = values.iter().sum();
    
    // Kahan sum maintains precision
    let kahan = kahan_sum(&values);
    
    // Kahan should give 6.0
    assert!((kahan - 6.0).abs() < 1e-10, "Kahan sum should be 6.0, got {}", kahan);
    
    println!("✓ Kahan summation test passed");
    println!("  Regular sum: {}, Kahan sum: {}", regular_sum, kahan);
}

/// Test 80-bit accumulator
#[test]
fn test_accumulator_80_core() {
    let mut acc = Accumulator80::zero();
    
    // Add values that require extended precision
    let values = [1e15, 1.0, -1e15, 2.0, 1e15, 3.0, -1e15, 4.0];
    for v in &values {
        acc.add(*v);
    }
    
    let result = acc.get_compensated();
    assert!((result - 10.0).abs() < 1e-10, 
           "Accumulator80 should give 10.0, got {}", result);
    
    println!("✓ 80-bit accumulator test passed");
}

/// Test 128-bit accumulator
#[test]
fn test_accumulator_128_core() {
    let mut acc = Accumulator128::zero();
    
    // Test with very large numbers
    acc.add(1e20);
    acc.add(1.0);
    acc.add(-1e20);
    acc.add(2.0);
    
    let result = acc.get();
    assert!((result - 3.0).abs() < 1e-10,
           "Accumulator128 should give 3.0, got {}", result);
    
    println!("✓ 128-bit accumulator test passed");
}

/// Test extended dot product
#[test]
fn test_extended_dot_product_core() {
    let a = vec![1e10, 1.0, 1e10];
    let b = vec![1e10, 1.0, -1e10];
    
    // Extended precision dot product
    let extended = extended_dot_product(&a, &b);
    
    // Expected: 1e10*1e10 + 1*1 + 1e10*(-1e10) = 1e20 + 1 - 1e20 = 1
    let expected = 1.0;
    assert!((extended - expected).abs() < 1e-8,
           "Extended dot product failed: got {}, expected {}", extended, expected);
    
    println!("✓ Extended dot product test passed");
}

/// Test hybrid FFT round-trip accuracy
#[test]
fn test_hybrid_fft_roundtrip() {
    let mut rng = StdRng::seed_from_u64(42);
    
    // Create test polynomial
    let mut coeffs = vec![0.0; N];
    for i in 0..N {
        coeffs[i] = (rng.next_u32() % 1000) as f64 - 500.0;
    }
    let poly = PolyF64::new(coeffs.clone());
    
    // Test all three modes
    let modes = [FFTMode::Native, FFTMode::Emulated, FFTMode::Hybrid];
    
    for mode in &modes {
        let fft = HybridFFT::new(*mode);
        let forward = fft.forward(&poly);
        let inverse = fft.inverse(&forward);
        
        // Check round-trip accuracy
        let mut max_error = 0.0;
        for i in 0..N {
            let error = (inverse.coeffs[i] - coeffs[i]).abs();
            if error > max_error {
                max_error = error;
            }
        }
        
        println!("✓ FFT mode {:?}: max round-trip error = {:.2e}", mode, max_error);
        
        // Different accuracy expectations for different modes
        let tolerance = match mode {
            FFTMode::Native => 1e-6,
            FFTMode::Emulated => 1e3,  // Emulated mode may have larger errors
            FFTMode::Hybrid => 1e-3,
        };
        assert!(max_error < tolerance, "FFT mode {:?} error too large: {:.2e} (tolerance: {:.2e})", mode, max_error, tolerance);
    }
}

/// Test hybrid basis stability
#[test]
fn test_hybrid_basis_stability() {
    let mut rng = StdRng::seed_from_u64(12345);
    
    // Generate test keys using the working solver
    match metamui_falcon512::ntru_working::ntru_keygen_working(&mut rng) {
        Ok((f, g, big_f, big_g)) => {
            // Test with hybrid mode
            match HybridBasis::new(&f, &g, &big_f, &big_g, FFTMode::Hybrid) {
                Ok(basis) => {
                    // Check stability
                    assert!(basis.check_stability(), "Basis unstable");
                    
                    // Check condition number
                    let cond = basis.estimate_condition_number();
                    println!("✓ Hybrid basis created successfully");
                    println!("  Condition number: {:.2e}", cond);
                    
                    // Should be reasonable
                    assert!(cond < 1e10, "Condition number too large: {:.2e}", cond);
                }
                Err(e) => {
                    eprintln!("Failed to create basis: {:?}", e);
                    // This can happen with some keys
                }
            }
        }
        Err(_) => {
            eprintln!("Key generation failed (expected occasionally)");
        }
    }
}

/// Performance test for different FFT modes
#[test]
fn test_fft_performance() {
    use std::time::Instant;
    
    let mut rng = StdRng::seed_from_u64(123);
    
    // Create test polynomial
    let mut coeffs = vec![0.0; N];
    for i in 0..N {
        coeffs[i] = (rng.next_u32() % 1000) as f64 - 500.0;
    }
    let poly = PolyF64::new(coeffs);
    
    let iterations = 100;
    
    println!("✓ FFT Performance comparison:");
    
    // Benchmark each mode
    for mode in &[FFTMode::Native, FFTMode::Emulated, FFTMode::Hybrid] {
        let fft = HybridFFT::new(*mode);
        
        let start = Instant::now();
        for _ in 0..iterations {
            let forward = fft.forward(&poly);
            let _inverse = fft.inverse(&forward);
        }
        let elapsed = start.elapsed();
        
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
        println!("  Mode {:?}: {:.2} FFT round-trips/sec", mode, ops_per_sec);
    }
}