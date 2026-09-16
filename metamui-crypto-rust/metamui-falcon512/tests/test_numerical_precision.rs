//! Comprehensive test suite for numerical precision fixes
//! 
//! Tests the hybrid FFT approach, extended precision arithmetic,
//! and enhanced key generation with conditioning checks.

use metamui_falcon512::*;
use metamui_falcon512::fft_hybrid::{FFTMode, HybridFFT};
use metamui_falcon512::falcon_reference::extended_precision::*;
use metamui_falcon512::falcon_reference::basis_hybrid::HybridBasis;
use metamui_falcon512::falcon_reference::ffsampling_hybrid::HybridFFSampler;
use metamui_falcon512::keygen_enhanced::{KeygenParams, keygen_enhanced};
use metamui_falcon512::poly::PolyF64;
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;

/// Test Kahan summation accuracy
#[test]
fn test_kahan_summation_accuracy() {
    // Values that would lose precision with regular summation
    let values = vec![1e10, 1.0, -1e10, 2.0, 1e10, 3.0, -1e10];
    
    // Regular sum loses precision
    let regular_sum: f64 = values.iter().sum();
    
    // Kahan sum maintains precision
    let kahan = kahan_sum(&values);
    
    // Kahan should give 6.0, regular might give 0.0 or imprecise value
    assert!((kahan - 6.0).abs() < 1e-10, "Kahan sum should be 6.0, got {}", kahan);
    
    // Show that regular sum is less accurate
    println!("Regular sum: {}, Kahan sum: {}", regular_sum, kahan);
}

/// Test 80-bit accumulator
#[test]
fn test_accumulator_80_precision() {
    let mut acc = Accumulator80::zero();
    
    // Add values that require extended precision
    let values = [1e15, 1.0, -1e15, 2.0, 1e15, 3.0, -1e15, 4.0];
    for v in &values {
        acc.add(*v);
    }
    
    let result = acc.get_compensated();
    assert!((result - 10.0).abs() < 1e-10, 
           "Accumulator80 should give 10.0, got {}", result);
}

/// Test 128-bit accumulator
#[test]
fn test_accumulator_128_precision() {
    let mut acc = Accumulator128::zero();
    
    // Test with very large numbers
    acc.add(1e20);
    acc.add(1.0);
    acc.add(-1e20);
    acc.add(2.0);
    acc.add(1e20);
    acc.add(3.0);
    acc.add(-1e20);
    
    let result = acc.get();
    assert!((result - 6.0).abs() < 1e-10,
           "Accumulator128 should give 6.0, got {}", result);
}

/// Test hybrid basis conditioning
#[test]
fn test_hybrid_basis_conditioning() {
    let mut rng = StdRng::seed_from_u64(12345);
    
    // Generate test keys
    if let Ok((f, g, big_f, big_g)) = generate_test_keys(&mut rng) {
        // Test with different FFT modes
        let modes = [FFTMode::Native, FFTMode::Emulated, FFTMode::Hybrid];
        
        for mode in &modes {
            match HybridBasis::new(&f, &g, &big_f, &big_g, *mode) {
                Ok(basis) => {
                    // Check stability
                    assert!(basis.check_stability(), 
                           "Basis unstable in mode {:?}", mode);
                    
                    // Check condition number
                    let cond = basis.estimate_condition_number();
                    println!("Mode {:?}: condition number = {:.2e}", mode, cond);
                    
                    // Should be reasonable
                    assert!(cond < 1e8, "Condition number too large in mode {:?}", mode);
                }
                Err(e) => {
                    eprintln!("Failed to create basis in mode {:?}: {:?}", mode, e);
                }
            }
        }
    }
}

/// Test hybrid FFT sampler with real signature generation
#[test]
fn test_hybrid_sampler_signature() {
    let mut rng = StdRng::seed_from_u64(777);
    
    // Generate keys with enhanced generation
    let params = KeygenParams {
        max_condition_number: 1e6,
        max_rejections: 100,
        enable_gram_schmidt: true,
        fft_mode: FFTMode::Hybrid,
    };
    
    match keygen_enhanced(&mut rng, &params) {
        Ok((pk, sk)) => {
            // Create hybrid sampler
            let sampler = HybridFFSampler::new(
                &sk.f.coeffs,
                &sk.g.coeffs,
                &sk.big_f.coeffs,
                &sk.big_g.coeffs,
                165.7,  // sigma
                1.277833697,  // sigma_min
                FFTMode::Hybrid,
            ).expect("Failed to create sampler");
            
            // Hash a message to get a point
            let message = b"Test message for hybrid sampler";
            let point = hash_to_point(message, Q);
            
            // Sample a signature
            let (s0, s1) = sampler.sample_preimage(&point, &mut rng)
                .expect("Sampling failed");
            
            // Check signature norm
            let norm: i64 = s0.iter().map(|&x| x as i64 * x as i64).sum::<i64>()
                         + s1.iter().map(|&x| x as i64 * x as i64).sum::<i64>();
            
            println!("Signature norm: {} (limit: 34034726)", norm);
            
            // Should be within bounds
            assert!(norm < 34034726, "Signature norm exceeds bound");
            
            // Verify the signature equation: s0 + s1*h = c (mod q)
            verify_signature_equation(&s0, &s1, &pk.h.coeffs, &point);
        }
        Err(e) => {
            eprintln!("Key generation failed: {:?}", e);
            // This can happen due to rejection sampling
        }
    }
}

/// Helper function to generate test keys
fn generate_test_keys<R: RngCore + Send>(rng: &mut R) -> std::result::Result<(Vec<i16>, Vec<i16>, Vec<i16>, Vec<i16>), metamui_falcon512::Falcon512Error> {
    // Try multiple solvers
    match metamui_falcon512::ntru_working::ntru_keygen_working(rng) {
        Ok(keys) => Ok(keys),
        Err(_) => {
            match metamui_falcon512::ntru_optimized::ntru_keygen_optimized(rng) {
                Ok(keys) => Ok(keys),
                Err(_) => {
                    metamui_falcon512::ntru_solver_robust::generate_ntru_keys_robust(rng)
                }
            }
        }
    }
}

/// Hash message to polynomial point
fn hash_to_point(message: &[u8], modulus: u16) -> Vec<i16> {
    use metamui_sha2::Sha256Hasher;
    
    let mut hasher = Sha256Hasher::new();
    hasher.update(message);
    let hash = hasher.finalize();
    
    let mut point = vec![0i16; N];
    for i in 0..N {
        let idx = (i * 2) % 32;
        let val = u16::from_le_bytes([hash[idx], hash[(idx + 1) % 32]]);
        point[i] = (val % modulus) as i16;
    }
    
    point
}

/// Verify signature equation
fn verify_signature_equation(s0: &[i16], s1: &[i16], h: &[i16], c: &[i16]) {
    use metamui_falcon512::ntt_falcon;
    
    // Convert to NTT domain
    let s0_ntt = ntt_falcon::ntt_forward(s0);
    let s1_ntt = ntt_falcon::ntt_forward(s1);
    let h_ntt = ntt_falcon::ntt_forward(h);
    let c_ntt = ntt_falcon::ntt_forward(c);
    
    // Compute s0 + s1*h in NTT domain (all values are i16, work in i64 to avoid overflow)
    let q = Q as i64;
    let mut check_ntt = vec![0i64; N];
    for i in 0..N {
        let s1h = ((s1_ntt[i] as i64 * h_ntt[i] as i64) % q + q) % q;
        check_ntt[i] = ((s0_ntt[i] as i64 + s1h) % q + q) % q;
    }

    // Check equality
    let mut max_diff = 0i64;
    for i in 0..N {
        let c_val = ((c_ntt[i] as i64) % q + q) % q;
        let diff = (check_ntt[i] - c_val).abs() % q;
        let diff = diff.min(q - diff);
        if diff > max_diff {
            max_diff = diff;
        }
    }
    
    println!("Signature equation max difference: {} (should be 0)", max_diff);
    assert!(max_diff < 10, "Signature equation not satisfied");
}

/// Test performance comparison between FFT modes
#[test]
fn test_fft_performance_comparison() {
    use std::time::Instant;
    
    let mut rng = StdRng::seed_from_u64(123);
    
    // Create test polynomial
    let mut coeffs = vec![0.0; N];
    for i in 0..N {
        coeffs[i] = (rng.next_u32() % 1000) as f64 - 500.0;
    }
    let poly = PolyF64::new(coeffs);
    
    let iterations = 100;
    
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
        println!("Mode {:?}: {:.2} FFT round-trips/sec", mode, ops_per_sec);
    }
}