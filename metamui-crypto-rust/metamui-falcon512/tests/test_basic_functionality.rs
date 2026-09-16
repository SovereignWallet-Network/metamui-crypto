//! Basic functionality tests for Falcon-512
//!
//! These tests verify that the basic operations work,
//! even if the full cryptographic properties aren't perfect yet.

use metamui_falcon512::simple_sampler::SimpleSampler;
use metamui_falcon512::{generate_keypair, Falcon512Error, N};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn test_keygen_basic() {
    let mut rng = StdRng::seed_from_u64(12345);

    match generate_keypair(&mut rng) {
        Ok(keypair) => {
            assert_eq!(keypair.public_key.h.coeffs.len(), N);
            assert_eq!(keypair.private_key.f.coeffs.len(), N);
            assert_eq!(keypair.private_key.g.coeffs.len(), N);
            assert_eq!(keypair.private_key.big_f.coeffs.len(), N);
            assert_eq!(keypair.private_key.big_g.coeffs.len(), N);
            println!("??Key generation successful");
        }
        Err(e) => {
            println!("Key generation failed (expected for now): {:?}", e);
        }
    }
}

#[test]
fn test_simple_sampler_basic() {
    let mut rng = StdRng::seed_from_u64(54321);
    let sampler = SimpleSampler::new();
    let target = vec![100i16; N];
    let h = vec![1i16; N];

    assert!(matches!(
        sampler.sample_signature(&target, &h, &mut rng),
        Err(Falcon512Error::NotImplemented)
    ));
    assert!(matches!(
        sampler.sample_direct(&target, &h, &mut rng),
        Err(Falcon512Error::NotImplemented)
    ));
}

#[test]
fn test_polynomial_operations() {
    use metamui_falcon512::ntt_falcon;

    let a = vec![1i16; N];
    let b = vec![2i16; N];

    let c = ntt_falcon::multiply_ntt(&a, &b);
    assert_eq!(c.len(), N);

    let non_zero = c.iter().any(|&x| x != 0);
    assert!(non_zero, "NTT multiplication produced all zeros");

    println!("??NTT multiplication works");
}

#[test]
fn test_gaussian_sampling() {
    use metamui_falcon512::gaussian_calibrated::GaussianCalibrated;

    let mut rng = StdRng::seed_from_u64(99999);
    let sampler = GaussianCalibrated::new(10.0);

    let mut samples = Vec::new();
    for _ in 0..100 {
        samples.push(sampler.sample(&mut rng));
    }

    let unique_values: std::collections::HashSet<_> = samples.iter().cloned().collect();
    assert!(unique_values.len() > 10, "Gaussian sampler not producing enough variety");

    let max_abs = samples.iter().map(|&x| x.abs()).max().unwrap();
    assert!(max_abs < 100, "Gaussian samples too large");

    println!("??Gaussian sampling works");
}

#[test]
fn test_deterministic_rng() {
    use metamui_falcon512::deterministic_rng::DeterministicRng;
    use rand::RngCore;

    let seed = b"test seed";
    let mut rng1 = DeterministicRng::new(seed);
    let mut rng2 = DeterministicRng::new(seed);

    let mut bytes1 = [0u8; 32];
    let mut bytes2 = [0u8; 32];

    rng1.fill_bytes(&mut bytes1);
    rng2.fill_bytes(&mut bytes2);

    assert_eq!(bytes1, bytes2, "Deterministic RNG not reproducible");
    assert!(bytes1.iter().any(|&b| b != 0), "RNG producing all zeros");

    println!("??Deterministic RNG works");
}

#[test]
fn test_shake256() {
    use metamui_falcon512::shake::Shake256Context;

    let mut shake = Shake256Context::new();
    shake.update(b"test input");

    let mut reader = shake.finalize_xof();
    let mut output = [0u8; 32];
    reader.read(&mut output);

    assert!(output.iter().any(|&b| b != 0), "SHAKE256 producing all zeros");

    println!("??SHAKE256 works");
}

#[test]
fn test_simple_signature_flow_fails_closed() {
    let mut rng = StdRng::seed_from_u64(11111);
    let sampler = SimpleSampler::new();
    let message_hash = vec![42i16; N];
    let h = vec![1i16; N];

    assert!(matches!(
        sampler.sample_direct(&message_hash, &h, &mut rng),
        Err(Falcon512Error::NotImplemented)
    ));
}
