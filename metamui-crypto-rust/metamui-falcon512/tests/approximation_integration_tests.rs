//! Phase 0 regression tests for Falcon-512 approximation helper surfaces.
//!
//! These exported equation-verification helpers previously treated
//! approximation/tolerance checks as meaningful success criteria. Until exact
//! verification exists, they must fail closed.

use metamui_falcon512::{generate_keypair, sign, verify};
use metamui_falcon512::equation_verification::{
    BatchVerifier, ToleranceConfig, verify_ntru_equation, verify_signature_equation,
};
use metamui_falcon512::nist_kat_framework::{KATGenerator, KATValidator};
use metamui_falcon512::Falcon512Error;
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn test_ntru_equation_verifier_fails_closed() {
    let mut rng = StdRng::seed_from_u64(42);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");

    let result = verify_ntru_equation(
        &keypair.private_key.f.coeffs,
        &keypair.private_key.g.coeffs,
        &keypair.private_key.big_f.coeffs,
        &keypair.private_key.big_g.coeffs,
        &ToleranceConfig::default(),
    );

    assert!(!result.valid);
    assert!(result.max_absolute_error.is_infinite());
    assert!(result.max_relative_error.is_infinite());
    assert_eq!(result.error_stats.coeffs_exceeding, metamui_falcon512::N);
}

#[test]
fn test_signature_equation_verifier_fails_closed() {
    let mut rng = StdRng::seed_from_u64(7);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    let message = b"equation helper fail-closed";
    let signature = sign(message, &keypair.private_key, &mut rng).expect("Signing should succeed");

    assert!(verify(message, &signature, &keypair.public_key).expect("Verification should succeed"));

    let s0 = vec![0i16; metamui_falcon512::N];
    let s1 = vec![0i16; metamui_falcon512::N];
    let c = vec![0i16; metamui_falcon512::N];
    let result = verify_signature_equation(&s0, &s1, &keypair.public_key.h.coeffs, &c, &ToleranceConfig::default());

    assert!(!result.valid);
    assert!(result.max_absolute_error.is_infinite());
    assert!(result.error_stats.mean_error.is_infinite());
}

#[test]
fn test_tolerance_profiles_do_not_reenable_equation_helpers() {
    let mut rng = StdRng::seed_from_u64(99);
    let keypair = generate_keypair(&mut rng).expect("Key generation should succeed");
    let configs = [
        ToleranceConfig::strict(),
        ToleranceConfig::production(),
        ToleranceConfig::default(),
        ToleranceConfig::relaxed(),
    ];

    for config in &configs {
        let result = verify_ntru_equation(
            &keypair.private_key.f.coeffs,
            &keypair.private_key.g.coeffs,
            &keypair.private_key.big_f.coeffs,
            &keypair.private_key.big_g.coeffs,
            config,
        );
        assert!(!result.valid);
    }
}

#[test]
fn test_batch_equation_verifier_fails_closed() {
    let mut verifier = BatchVerifier::new(ToleranceConfig::relaxed());
    let f = vec![1i16; metamui_falcon512::N];
    let g = vec![0i16; metamui_falcon512::N];
    let big_f = vec![0i16; metamui_falcon512::N];
    let big_g = vec![0i16; metamui_falcon512::N];

    verifier.add_ntru_verification(&f, &g, &big_f, &big_g);

    let summary = verifier.get_summary();
    assert_eq!(summary.total_verifications, 1);
    assert_eq!(summary.valid_verifications, 0);
    assert!(summary.overall_max_error.is_infinite());
    assert!(!verifier.is_valid());
}

#[test]
fn test_kat_framework_approximation_stays_fail_closed() {
    let seed = [0x42u8; 32];
    let generator = KATGenerator::new(seed, 5);
    let validator = KATValidator::new();

    assert!(matches!(generator.generate(), Err(Falcon512Error::NotImplemented)));
    assert!(matches!(validator.validate_all(&[]), Err(Falcon512Error::NotImplemented)));
}
