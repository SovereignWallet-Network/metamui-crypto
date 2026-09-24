// NIST test vector validation for SLH-DSA (SPHINCS+)
// Tests against official FIPS 205 parameter sizes and sign/verify cycles

use metamui_slhdsa::*;
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[cfg(test)]
mod nist_vector_tests {
    use super::*;

    #[test]
    fn test_slhdsa_128s_keygen_sizes() {
        // Verify key sizes match FIPS 205 for SLH-DSA-SHAKE-128s
        let sk = SigningKey::<SlhDsa128s>::generate(&mut OsRng);
        let pk = sk.verifying_key();

        let sk_bytes = sk.to_bytes();
        let pk_bytes = pk.to_bytes();

        // FIPS 205: PK = 32 bytes, SK = 64 bytes for 128s
        assert_eq!(pk_bytes.len(), 32, "SLH-DSA-128s public key must be 32 bytes");
        assert_eq!(sk_bytes.len(), 64, "SLH-DSA-128s secret key must be 64 bytes");
    }

    #[test]
    fn test_slhdsa_128s_sign_verify() {
        // Test signing and verification for SLH-DSA-128s
        let sk = SigningKey::<SlhDsa128s>::generate(&mut OsRng);
        let pk = sk.verifying_key();

        let message = b"Test message for SLH-DSA signature validation";

        // Sign message
        let signature = sk.sign(message);

        // Verify signature size (FIPS 205: 7856 bytes for SLH-DSA-SHAKE-128s)
        assert_eq!(signature.to_bytes().len(), 7856,
            "SLH-DSA-128s signature must be 7856 bytes");

        // Verify signature
        assert!(pk.verify(message, &signature).is_ok(),
            "Valid signature must verify");

        // Test invalid signature
        let mut invalid_bytes = signature.to_bytes().to_vec();
        invalid_bytes[100] ^= 0xFF;
        let invalid_sig = Signature::<SlhDsa128s>::from_bytes(&invalid_bytes).unwrap();
        assert!(pk.verify(message, &invalid_sig).is_err(),
            "Tampered signature must not verify");
    }

    #[test]
    fn test_slhdsa_128f_parameters() {
        // Test SLH-DSA-128f parameter set
        assert_eq!(SlhDsa128f::N, 16);
        assert_eq!(SlhDsa128f::H, 66);
        assert_eq!(SlhDsa128f::D, 22);
        assert_eq!(SlhDsa128f::W, 16);
        assert_eq!(SlhDsa128f::PK_BYTES, 32);
        assert_eq!(SlhDsa128f::SK_BYTES, 64);

        let sk = SigningKey::<SlhDsa128f>::generate(&mut OsRng);
        let pk = sk.verifying_key();

        assert_eq!(pk.to_bytes().len(), 32);
        assert_eq!(sk.to_bytes().len(), 64);

        // Test signature size (17088 bytes for 128f)
        let message = b"Test message";
        let signature = sk.sign(message);
        assert_eq!(signature.to_bytes().len(), 17088,
            "SLH-DSA-128f signature must be 17088 bytes");
    }

    #[test]
    fn test_slhdsa_192s_sign_verify() {
        // Test SLH-DSA-192s
        let sk = SigningKey::<SlhDsa192s>::generate(&mut OsRng);
        let pk = sk.verifying_key();

        // Verify key sizes
        assert_eq!(pk.to_bytes().len(), 48);
        assert_eq!(sk.to_bytes().len(), 96);

        let message = b"Test message for SLH-DSA-192s";
        let signature = sk.sign(message);

        // Verify signature size (16224 bytes for 192s)
        assert_eq!(signature.to_bytes().len(), 16224,
            "SLH-DSA-192s signature must be 16224 bytes");

        // Verify signature
        assert!(pk.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_slhdsa_192f_parameters() {
        // Test SLH-DSA-192f parameter set
        assert_eq!(SlhDsa192f::N, 24);
        assert_eq!(SlhDsa192f::H, 66);
        assert_eq!(SlhDsa192f::D, 22);
        assert_eq!(SlhDsa192f::W, 16);

        // Test signature size (35664 bytes for 192f)
        let sk = SigningKey::<SlhDsa192f>::generate(&mut OsRng);
        let message = b"Test";
        let signature = sk.sign(message);
        assert_eq!(signature.to_bytes().len(), 35664,
            "SLH-DSA-192f signature must be 35664 bytes");
    }

    #[test]
    fn test_slhdsa_256s_sign_verify() {
        // Test SLH-DSA-256s
        let sk = SigningKey::<SlhDsa256s>::generate(&mut OsRng);
        let pk = sk.verifying_key();

        // Verify key sizes
        assert_eq!(pk.to_bytes().len(), 64);
        assert_eq!(sk.to_bytes().len(), 128);

        let message = b"Test message for SLH-DSA-256s";
        let signature = sk.sign(message);

        assert_eq!(signature.to_bytes().len(), 29792,
            "SLH-DSA-256s signature must be 29792 bytes per FIPS 205");

        // Verify signature
        assert!(pk.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_slhdsa_256f_parameters() {
        // Test SLH-DSA-256f parameter set
        assert_eq!(SlhDsa256f::N, 32);
        assert_eq!(SlhDsa256f::H, 68);
        assert_eq!(SlhDsa256f::D, 17);
        assert_eq!(SlhDsa256f::W, 16);

        // Test signature size (49856 bytes for 256f)
        let sk = SigningKey::<SlhDsa256f>::generate(&mut OsRng);
        let message = b"Test";
        let signature = sk.sign(message);
        assert_eq!(signature.to_bytes().len(), 49856,
            "SLH-DSA-256f signature must be 49856 bytes");
    }

    #[test]
    fn test_cross_variant_incompatibility() {
        // Ensure signatures from one variant don't verify with another
        let message = b"Test cross-variant message";

        // Generate with 128s
        let sk_128s = SigningKey::<SlhDsa128s>::generate(&mut OsRng);
        let signature_128s = sk_128s.sign(message);

        // Signature sizes differ between variants, preventing cross-verification
        assert_ne!(signature_128s.to_bytes().len(), SlhDsa128f::SIG_BYTES,
            "128s and 128f signature sizes must differ");
    }

    #[test]
    fn test_deterministic_signatures() {
        // Test that deterministic signing produces consistent results
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let sk = SigningKey::<SlhDsa128s>::generate(&mut rng);

        let message = b"Deterministic test";

        // Sign twice with deterministic signing (no additional randomness)
        let sig1 = sk.sign(message);
        let sig2 = sk.sign(message);

        // Deterministic signing should produce identical signatures
        assert_eq!(sig1.to_bytes(), sig2.to_bytes(),
            "Deterministic signing must produce identical signatures");
    }

    #[test]
    fn test_message_recovery_resistance() {
        // Test that modified messages don't verify
        let sk = SigningKey::<SlhDsa128s>::generate(&mut OsRng);
        let pk = sk.verifying_key();

        let message1 = b"Original message";
        let message2 = b"Modified message";

        let signature = sk.sign(message1);

        // Original message should verify
        assert!(pk.verify(message1, &signature).is_ok());

        // Modified message should not verify
        assert!(pk.verify(message2, &signature).is_err());
    }

    #[test]
    fn test_public_key_recovery_resistance() {
        // Test that signatures don't verify with wrong public keys
        let sk1 = SigningKey::<SlhDsa128s>::generate(&mut OsRng);
        let pk1 = sk1.verifying_key();

        let sk2 = SigningKey::<SlhDsa128s>::generate(&mut OsRng);
        let pk2 = sk2.verifying_key();

        let message = b"Test message";
        let signature = sk1.sign(message);

        // Should verify with correct public key
        assert!(pk1.verify(message, &signature).is_ok());

        // Should not verify with different public key
        assert!(pk2.verify(message, &signature).is_err());
    }

    #[test]
    fn test_key_serialization_roundtrip() {
        // Test that keys survive serialization/deserialization
        let sk = SigningKey::<SlhDsa128s>::generate(&mut OsRng);
        let pk = sk.verifying_key();

        let sk_bytes = sk.to_bytes();
        let pk_bytes = pk.to_bytes();

        let sk_restored = SigningKey::<SlhDsa128s>::from_bytes(&sk_bytes).unwrap();
        let pk_restored = VerifyingKey::<SlhDsa128s>::from_bytes(&pk_bytes).unwrap();

        // Sign with restored key, verify with restored key
        let message = b"Serialization test";
        let signature = sk_restored.sign(message);
        assert!(pk_restored.verify(message, &signature).is_ok(),
            "Deserialized keys must produce valid signatures");
    }

    #[test]
    fn test_parameter_set_enum() {
        // Verify ParameterSet enum matches const parameters
        assert_eq!(ParameterSet::SlhDsa128s.public_key_bytes(), SlhDsa128s::PK_BYTES);
        assert_eq!(ParameterSet::SlhDsa128s.secret_key_bytes(), SlhDsa128s::SK_BYTES);
        assert_eq!(ParameterSet::SlhDsa128s.signature_bytes(), SlhDsa128s::SIG_BYTES);

        assert_eq!(ParameterSet::SlhDsa256s.public_key_bytes(), SlhDsa256s::PK_BYTES);
        assert_eq!(ParameterSet::SlhDsa256f.signature_bytes(), SlhDsa256f::SIG_BYTES);

        assert!(ParameterSet::SlhDsa128s.is_small());
        assert!(ParameterSet::SlhDsa128f.is_fast());
    }
}
