//! Integration tests for ML-KEM

#[cfg(test)]
mod tests {
    #[cfg(feature = "mlkem768")]
    use metamui_mlkem::mlkem768::{
        generate_keypair, encapsulate, decapsulate, generate_keypair_from_seed,
    };
    use rand_core::OsRng;

    #[test]
    #[cfg(feature = "mlkem768")]
    fn test_mlkem768_full_cycle() {
        let mut rng = OsRng;

        // Generate keypair
        let keypair = generate_keypair(&mut rng)
            .expect("Failed to generate keypair");

        // Encapsulate
        let (ct, ss1) = encapsulate(&keypair.public_key, &mut rng)
            .expect("Failed to encapsulate");

        // Decapsulate
        let ss2 = decapsulate(&keypair.private_key, &ct)
            .expect("Failed to decapsulate");

        // Verify shared secrets match
        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "Shared secrets don't match!");
    }

    #[test]
    #[cfg(feature = "mlkem768")]
    fn test_mlkem768_wrong_ciphertext() {
        let mut rng = OsRng;

        // Generate two keypairs
        let kp1 = generate_keypair(&mut rng)
            .expect("Failed to generate keypair 1");
        let kp2 = generate_keypair(&mut rng)
            .expect("Failed to generate keypair 2");

        // Encapsulate with pk2
        let (ct, ss1) = encapsulate(&kp2.public_key, &mut rng)
            .expect("Failed to encapsulate");

        // Decapsulate with sk1 (wrong key)
        let ss2 = decapsulate(&kp1.private_key, &ct)
            .expect("Failed to decapsulate");

        // Shared secrets should NOT match
        assert_ne!(ss1.as_bytes(), ss2.as_bytes(), "Shared secrets shouldn't match with wrong key!");
    }

    #[test]
    #[cfg(feature = "mlkem768")]
    fn test_mlkem768_deterministic() {
        // Use deterministic seed
        let seed = [42u8; 32];

        let kp1 = generate_keypair_from_seed(&seed)
            .expect("Failed to generate keypair 1");
        let kp2 = generate_keypair_from_seed(&seed)
            .expect("Failed to generate keypair 2");

        // Keys should be identical
        assert_eq!(kp1.public_key.as_bytes(), kp2.public_key.as_bytes(), "Public keys don't match!");
        assert_eq!(kp1.private_key.as_bytes(), kp2.private_key.as_bytes(), "Private keys don't match!");
    }
}
