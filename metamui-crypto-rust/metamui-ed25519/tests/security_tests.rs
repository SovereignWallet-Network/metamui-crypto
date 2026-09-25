#[cfg(test)]
mod security_tests {
    use metamui_ed25519::*;

    #[test]
    fn test_zeroization_on_drop() {
        // Test that PrivateKey zeroizes on drop
        let seed = [42u8; 32];
        
        {
            let _keypair = keypair_from_seed(&seed).unwrap();
            // private key will be zeroized when it goes out of scope
        } // Drop called here, memory should be cleared
        
        // Note: We can't directly test memory clearing in safe Rust,
        // but the Zeroize trait guarantees it happens
    }

    #[test]
    fn test_constant_time_verification() {
        // Test constant-time verification
        let seed = [1u8; 32];
        let keypair = keypair_from_seed(&seed).unwrap();
        let message = b"constant time test";
        
        let signature = keypair.sign(message).unwrap();
        
        // Both valid and invalid verifications should take constant time
        assert!(keypair.public.verify(&signature, message).unwrap());
        assert!(!keypair.public.verify(&signature, b"wrong message").unwrap());
    }

    #[test]
    fn test_signature_malleability_protection() {
        // Test that non-canonical signatures are rejected
        let seed = [0x42u8; 32];
        let keypair = keypair_from_seed(&seed).unwrap();
        let message = b"malleability test";
        
        let signature = keypair.sign(message).unwrap();
        
        // Try to create a non-canonical signature
        // Should reject signatures where s >= L
        let mut modified_sig = signature.to_bytes();
        
        // Set the s component to be >= L (last 32 bytes)
        // L = 2^252 + 27742317777372353535851937790883648493
        // Setting all high bits would make s >= L
        for i in 32..64 {
            modified_sig[i] = 0xFF;
        }
        
        let modified = Signature::from_bytes(modified_sig);
        
        // This should fail verification
        let result = keypair.public.verify(&modified, message);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_small_order_keys_not_screened() {
        // MetaMUI policy (2026-09-24): RFC 8032 as written. RFC 8032 does
        // not screen small-order public keys, and verification uses the
        // cofactored equation [8][S]B = [8]R + [8][k]A. With A of order
        // dividing 8, R = the all-zero encoding (y = 0, a point of order 4)
        // and S = 0, every term is killed by [8], so the signature VERIFIES
        // for any message. This test used to assert rejection (a small-order
        // screen the policy removed). Cf. test-vectors/ed25519/
        // ed25519-policy-vectors.json tcIds 23-30.
        let small_order_points = vec![
            // Identity point (order 1)
            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            // Point of order 2
            [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
            // Point of order 4
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            // The other point of order 4 (sign bit set, x != 0)
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80],
            // Point of order 8 (canonical encoding)
            [0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
             0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
             0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
             0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a],
        ];

        let message = b"test";
        let dummy_sig = Signature::from_bytes([0u8; 64]);

        for point_bytes in small_order_points {
            let pk = PublicKey::from_bytes(&point_bytes).unwrap();
            assert!(
                pk.verify(&dummy_sig, message).unwrap(),
                "small-order key {:02x?} must verify (cofactored, no small-order screen)",
                point_bytes
            );
            assert!(pk.verify_strict(&dummy_sig, message).unwrap());
        }

        // The same key's non-canonical encodings are still refused: the
        // identity with the sign bit set (x = 0, §5.1.3 step 4) and with
        // y = p + 1 (y >= p, §5.1.3 step 1).
        let mut identity_sign_bit = [0u8; 32];
        identity_sign_bit[0] = 0x01;
        identity_sign_bit[31] = 0x80;
        let mut identity_y_p_plus_1 = [0xffu8; 32];
        identity_y_p_plus_1[0] = 0xee;
        identity_y_p_plus_1[31] = 0x7f;
        for bad in [identity_sign_bit, identity_y_p_plus_1] {
            let pk = PublicKey::from_bytes(&bad).unwrap();
            assert!(
                !pk.verify(&dummy_sig, message).unwrap_or(false),
                "non-canonical encoding {:02x?} must be refused",
                bad
            );
        }
    }

    #[test]
    fn test_deterministic_signatures() {
        // RFC 8032 requires deterministic signatures
        let seed = [0x55u8; 32];
        let keypair = keypair_from_seed(&seed).unwrap();
        let message = b"deterministic test";
        
        // Sign the same message multiple times
        let mut signatures = Vec::new();
        for _ in 0..10 {
            signatures.push(keypair.sign(message).unwrap());
        }
        
        // All signatures must be identical
        for sig in &signatures[1..] {
            assert_eq!(sig.to_bytes(), signatures[0].to_bytes());
        }
        
        // Different message must produce different signature
        let sig2 = keypair.sign(b"different").unwrap();
        assert_ne!(sig2.to_bytes(), signatures[0].to_bytes());
    }

    #[test]
    fn test_key_validation() {
        // Test public key validation
        // Zero is actually a valid point on the curve
        assert!(PublicKey::from_bytes(&[0u8; 32]).is_ok());
        
        // Most 32-byte values should be valid public keys
        assert!(PublicKey::from_bytes(&[1u8; 32]).is_ok());
        
        // Test that signature size is enforced
        assert_eq!(SIGNATURE_SIZE, 64);
        assert_eq!(PUBLIC_KEY_SIZE, 32);
        assert_eq!(PRIVATE_KEY_SIZE, 64);
        assert_eq!(SEED_SIZE, 32);
    }

    #[test] 
    fn test_invalid_point_rejection() {
        // Test that invalid points are rejected
        let invalid_point = [0xffu8; 32]; // All bits set is not a valid point
        
        let pk_result = PublicKey::from_bytes(&invalid_point);
        // This specific value may or may not be rejected depending on implementation
        // But if accepted, it should at least fail verification
        if let Ok(pk) = pk_result {
            let dummy_sig = Signature::from_bytes([0u8; 64]);
            let result = pk.verify(&dummy_sig, b"test");
            assert!(!result.unwrap_or(false));
        }
    }

    #[test]
    fn test_signature_size_enforcement() {
        // Test that signatures must be exactly 64 bytes
        let seed = [1u8; 32];
        let keypair = keypair_from_seed(&seed).unwrap();
        
        // Valid signature
        let sig = keypair.sign(b"test").unwrap();
        assert_eq!(sig.to_bytes().len(), 64);
        
        // Signature bytes should be accepted
        let sig_bytes = sig.to_bytes();
        let sig2 = Signature::from_bytes(sig_bytes);
        assert_eq!(sig2.to_bytes(), sig_bytes);
    }
}