/// Basic Ed25519 tests that work with our implementation
use metamui_ed25519::*;

#[test]
fn test_key_generation() {
    let seed = [0u8; 32];
    let keypair = keypair_from_seed(&seed).expect("Failed to generate keypair");
    
    assert_eq!(keypair.public.as_bytes().len(), 32);
    // Private key is 64 bytes but doesn't expose as_bytes() method
}

#[test]
fn test_sign_verify() {
    let seed = [1u8; 32];
    let keypair = keypair_from_seed(&seed).expect("Failed to generate keypair");
    let message = b"Hello, world!";
    
    let signature = keypair.sign(message).expect("Failed to sign");
    assert_eq!(signature.to_bytes().len(), 64);
    
    let is_valid = keypair.public.verify(&signature, message).expect("Failed to verify");
    assert!(is_valid);
    
    // Wrong message should fail
    let is_valid = keypair.public.verify(&signature, b"Wrong message").unwrap_or(false);
    assert!(!is_valid);
}

#[test]
fn test_deterministic_signatures() {
    let seed = [42u8; 32];
    let keypair = keypair_from_seed(&seed).expect("Failed to generate keypair");
    let message = b"Test message";
    
    let sig1 = keypair.sign(message).expect("Failed to sign");
    let sig2 = keypair.sign(message).expect("Failed to sign");
    
    assert_eq!(sig1.to_bytes(), sig2.to_bytes(), "Signatures should be deterministic");
}

#[test]
fn test_batch_verification() {
    let seeds = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let messages = vec![b"msg1", b"msg2", b"msg3"];
    
    let mut keypairs = Vec::new();
    let mut signatures = Vec::new();
    let mut public_keys = Vec::new();
    
    for (seed, msg) in seeds.iter().zip(messages.iter()) {
        let kp = keypair_from_seed(seed).unwrap();
        let sig = kp.sign(*msg).unwrap();
        
        signatures.push(sig.to_bytes());
        public_keys.push(kp.public.as_bytes().clone());
        keypairs.push(kp);
    }
    
    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_ref()).collect();
    let sig_refs: Vec<&[u8; 64]> = signatures.iter().collect();
    let pk_refs: Vec<&[u8; 32]> = public_keys.iter().collect();
    
    let results = BatchVerifier::verify_batch(&msg_refs, &sig_refs, &pk_refs);
    assert!(results.iter().all(|&r| r), "All signatures should verify in batch");
}

#[test]
fn test_invalid_signature_rejection() {
    let seed = [10u8; 32];
    let keypair = keypair_from_seed(&seed).expect("Failed to generate keypair");
    let message = b"Test";
    
    let signature = keypair.sign(message).expect("Failed to sign");
    let mut sig_bytes = signature.to_bytes();
    
    // Corrupt the signature
    sig_bytes[0] ^= 0x01;
    let bad_sig = Signature::from_bytes(sig_bytes);
    
    let is_valid = keypair.public.verify(&bad_sig, message).unwrap_or(false);
    assert!(!is_valid, "Corrupted signature should not verify");
}

#[test]
fn test_rfc8032_public_keys() {
    // Test that we derive the same public keys as RFC 8032
    let test_cases = vec![
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        ),
    ];
    
    for (seed_hex, expected_pk_hex) in test_cases {
        let seed = hex::decode(seed_hex).unwrap();
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(&seed);
        
        let keypair = keypair_from_seed(&seed_array).unwrap();
        let expected_pk = hex::decode(expected_pk_hex).unwrap();
        
        assert_eq!(
            keypair.public.as_bytes(),
            &expected_pk[..],
            "Public key mismatch for seed {}",
            seed_hex
        );
    }
}