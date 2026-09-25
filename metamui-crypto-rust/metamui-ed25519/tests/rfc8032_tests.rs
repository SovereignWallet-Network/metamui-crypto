/// Tests using RFC 8032 test vectors
use metamui_ed25519::*;
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
struct TestCase {
    tc_id: u32,
    description: String,
    private_key: String,
    public_key: String,
    message: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct VectorFile {
    test_vectors: Vec<TestCase>,
}

/// 3-axis RFC 8032 conformance gate over the official §7.1 vectors:
///   (A) public key derived from the 32-byte seed == vector public_key;
///   (B) sign(seed, message) == vector signature BYTE-EXACTLY (Ed25519
///       signing is deterministic, RFC 8032 §5.1.6: nonce = SHA-512(prefix
///       || message), so the produced signature must reproduce the vector
///       exactly — a strictly stronger check than sign/verify round-trip);
///   (C) verify(public_key, message, signature) accepts.
/// Plus negatives (tampered message / signature / public key are rejected)
/// and a determinism check (signing twice yields identical bytes).
///
/// Ground truth: test-vectors/ed25519/rfc8032-vectors.json. This test must
/// FAIL (panic) — never silently skip — if that file is missing.
#[test]
fn test_rfc8032_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/ed25519/rfc8032-vectors.json"
    );
    // Fail-closed: a missing/unreadable vector file is a hard error.
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("RFC 8032 vector file unavailable at {path}: {e}"));
    let file: VectorFile = serde_json::from_str(&contents)
        .unwrap_or_else(|e| panic!("RFC 8032 vector file unparseable: {e}"));
    assert!(
        !file.test_vectors.is_empty(),
        "RFC 8032 vector file contains no vectors"
    );
    println!("Testing {} RFC 8032 vectors", file.test_vectors.len());

    for tv in &file.test_vectors {
        println!("Testing tc_id={}: {}", tv.tc_id, tv.description);

        let mut seed = [0u8; 32];
        let seed_bytes = hex::decode(&tv.private_key)
            .unwrap_or_else(|e| panic!("tc_id={}: private_key hex error: {e}", tv.tc_id));
        seed.copy_from_slice(&seed_bytes[..32]);

        let expected_public_key = hex::decode(&tv.public_key)
            .unwrap_or_else(|e| panic!("tc_id={}: public_key hex error: {e}", tv.tc_id));
        let message = hex::decode(&tv.message)
            .unwrap_or_else(|e| panic!("tc_id={}: message hex error: {e}", tv.tc_id));
        let expected_signature = hex::decode(&tv.signature)
            .unwrap_or_else(|e| panic!("tc_id={}: signature hex error: {e}", tv.tc_id));

        // Generate keypair from seed.
        let keypair = keypair_from_seed(&seed).expect("Failed to generate keypair");

        // (A) Public key derivation.
        assert_eq!(
            keypair.public.as_bytes(),
            &expected_public_key[..],
            "Public key mismatch for tc_id={}",
            tv.tc_id
        );

        // Sign message.
        let signature = keypair.sign(&message).expect("Failed to sign");

        // (B) Byte-exact signature (determinism vs. the published vector).
        assert_eq!(
            signature.to_bytes(),
            expected_signature.as_slice(),
            "Signature mismatch (not byte-exact) for tc_id={}",
            tv.tc_id
        );

        // (C) Verification accepts the genuine signature — both the default
        // and the strict RFC 8032 path. (The WASM wrapper verifies via the
        // strict path, so it must accept every genuine vector signature; the
        // R-point of e.g. TEST 2 carries a set x-sign bit, which strict
        // verification must not mistake for a non-canonical encoding.)
        let valid = keypair.public.verify(&signature, &message).unwrap_or(false);
        assert!(valid, "Signature verification failed for tc_id={}", tv.tc_id);
        let valid_strict = keypair.public.verify_strict(&signature, &message).unwrap_or(false);
        assert!(valid_strict, "Strict signature verification failed for tc_id={}", tv.tc_id);

        // Determinism: signing the same message again is byte-identical.
        let signature2 = keypair.sign(&message).expect("Failed to re-sign");
        assert_eq!(
            signature.to_bytes(),
            signature2.to_bytes(),
            "Non-deterministic signing for tc_id={}",
            tv.tc_id
        );

        // Negative: tampered message must be rejected.
        let mut bad_msg = message.clone();
        bad_msg.push(0x00); // append a byte (also covers the empty-message case)
        assert!(
            !keypair.public.verify(&signature, &bad_msg).unwrap_or(false),
            "Tampered message wrongly accepted for tc_id={}",
            tv.tc_id
        );

        // Negative: tampered signature must be rejected.
        let mut bad_sig_bytes = signature.to_bytes();
        bad_sig_bytes[0] ^= 0x01; // flip a bit in R
        let bad_sig = Signature::from_bytes(bad_sig_bytes);
        assert!(
            !keypair.public.verify(&bad_sig, &message).unwrap_or(false),
            "Tampered signature wrongly accepted for tc_id={}",
            tv.tc_id
        );

        // Negative: tampered public key must reject the genuine signature.
        let mut bad_pk_bytes = keypair.public.to_bytes();
        bad_pk_bytes[0] ^= 0x01;
        let bad_pk = PublicKey::from_bytes(&bad_pk_bytes).expect("pk from bytes");
        assert!(
            !bad_pk.verify(&signature, &message).unwrap_or(false),
            "Tampered public key wrongly accepted signature for tc_id={}",
            tv.tc_id
        );
    }
    println!("RFC 8032: all {} vectors passed (3-axis + negatives + determinism)", file.test_vectors.len());
}
