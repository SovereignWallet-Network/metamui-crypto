//! Integration tests for AIM2 (AIMer v2.0) sign/verify cycle
//!
//! These tests verify the full signature lifecycle using Aim2er parameter sets
//! which use the AIM2 cipher (Mersenne S-boxes, KPQC winner January 2025).

use metamui_aimer::{Aimer, Aim2erI, Aim2erIII, Aim2erV};

// =============================================================================
// AIM2er-I (128-bit security, AIM2 cipher)
// =============================================================================

#[test]
fn test_aim2_sign_verify_roundtrip_l1() {
    let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().expect("keygen failed");
    let msg = b"AIM2 L1 roundtrip test";

    let sig = Aimer::<Aim2erI>::sign(msg, &sk).expect("signing failed");
    let result = Aimer::<Aim2erI>::verify(msg, &sig, &pk).expect("verify error");

    assert!(result, "Aim2erI signature failed verification");
}

#[test]
fn test_aim2_wrong_message_l1() {
    let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().expect("keygen failed");
    let msg = b"Original message";
    let sig = Aimer::<Aim2erI>::sign(msg, &sk).expect("signing failed");

    let wrong_msg = b"Tampered message";
    let result = Aimer::<Aim2erI>::verify(wrong_msg, &sig, &pk).expect("verify error");
    assert!(!result, "Aim2erI should reject wrong message");
}

#[test]
fn test_aim2_wrong_key_l1() {
    let (_pk1, sk1) = Aimer::<Aim2erI>::generate_keypair().expect("keygen failed");
    let (pk2, _sk2) = Aimer::<Aim2erI>::generate_keypair().expect("keygen failed");
    let msg = b"Test message";
    let sig = Aimer::<Aim2erI>::sign(msg, &sk1).expect("signing failed");

    let result = Aimer::<Aim2erI>::verify(msg, &sig, &pk2).expect("verify error");
    assert!(!result, "Aim2erI should reject wrong public key");
}

#[test]
fn test_aim2_randomized_signatures_l1() {
    let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().expect("keygen failed");
    let msg = b"Randomization test";

    let sig1 = Aimer::<Aim2erI>::sign(msg, &sk).expect("signing failed");
    let sig2 = Aimer::<Aim2erI>::sign(msg, &sk).expect("signing failed");

    assert_ne!(sig1.salt, sig2.salt, "randomized signatures must differ");
    assert!(Aimer::<Aim2erI>::verify(msg, &sig1, &pk).expect("verify error"));
    assert!(Aimer::<Aim2erI>::verify(msg, &sig2, &pk).expect("verify error"));
}

// =============================================================================
// AIM2er-III (192-bit security, AIM2 cipher)
// =============================================================================

#[test]
fn test_aim2_sign_verify_roundtrip_l3() {
    let (pk, sk) = Aimer::<Aim2erIII>::generate_keypair().expect("keygen failed");
    let msg = b"AIM2 L3 roundtrip test";

    let sig = Aimer::<Aim2erIII>::sign(msg, &sk).expect("signing failed");
    let result = Aimer::<Aim2erIII>::verify(msg, &sig, &pk).expect("verify error");

    assert!(result, "Aim2erIII signature failed verification");
}

#[test]
fn test_aim2_wrong_message_l3() {
    let (pk, sk) = Aimer::<Aim2erIII>::generate_keypair().expect("keygen failed");
    let msg = b"Original";
    let sig = Aimer::<Aim2erIII>::sign(msg, &sk).expect("signing failed");

    assert!(!Aimer::<Aim2erIII>::verify(b"Tampered", &sig, &pk).expect("verify error"));
}

// =============================================================================
// AIM2er-V (256-bit security, AIM2 cipher)
// =============================================================================

#[test]
fn test_aim2_sign_verify_roundtrip_l5() {
    let (pk, sk) = Aimer::<Aim2erV>::generate_keypair().expect("keygen failed");
    let msg = b"AIM2 L5 roundtrip test";

    let sig = Aimer::<Aim2erV>::sign(msg, &sk).expect("signing failed");
    let result = Aimer::<Aim2erV>::verify(msg, &sig, &pk).expect("verify error");

    assert!(result, "Aim2erV signature failed verification");
}

#[test]
fn test_aim2_wrong_message_l5() {
    let (pk, sk) = Aimer::<Aim2erV>::generate_keypair().expect("keygen failed");
    let msg = b"Original";
    let sig = Aimer::<Aim2erV>::sign(msg, &sk).expect("signing failed");

    assert!(!Aimer::<Aim2erV>::verify(b"Tampered", &sig, &pk).expect("verify error"));
}

// =============================================================================
// A signature with no proofs is rejected, not routed elsewhere
// =============================================================================

/// Until 2026-09 a `Signature` carrying no per-repetition proofs selected a
/// legacy AIM v1 verifier. AIM v1 is deleted, so this shape must now be an
/// outright rejection: the successor to `test_aim_v1_v2_cross_version_isolation`,
/// which proved the two ciphers did not interoperate. There is only one cipher
/// left, and the property worth holding is that the empty shape cannot be made
/// to verify against anything.
#[test]
fn test_proofless_signature_is_rejected() {
    let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().expect("keygen failed");
    let msg = b"Cross-version isolation test";
    let mut sig = Aimer::<Aim2erI>::sign(msg, &sk).expect("signing failed");
    assert!(Aimer::<Aim2erI>::verify(msg, &sig, &pk).expect("verify error"));

    sig.proofs.clear();
    assert!(!sig.is_well_formed());
    assert!(
        Aimer::<Aim2erI>::verify(msg, &sig, &pk).is_err(),
        "a signature with no proofs must be rejected, not verified"
    );
}

#[test]
fn test_aim2_empty_message() {
    let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().expect("keygen failed");
    let msg = b"";
    let sig = Aimer::<Aim2erI>::sign(msg, &sk).expect("signing failed");
    assert!(Aimer::<Aim2erI>::verify(msg, &sig, &pk).expect("verify error"));
}

#[test]
fn test_aim2_tampered_commitment() {
    let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().expect("keygen failed");
    let msg = b"Tamper test";
    let mut sig = Aimer::<Aim2erI>::sign(msg, &sk).expect("signing failed");

    // Tamper with the excluded party's commitment.
    assert!(!sig.proofs.is_empty(), "AIM2 signature must carry proofs");
    sig.proofs[0].com_excluded[0] ^= 0xFF;
    assert!(!Aimer::<Aim2erI>::verify(msg, &sig, &pk).expect("verify error"),
        "tampered commitment should fail");
}
