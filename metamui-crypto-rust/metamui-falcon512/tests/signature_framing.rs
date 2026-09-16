//! Signature framing contract (consumer issue #7057): sizes have one source of
//! truth, no profile ever yields a truncatable or malleable encoding, and every
//! malformed shape is rejected before a success value is returned.

use metamui_falcon512::falcon1024::{generate_keypair_1024, sign_1024, sign_padded_1024, verify_1024, verify_padded_1024};
use metamui_falcon512::{generate_keypair, sign, sign_padded, sizes, verify, verify_padded, Falcon512Error, PrivateKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn size_table_matches_reference_and_pqclean() {
    // falcon.h FALCON_SIG_COMPRESSED_MAXSIZE / FALCON_SIG_PADDED_SIZE / FALCON_SIG_CT_SIZE
    assert_eq!(sizes::falcon512::SIG_COMPRESSED_MAX, 752);
    assert_eq!(sizes::falcon512::SIG_PADDED, 666);
    assert_eq!(sizes::falcon512::SIG_CT, 809);
    assert_eq!(sizes::falcon1024::SIG_COMPRESSED_MAX, 1462);
    assert_eq!(sizes::falcon1024::SIG_PADDED, 1280);
    assert_eq!(sizes::falcon1024::SIG_CT, 1577);
    // api.h CRYPTO_BYTES is signed-message overhead, and is smaller than the
    // compressed maximum — the number #7057 found used as a buffer bound.
    assert_eq!(sizes::falcon512::NIST_SM_OVERHEAD, 690);
    assert!(sizes::falcon512::NIST_SM_OVERHEAD < sizes::falcon512::SIG_COMPRESSED_MAX);
    assert_eq!(sizes::falcon512::PUBLIC_KEY, 897);
    assert_eq!(sizes::falcon512::SECRET_KEY, 1281);
    assert_eq!(sizes::SIG_PREFIX_LEN, 41);
}

#[test]
fn compressed_profile_is_bounded_and_strict() {
    let mut rng = StdRng::seed_from_u64(1);
    let kp = generate_keypair(&mut rng).unwrap();
    for i in 0..8u8 {
        let msg = [i; 33];
        let sig = sign(&msg, &kp.private_key, &mut rng).unwrap();
        assert!(sig.len() > sizes::SIG_PREFIX_LEN && sig.len() <= sizes::falcon512::SIG_COMPRESSED_MAX,
            "compressed length {} outside (41, 752]", sig.len());
        assert_eq!(sig[0], 0x39);
        assert_eq!(verify(&msg, &sig, &kp.public_key), Ok(true));

        // trailing byte → rejected (no malleable second encoding)
        let mut t = sig.clone();
        t.push(0x00);
        assert_ne!(verify(&msg, &t, &kp.public_key), Ok(true), "trailing byte accepted");
        // truncated by one → rejected
        assert_ne!(verify(&msg, &sig[..sig.len() - 1], &kp.public_key), Ok(true));
        // wrong header nibble → rejected
        let mut t = sig.clone();
        t[0] = 0x3A;
        assert_ne!(verify(&msg, &t, &kp.public_key), Ok(true));
        // truncated nonce → error, not success
        assert_ne!(verify(&msg, &sig[..30], &kp.public_key), Ok(true));
    }
}

#[test]
fn padded_profile_is_exact_and_rejects_non_zero_padding() {
    let mut rng = StdRng::seed_from_u64(2);
    let kp = generate_keypair(&mut rng).unwrap();
    let msg = b"fixed-size profile";
    let sig = sign_padded(msg, &kp.private_key, &mut rng).unwrap();
    assert_eq!(sig.len(), sizes::falcon512::SIG_PADDED);
    assert_eq!(sig[0], 0x39);
    assert_eq!(verify_padded(msg, &sig, &kp.public_key), Ok(true));
    // the compressed verifier must NOT accept a padded signature (it has trailing zeros)
    assert_ne!(verify(msg, &sig, &kp.public_key), Ok(true), "compressed verifier accepted a padded blob");

    let mut t = sig.clone();
    let last = t.len() - 1;
    assert_eq!(t[last], 0);
    t[last] = 1;
    assert!(matches!(verify_padded(msg, &t, &kp.public_key), Err(Falcon512Error::InvalidPadding)));
    assert!(matches!(verify_padded(msg, &sig[..sig.len() - 1], &kp.public_key), Err(Falcon512Error::InvalidPadding)));
    let mut long = sig.clone();
    long.push(0);
    assert!(matches!(verify_padded(msg, &long, &kp.public_key), Err(Falcon512Error::InvalidPadding)));
    // padded and compressed bodies are the same coder: strip the padding and it verifies compressed
    let body_end = sizes::SIG_PREFIX_LEN
        + {
            let (_, consumed) = metamui_falcon512::nist_encoding::comp_decode_consumed(&sig[sizes::SIG_PREFIX_LEN..], 9).unwrap();
            consumed
        };
    assert_eq!(verify(msg, &sig[..body_end], &kp.public_key), Ok(true));
}

#[test]
fn falcon1024_profiles() {
    let mut rng = StdRng::seed_from_u64(3);
    let kp = generate_keypair_1024(&mut rng).unwrap();
    let msg = b"falcon-1024";
    let sig = sign_1024(msg, &kp.private_key, &mut rng).unwrap();
    assert!(sig.len() <= sizes::falcon1024::SIG_COMPRESSED_MAX);
    assert_eq!(verify_1024(msg, &sig, &kp.public_key), Ok(true));
    let mut t = sig.clone();
    t.push(0);
    assert_ne!(verify_1024(msg, &t, &kp.public_key), Ok(true));
    let p = sign_padded_1024(msg, &kp.private_key, &mut rng).unwrap();
    assert_eq!(p.len(), sizes::falcon1024::SIG_PADDED);
    assert_eq!(verify_padded_1024(msg, &p, &kp.public_key), Ok(true));
}

#[test]
fn deterministic_rng_stream_gives_identical_compressed_bytes() {
    // Consensus signers seed the RNG from (sk, msg); the bytes must not move.
    let mut kr = StdRng::seed_from_u64(4);
    let kp = generate_keypair(&mut kr).unwrap();
    let msg = b"deterministic";
    let a = sign(msg, &kp.private_key, &mut StdRng::seed_from_u64(99)).unwrap();
    let b = sign(msg, &kp.private_key, &mut StdRng::seed_from_u64(99)).unwrap();
    assert_eq!(a, b);
}

#[test]
fn validated_import_accepts_fresh_keys() {
    let mut rng = StdRng::seed_from_u64(5);
    let kp = generate_keypair(&mut rng).unwrap();
    let bytes = kp.private_key.to_bytes();
    assert_eq!(bytes.len(), sizes::falcon512::SECRET_KEY);
    PrivateKey::from_bytes_validated(&bytes).expect("post-#141 key passes the sigma-band check");
}

#[cfg(feature = "std")]
#[test]
fn hedged_entry_points_produce_verifiable_signatures() {
    let mut rng = StdRng::seed_from_u64(6);
    let kp = generate_keypair(&mut rng).unwrap();
    let msg = b"hedged";
    let a = metamui_falcon512::sign_hedged(msg, &kp.private_key).unwrap();
    let b = metamui_falcon512::sign_hedged(msg, &kp.private_key).unwrap();
    assert_ne!(a, b, "hedged signing must not be deterministic");
    assert_eq!(verify(msg, &a, &kp.public_key), Ok(true));
    let p = metamui_falcon512::sign_padded_hedged(msg, &kp.private_key).unwrap();
    assert_eq!(p.len(), sizes::falcon512::SIG_PADDED);
    assert_eq!(verify_padded(msg, &p, &kp.public_key), Ok(true));
}
