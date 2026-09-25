//! FIPS 205 Algorithms 22–25: a context longer than 255 bytes is an error.
//!
//! M' carries |ctx| in a single byte. Without the check, a 256-byte context C
//! was written as length 0 followed by C, so M'(C, m) = M'(ε, C ‖ m): a
//! signature the signer made over C ‖ m with the empty context verified as a
//! signature over m in context C, which the signer never used. The first test
//! is that forgery; it verified before the check existed.

use metamui_slhdsa::*;

type P = SlhDsa128f;

struct Key {
    sk_seed: [u8; 16],
    sk_prf: [u8; 16],
    pk_seed: [u8; 16],
    pk_root: Vec<u8>,
}

fn key() -> Key {
    let (sk_seed, sk_prf, pk_seed) = ([0x11u8; 16], [0x22u8; 16], [0x33u8; 16]);
    let (pk, _sk) = slh_keygen_from_seeds::<P>(&sk_seed, &sk_prf, &pk_seed).unwrap();
    Key { sk_seed, sk_prf, pk_seed, pk_root: pk[P::N..].to_vec() }
}

#[test]
fn wrapped_length_byte_no_longer_forges_a_context() {
    let k = key();
    let ctx = [0xC7u8; 256];
    let msg = b"pay 100";

    // Honest signature over C || m with the empty context.
    let signed = [&ctx[..], &msg[..]].concat();
    let sig = signing::slh_sign_deterministic::<P>(&k.sk_seed, &k.sk_prf, &k.pk_seed, &k.pk_root, &signed, &[])
        .unwrap();
    verification::slh_verify::<P>(&k.pk_seed, &k.pk_root, &signed, &[], &sig).unwrap();

    // Presented as (ctx = C, m): the encodings used to coincide.
    assert_eq!(
        verification::slh_verify::<P>(&k.pk_seed, &k.pk_root, msg, &ctx, &sig),
        Err(Error::ContextTooLong)
    );
}

#[test]
fn every_context_entry_point_refuses_256_bytes() {
    let k = key();
    let long = [0u8; MAX_CONTEXT_BYTES + 1];
    let sig = vec![0u8; P::SIG_BYTES];
    let msg = b"m";
    let ph = PreHashAlgorithm::Sha256;

    assert_eq!(
        signing::slh_sign_deterministic::<P>(&k.sk_seed, &k.sk_prf, &k.pk_seed, &k.pk_root, msg, &long),
        Err(Error::ContextTooLong)
    );
    assert_eq!(
        signing::slh_sign_randomized::<P, _>(&k.sk_seed, &k.sk_prf, &k.pk_seed, &k.pk_root, msg, &mut rand_core::OsRng, &long),
        Err(Error::ContextTooLong)
    );
    assert_eq!(
        signing::slh_hash_sign_deterministic::<P>(&k.sk_seed, &k.sk_prf, &k.pk_seed, &k.pk_root, msg, &long, ph),
        Err(Error::ContextTooLong)
    );
    assert_eq!(
        verification::slh_verify::<P>(&k.pk_seed, &k.pk_root, msg, &long, &sig),
        Err(Error::ContextTooLong)
    );
    assert_eq!(
        verification::slh_hash_verify::<P>(&k.pk_seed, &k.pk_root, msg, &long, &sig, ph),
        Err(Error::ContextTooLong)
    );

    let mut pk = k.pk_seed.to_vec();
    pk.extend_from_slice(&k.pk_root);
    let vk = VerifyingKey::<P>::from_bytes(&pk).unwrap();
    let s = Signature::<P>::from_bytes(&sig).unwrap();
    assert_eq!(vk.verify_with_context(msg, &long, &s), Err(Error::ContextTooLong));
}

#[test]
fn a_255_byte_context_still_signs_and_verifies() {
    let k = key();
    let ctx = [0xA5u8; MAX_CONTEXT_BYTES];
    let msg = b"boundary";
    let ph = PreHashAlgorithm::Sha256;

    let sig = signing::slh_sign_deterministic::<P>(&k.sk_seed, &k.sk_prf, &k.pk_seed, &k.pk_root, msg, &ctx).unwrap();
    verification::slh_verify::<P>(&k.pk_seed, &k.pk_root, msg, &ctx, &sig).unwrap();

    let hsig =
        signing::slh_hash_sign_deterministic::<P>(&k.sk_seed, &k.sk_prf, &k.pk_seed, &k.pk_root, msg, &ctx, ph).unwrap();
    verification::slh_hash_verify::<P>(&k.pk_seed, &k.pk_root, msg, &ctx, &hsig, ph).unwrap();
}
