use metamui_slhdsa::*;
use rand_core::OsRng;

#[test]
fn test_sign_verify_roundtrip() {
    type P = SlhDsa128s;

    let sk_seed = [0x01u8; P::N];
    let sk_prf = [0x02u8; P::N];
    let pk_seed = [0x03u8; P::N];

    let (pk, _sk) = slh_keygen_from_seeds::<P>(&sk_seed, &sk_prf, &pk_seed).expect("Keygen failed");

    let pk_root = &pk[P::N..];
    println!("pk_seed: {}", hex::encode(&pk_seed));
    println!("pk_root: {}", hex::encode(pk_root));

    let msg = b"Round trip testing";
    println!("msg:     {}", String::from_utf8_lossy(msg));

    println!("Signing...");
    let sig = signing::slh_sign_randomized::<P, _>(
        &sk_seed,
        &sk_prf,
        &pk_seed,
        pk_root,
        msg,
        &mut OsRng,
        &[],
    )
    .expect("signing failed");
    println!(
        "sig:     {}...{} ({} bytes)",
        hex::encode(&sig[..8]),
        hex::encode(&sig[sig.len() - 8..]),
        sig.len()
    );

    println!("Verifying...");
    let result = verification::slh_verify::<P>(&pk_seed, pk_root, msg, &[], &sig);
    println!("result:  {:?}", result);

    assert!(result.is_ok(), "randomized signature failed verification")
}

#[test]
fn test_randomized_signatures_differ() {
    type P = SlhDsa128s;

    let sk_seed = [0x01u8; P::N];
    let sk_prf = [0x02u8; P::N];
    let pk_seed = [0x03u8; P::N];

    let (pk, _sk) = slh_keygen_from_seeds::<P>(&sk_seed, &sk_prf, &pk_seed).expect("keygen failed");

    let pk_root = &pk[P::N..];
    let msg = b"Round trip testing";

    println!("Signing (first)...");
    let sig1 = signing::slh_sign_randomized::<P, _>(
        &sk_seed,
        &sk_prf,
        &pk_seed,
        pk_root,
        msg,
        &mut OsRng,
        &[],
    )
    .expect("signing failed");

    println!("Signing (second)...");
    let sig2 = signing::slh_sign_randomized::<P, _>(
        &sk_seed,
        &sk_prf,
        &pk_seed,
        pk_root,
        msg,
        &mut OsRng,
        &[],
    )
    .expect("signing failed");

    println!(
        "sig1: {}...{}",
        hex::encode(&sig1[..8]),
        hex::encode(&sig1[sig1.len() - 8..])
    );
    println!(
        "sig2: {}...{}",
        hex::encode(&sig2[..8]),
        hex::encode(&sig2[sig2.len() - 8..])
    );

    assert_ne!(sig1, sig2, "two randomized signatures must differ");
    println!("signatures differ: ok");

    let r1 = verification::slh_verify::<P>(&pk_seed, pk_root, msg, &[], &sig1);
    let r2 = verification::slh_verify::<P>(&pk_seed, pk_root, msg, &[], &sig2);
    println!("verify sig1: {:?}", r1);
    println!("verify sig2: {:?}", r2);

    assert!(r1.is_ok(), "sig1 failed verification");
    assert!(r2.is_ok(), "sig2 failed verification");
}
