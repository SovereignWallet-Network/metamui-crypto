use metamui_aimer::{Aimer, Aim2erI, Aim2erIII, Aim2erV};

// --- AIM2er-I (128-bit security) ---

#[test]
fn test_sign_verify_roundtrip_aim2er_i() {
    let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().expect("keygen failed");
    let msg = b"Round trip testing";
    println!("msg: {}", String::from_utf8_lossy(msg));

    println!("Signing (AIM2er-I)...");
    let sig = Aimer::<Aim2erI>::sign(msg, &sk).expect("signing failed");
    println!("sig: salt={}... ({} bytes salt)", hex::encode(&sig.salt[..8]), sig.salt.len());

    println!("Verifying...");
    let result = Aimer::<Aim2erI>::verify(msg, &sig, &pk).expect("verify error");
    println!("result: {}", result);

    assert!(result, "randomized signature failed verification");
}

#[test]
fn test_randomized_signatures_differ_aim2er_i() {
    let (pk, sk) = Aimer::<Aim2erI>::generate_keypair().expect("keygen failed");
    let msg = b"Round trip testing";

    println!("Signing (first, AIM2er-I)...");
    let sig1 = Aimer::<Aim2erI>::sign(msg, &sk).expect("signing failed");

    println!("Signing (second, AIM2er-I)...");
    let sig2 = Aimer::<Aim2erI>::sign(msg, &sk).expect("signing failed");

    println!("sig1 salt: {}", hex::encode(&sig1.salt));
    println!("sig2 salt: {}", hex::encode(&sig2.salt));

    assert_ne!(sig1.salt, sig2.salt, "two randomized signatures must have different salts");
    println!("salts differ: ok");

    let r1 = Aimer::<Aim2erI>::verify(msg, &sig1, &pk).expect("verify error");
    let r2 = Aimer::<Aim2erI>::verify(msg, &sig2, &pk).expect("verify error");
    println!("verify sig1: {}", r1);
    println!("verify sig2: {}", r2);

    assert!(r1, "sig1 failed verification");
    assert!(r2, "sig2 failed verification");
}

// --- AIM2er-III (192-bit security) ---

#[test]
fn test_sign_verify_roundtrip_aim2er_iii() {
    let (pk, sk) = Aimer::<Aim2erIII>::generate_keypair().expect("keygen failed");
    let msg = b"Round trip testing";
    println!("msg: {}", String::from_utf8_lossy(msg));

    println!("Signing (AIM2er-III)...");
    let sig = Aimer::<Aim2erIII>::sign(msg, &sk).expect("signing failed");
    println!("sig: salt={}... ({} bytes salt)", hex::encode(&sig.salt[..8]), sig.salt.len());

    println!("Verifying...");
    let result = Aimer::<Aim2erIII>::verify(msg, &sig, &pk).expect("verify error");
    println!("result: {}", result);

    assert!(result, "randomized signature failed verification");
}

#[test]
fn test_randomized_signatures_differ_aim2er_iii() {
    let (pk, sk) = Aimer::<Aim2erIII>::generate_keypair().expect("keygen failed");
    let msg = b"Round trip testing";

    println!("Signing (first, AIM2er-III)...");
    let sig1 = Aimer::<Aim2erIII>::sign(msg, &sk).expect("signing failed");

    println!("Signing (second, AIM2er-III)...");
    let sig2 = Aimer::<Aim2erIII>::sign(msg, &sk).expect("signing failed");

    println!("sig1 salt: {}", hex::encode(&sig1.salt));
    println!("sig2 salt: {}", hex::encode(&sig2.salt));

    assert_ne!(sig1.salt, sig2.salt, "two randomized signatures must have different salts");
    println!("salts differ: ok");

    let r1 = Aimer::<Aim2erIII>::verify(msg, &sig1, &pk).expect("verify error");
    let r2 = Aimer::<Aim2erIII>::verify(msg, &sig2, &pk).expect("verify error");
    println!("verify sig1: {}", r1);
    println!("verify sig2: {}", r2);

    assert!(r1, "sig1 failed verification");
    assert!(r2, "sig2 failed verification");
}

// --- AIM2er-V (256-bit security) ---

#[test]
fn test_sign_verify_roundtrip_aim2er_v() {
    let (pk, sk) = Aimer::<Aim2erV>::generate_keypair().expect("keygen failed");
    let msg = b"Round trip testing";
    println!("msg: {}", String::from_utf8_lossy(msg));

    println!("Signing (AIM2er-V)...");
    let sig = Aimer::<Aim2erV>::sign(msg, &sk).expect("signing failed");
    println!("sig: salt={}... ({} bytes salt)", hex::encode(&sig.salt[..8]), sig.salt.len());

    println!("Verifying...");
    let result = Aimer::<Aim2erV>::verify(msg, &sig, &pk).expect("verify error");
    println!("result: {}", result);

    assert!(result, "randomized signature failed verification");
}

#[test]
fn test_randomized_signatures_differ_aim2er_v() {
    let (pk, sk) = Aimer::<Aim2erV>::generate_keypair().expect("keygen failed");
    let msg = b"Round trip testing";

    println!("Signing (first, AIM2er-V)...");
    let sig1 = Aimer::<Aim2erV>::sign(msg, &sk).expect("signing failed");

    println!("Signing (second, AIM2er-V)...");
    let sig2 = Aimer::<Aim2erV>::sign(msg, &sk).expect("signing failed");

    println!("sig1 salt: {}", hex::encode(&sig1.salt));
    println!("sig2 salt: {}", hex::encode(&sig2.salt));

    assert_ne!(sig1.salt, sig2.salt, "two randomized signatures must have different salts");
    println!("salts differ: ok");

    let r1 = Aimer::<Aim2erV>::verify(msg, &sig1, &pk).expect("verify error");
    let r2 = Aimer::<Aim2erV>::verify(msg, &sig2, &pk).expect("verify error");
    println!("verify sig1: {}", r1);
    println!("verify sig2: {}", r2);

    assert!(r1, "sig1 failed verification");
    assert!(r2, "sig2 failed verification");
}
