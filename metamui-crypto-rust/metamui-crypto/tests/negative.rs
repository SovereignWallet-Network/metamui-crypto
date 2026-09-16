//! Malformed inputs and unsupported profiles fail explicitly, with a typed
//! reason, before any cryptographic operation runs.

mod common;

use common::seeded_rng;
use metamui_crypto::falcon512::{self, CompressedSignature, PaddedSignature};
use metamui_crypto::mlkem768::{self, Ciphertext, DecapsulationKey, EncapsulationKey};
use metamui_crypto::{Error, Kind, LengthRule, Profile};

fn rng() -> rand_chacha::ChaCha20Rng {
    seeded_rng(0x11)
}

#[test]
fn unsupported_profiles_are_refused_not_substituted() {
    for id in ["", "falcon-512", "falcon512", "FALCON-512.R3-PADDED", "falcon-1024.r3-padded", "ml-kem-512", "ml-kem-1024", "ml-dsa-65", "haetae-2", "smaug-t.v1_2_0.mode3"] {
        assert_eq!(Profile::parse(id), Err(Error::UnsupportedProfile { requested: id.into() }), "{id:?}");
        assert!(id.parse::<Profile>().is_err());
    }
    for p in Profile::ALL {
        assert_eq!(Profile::parse(p.id()), Ok(p));
        assert_eq!(p.to_string(), p.id());
    }
    assert_eq!(Profile::Falcon512R3Compressed.kind(), Kind::Signature);
    assert_eq!(Profile::Falcon512R3Padded.kind(), Kind::Signature);
    assert_eq!(Profile::MlKem768.kind(), Kind::Kem);
}

#[test]
fn falcon512_key_lengths_and_headers() {
    let kp = falcon512::generate_keypair(&mut rng()).unwrap();
    let pk = kp.public_key.as_bytes().to_vec();
    let sk = kp.secret_key.as_bytes().to_vec();
    assert_eq!(pk[0], falcon512::PUBLIC_KEY_HEADER);
    assert_eq!(sk[0], falcon512::SECRET_KEY_HEADER);

    // Public key: off-by-one lengths, wrong header, Falcon-1024 header.
    assert_eq!(falcon512::PublicKey::from_bytes(&pk[..896]), Err(Error::InvalidLength { what: "falcon-512 public key", expected: LengthRule::Exactly(897), actual: 896 }));
    let mut long = pk.clone();
    long.push(0);
    assert!(matches!(falcon512::PublicKey::from_bytes(&long), Err(Error::InvalidLength { actual: 898, .. })));
    let mut bad = pk.clone();
    bad[0] = 0x0a;
    assert_eq!(falcon512::PublicKey::from_bytes(&bad), Err(Error::InvalidHeader { what: "falcon-512 public key", expected: 0x09, actual: 0x0a }));
    assert!(matches!(falcon512::PublicKey::from_bytes(&[]), Err(Error::InvalidLength { actual: 0, .. })));

    // Secret key: same rules.
    assert!(matches!(falcon512::SecretKey::from_bytes(&sk[..1280]), Err(Error::InvalidLength { expected: LengthRule::Exactly(1281), actual: 1280, .. })));
    let mut bad = sk.clone();
    bad[0] = 0x09; // a public-key header where a secret key is expected
    assert_eq!(falcon512::SecretKey::from_bytes(&bad).err(), Some(Error::InvalidHeader { what: "falcon-512 secret key", expected: 0x59, actual: 0x09 }));
    // 2305 bytes is a valid Falcon-1024 secret key length the backend would
    // accept; the profile does not.
    assert!(matches!(falcon512::SecretKey::from_bytes(&vec![0x5a; 2305]), Err(Error::InvalidLength { actual: 2305, .. })));

    // Public key bytes that decode nowhere.
    let mut junk = vec![0xff; 897];
    junk[0] = 0x09;
    assert!(matches!(falcon512::PublicKey::from_bytes(&junk), Err(Error::MalformedKey { .. }) | Ok(_)), "must not panic");
}

#[test]
fn falcon512_signature_lengths_and_headers() {
    let kp = falcon512::generate_keypair(&mut rng()).unwrap();
    let msg = b"length rules";
    let c = falcon512::sign_compressed(&kp.secret_key, msg, &mut rng()).unwrap();
    let p = falcon512::sign_padded(&kp.secret_key, msg, &mut rng()).unwrap();
    assert!(c.as_bytes().len() <= falcon512::COMPRESSED_SIGNATURE_MAX_BYTES);
    assert_eq!(p.as_bytes().len(), falcon512::PADDED_SIGNATURE_BYTES);
    assert_eq!(c.as_bytes()[0], falcon512::SIGNATURE_HEADER);
    assert_eq!(p.as_bytes()[0], falcon512::SIGNATURE_HEADER);

    // Compressed: too short, too long, wrong header.
    assert!(matches!(CompressedSignature::from_bytes(&c.as_bytes()[..41]), Err(Error::InvalidLength { expected: LengthRule::Between { min: 42, max: 752 }, actual: 41, .. })));
    assert!(matches!(CompressedSignature::from_bytes(&vec![0x39; 753]), Err(Error::InvalidLength { actual: 753, .. })));
    let mut bad = c.as_bytes().to_vec();
    bad[0] = 0x3a;
    assert_eq!(CompressedSignature::from_bytes(&bad), Err(Error::InvalidHeader { what: "falcon-512 compressed signature", expected: 0x39, actual: 0x3a }));

    // Padded: any other length, wrong header.
    assert!(matches!(PaddedSignature::from_bytes(&p.as_bytes()[..665]), Err(Error::InvalidLength { expected: LengthRule::Exactly(666), actual: 665, .. })));
    let mut long = p.as_bytes().to_vec();
    long.push(0);
    assert!(matches!(PaddedSignature::from_bytes(&long), Err(Error::InvalidLength { actual: 667, .. })));
    let mut bad = p.as_bytes().to_vec();
    bad[0] = 0x29;
    assert_eq!(PaddedSignature::from_bytes(&bad), Err(Error::InvalidHeader { what: "falcon-512 padded signature", expected: 0x39, actual: 0x29 }));

    // Wrong message, wrong key, flipped nonce → InvalidSignature, no detail.
    let other = falcon512::generate_keypair(&mut seeded_rng(0x22)).unwrap();
    assert_eq!(falcon512::verify_compressed(&kp.public_key, b"other", &c), Err(Error::InvalidSignature));
    assert_eq!(falcon512::verify_compressed(&other.public_key, msg, &c), Err(Error::InvalidSignature));
    assert_eq!(falcon512::verify_padded(&other.public_key, msg, &p), Err(Error::InvalidSignature));
    let mut nonce_flip = p.as_bytes().to_vec();
    nonce_flip[5] ^= 0x80;
    assert_eq!(falcon512::verify_padded(&kp.public_key, msg, &PaddedSignature::from_bytes(&nonce_flip).unwrap()), Err(Error::InvalidSignature));
    // Non-zero padding byte in an otherwise valid padded signature.
    let mut pad = p.as_bytes().to_vec();
    pad[665] |= 0x01;
    assert_eq!(falcon512::verify_padded(&kp.public_key, msg, &PaddedSignature::from_bytes(&pad).unwrap()), Err(Error::InvalidSignature));
    // The happy paths still hold.
    falcon512::verify_compressed(&kp.public_key, msg, &c).unwrap();
    falcon512::verify_padded(&kp.public_key, msg, &p).unwrap();
}

#[test]
fn falcon512_secret_key_round_trips_and_redacts() {
    let kp = falcon512::generate_keypair(&mut rng()).unwrap();
    let again = falcon512::SecretKey::from_bytes(kp.secret_key.as_bytes()).unwrap();
    assert_eq!(again.as_bytes(), kp.secret_key.as_bytes());
    assert_eq!(format!("{:?}", kp.secret_key), "falcon512::SecretKey(<redacted>)");
    assert!(!format!("{:?}", kp.public_key).contains("09"));
}

#[test]
fn mlkem768_lengths_and_key_checks() {
    let kp = mlkem768::generate_keypair(&mut rng()).unwrap();
    let ek = kp.encapsulation_key.as_bytes().to_vec();
    let dk = kp.decapsulation_key.as_bytes().to_vec();

    assert!(matches!(EncapsulationKey::from_bytes(&ek[..1183]), Err(Error::InvalidLength { what: "ml-kem-768 encapsulation key", expected: LengthRule::Exactly(1184), actual: 1183 })));
    assert!(matches!(EncapsulationKey::from_bytes(&vec![0u8; 800]), Err(Error::InvalidLength { actual: 800, .. })), "ML-KEM-512 ek size refused");
    assert!(matches!(EncapsulationKey::from_bytes(&vec![0u8; 1568]), Err(Error::InvalidLength { actual: 1568, .. })), "ML-KEM-1024 ek size refused");
    // A coefficient ≥ q fails the §7.2 modulus check: 0xFFF encodes 4095 > 3329.
    let mut bad = ek.clone();
    bad[0] = 0xff;
    bad[1] = 0xff;
    assert_eq!(EncapsulationKey::from_bytes(&bad), Err(Error::MalformedKey { what: "ml-kem-768 encapsulation key" }));

    assert!(matches!(DecapsulationKey::from_bytes(&dk[..2399]), Err(Error::InvalidLength { what: "ml-kem-768 decapsulation key", expected: LengthRule::Exactly(2400), actual: 2399 })));
    // Corrupt the embedded H(ek): §7.3 hash check fails.
    let mut bad = dk.clone();
    bad[2400 - 64] ^= 0x01;
    assert_eq!(DecapsulationKey::from_bytes(&bad).err(), Some(Error::MalformedKey { what: "ml-kem-768 decapsulation key" }));

    assert!(matches!(Ciphertext::from_bytes(&[0u8; 1087]), Err(Error::InvalidLength { what: "ml-kem-768 ciphertext", expected: LengthRule::Exactly(1088), actual: 1087 })));
    assert!(matches!(Ciphertext::from_bytes(&[0u8; 768]), Err(Error::InvalidLength { actual: 768, .. })), "ML-KEM-512 ct size refused");

    // Implicit rejection: a tampered, well-sized ciphertext decapsulates to a
    // different secret, and never to an error.
    let (ct, ss) = mlkem768::encapsulate(&kp.encapsulation_key, &mut rng()).unwrap();
    assert_eq!(mlkem768::decapsulate(&kp.decapsulation_key, &ct).unwrap(), ss);
    let mut t = ct.as_bytes().to_vec();
    t[17] ^= 0x40;
    let rejected = mlkem768::decapsulate(&kp.decapsulation_key, &Ciphertext::from_bytes(&t).unwrap()).unwrap();
    assert_ne!(rejected, ss);
    // A different decapsulation key also yields a different secret.
    let other = mlkem768::generate_keypair(&mut seeded_rng(0x22)).unwrap();
    assert_ne!(mlkem768::decapsulate(&other.decapsulation_key, &ct).unwrap(), ss);

    assert_eq!(format!("{:?}", kp.decapsulation_key), "mlkem768::DecapsulationKey(<redacted>)");
    assert_eq!(format!("{:?}", ss), "mlkem768::SharedSecret(<redacted>)");
}

#[cfg(feature = "std")]
#[test]
fn os_entry_points_work_and_differ_per_call() {
    let kp = falcon512::generate_keypair_os().unwrap();
    let a = falcon512::sign_padded_os(&kp.secret_key, b"os").unwrap();
    let b = falcon512::sign_padded_os(&kp.secret_key, b"os").unwrap();
    assert_ne!(a, b, "operating-system randomness must give fresh nonces");
    falcon512::verify_padded(&kp.public_key, b"os", &a).unwrap();
    falcon512::verify_padded(&kp.public_key, b"os", &b).unwrap();
    let c1 = falcon512::sign_compressed_os(&kp.secret_key, b"os").unwrap();
    falcon512::verify_compressed(&kp.public_key, b"os", &c1).unwrap();

    let kem = mlkem768::generate_keypair_os().unwrap();
    let (ct1, ss1) = mlkem768::encapsulate_os(&kem.encapsulation_key).unwrap();
    let (ct2, ss2) = mlkem768::encapsulate_os(&kem.encapsulation_key).unwrap();
    assert_ne!(ct1, ct2);
    assert_ne!(ss1, ss2);
    assert_eq!(mlkem768::decapsulate(&kem.decapsulation_key, &ct1).unwrap(), ss1);
}
