//! The public `SmaugTV1` facade must reproduce the v1.1.1 oracle byte-for-byte
//! through the PUBLIC API (the existing byte-equality tests only prove the
//! internal `smaug_v1_2_0` module). KAT flow per `PQCgenKAT_kem.c`:
//! DRBG(seed) → d(32) ‖ inner_seed(32) → keypair_internal; DRBG → mu → enc_internal.
use metamui_aes_ctr_drbg::NistKatRng;
use metamui_smaug_t::smaug_v1_2_0::params::{CRYPTO_BYTES, T_BYTES};
use metamui_smaug_t::{SmaugTV1, SmaugV1Error, SmaugV1Mode};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::Value;
use std::path::PathBuf;

fn kat(filename: &str) -> Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("test-vectors/smaug-t/v1.2.0-kat");
    p.push(filename);
    let raw = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("oracle missing: {} ({e})", p.display()));
    serde_json::from_str(&raw).unwrap()
}

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s.chars().filter(|c| !c.is_whitespace()).collect::<String>()).unwrap()
}

fn check(filename: &str, kem: SmaugTV1, expect_sizes: (usize, usize, usize)) {
    assert_eq!((kem.public_key_bytes(), kem.secret_key_bytes(), kem.ciphertext_bytes()), expect_sizes, "{filename}: size table");
    let data = kat(filename);
    let vectors = data["test_vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for tv in vectors {
        let seed = hx(tv["seed"].as_str().unwrap());
        let mut drbg = NistKatRng::new(&seed).unwrap();
        let mut d = [0u8; T_BYTES];
        let mut inner = [0u8; CRYPTO_BYTES];
        drbg.randombytes_into(&mut d).unwrap();
        drbg.randombytes_into(&mut inner).unwrap();
        let (pk, sk) = kem.keygen_internal(&d, &inner);
        assert_eq!(pk, hx(tv["pk"].as_str().unwrap()), "{filename} count {}: pk", tv["count"]);
        assert_eq!(sk, hx(tv["sk"].as_str().unwrap()), "{filename} count {}: sk", tv["count"]);
        let mu = drbg.randombytes(kem.message_bytes()).unwrap();
        let (ct, ss) = kem.encapsulate_internal(&pk, &mu).unwrap();
        assert_eq!(ct, hx(tv["ct"].as_str().unwrap()), "{filename} count {}: ct", tv["count"]);
        assert_eq!(ss, hx(tv["ss"].as_str().unwrap()), "{filename} count {}: ss", tv["count"]);
        assert_eq!(kem.decapsulate(&sk, &ct).unwrap(), ss, "{filename} count {}: decaps", tv["count"]);
    }
}

#[test]
fn public_api_reproduces_v1_2_0_kat_mode1() {
    check("smaugt-mode1-v1.2.0-kat.json", SmaugTV1::new(SmaugV1Mode::Mode1), (672, 832, 672));
}
#[test]
fn public_api_reproduces_v1_2_0_kat_mode3() {
    check("smaugt-mode3-v1.2.0-kat.json", SmaugTV1::new(SmaugV1Mode::Mode3), (1088, 1312, 992));
}
#[test]
fn public_api_reproduces_v1_2_0_kat_mode5() {
    check("smaugt-mode5-v1.2.0-kat.json", SmaugTV1::new(SmaugV1Mode::Mode5), (1440, 1728, 1376));
}
#[test]
fn public_api_reproduces_v1_2_0_kat_modet() {
    let kem = SmaugTV1::new(SmaugV1Mode::ModeT);
    check("smaugt-modet-v1.2.0-kat.json", kem, (kem.public_key_bytes(), kem.secret_key_bytes(), kem.ciphertext_bytes()));
}

#[test]
fn from_level_selects_only_nist_levels() {
    assert_eq!(SmaugTV1::from_level(1).map(|k| k.mode()), Some(SmaugV1Mode::Mode1));
    assert_eq!(SmaugTV1::from_level(3).map(|k| k.mode()), Some(SmaugV1Mode::Mode3));
    assert_eq!(SmaugTV1::from_level(5).map(|k| k.mode()), Some(SmaugV1Mode::Mode5));
    assert!(SmaugTV1::from_level(2).is_none() && SmaugTV1::from_level(0).is_none());
}

#[test]
fn randomized_round_trip_and_seeded_keygen() {
    for mode in [SmaugV1Mode::Mode1, SmaugV1Mode::Mode3, SmaugV1Mode::Mode5, SmaugV1Mode::ModeT] {
        let kem = SmaugTV1::new(mode);
        let mut rng = StdRng::seed_from_u64(42);
        let (pk, sk) = kem.keygen(&mut rng);
        let (ct, ss) = kem.encapsulate(&pk, &mut rng).unwrap();
        assert_eq!(kem.decapsulate(&sk, &ct).unwrap(), ss);
        assert_eq!(ss.len(), kem.shared_secret_bytes());
        // seeded keygen is deterministic and interoperable with the Python facade's convention
        let (pk1, sk1) = kem.keygen_from_seed(b"metamui/smaug-t/v1.1.1/seed").unwrap();
        let (pk2, sk2) = kem.keygen_from_seed(b"metamui/smaug-t/v1.1.1/seed").unwrap();
        assert_eq!((pk1.len(), sk1.len()), (kem.public_key_bytes(), kem.secret_key_bytes()));
        assert_eq!((pk1, sk1), (pk2.clone(), sk2.clone()));
        let (ct, ss) = kem.encapsulate(&pk2, &mut rng).unwrap();
        assert_eq!(kem.decapsulate(&sk2, &ct).unwrap(), ss);
    }
}

#[test]
fn length_errors_are_typed() {
    let kem = SmaugTV1::new(SmaugV1Mode::Mode1);
    let mut rng = StdRng::seed_from_u64(1);
    let (pk, sk) = kem.keygen(&mut rng);
    assert_eq!(kem.encapsulate(&pk[..pk.len() - 1], &mut rng).unwrap_err(), SmaugV1Error::InvalidPublicKeyLength { expected: 672, got: 671 });
    assert_eq!(kem.decapsulate(&sk[..10], &vec![0u8; 672]).unwrap_err(), SmaugV1Error::InvalidSecretKeyLength { expected: 832, got: 10 });
    assert_eq!(kem.decapsulate(&sk, &vec![0u8; 10]).unwrap_err(), SmaugV1Error::InvalidCiphertextLength { expected: 672, got: 10 });
    assert_eq!(kem.encapsulate_internal(&pk, &[0u8; 5]).unwrap_err(), SmaugV1Error::InvalidMessageLength { expected: 32, got: 5 });
}
