//! ML-KEM-768 NIST ACVP vectors replayed through the facade's production
//! entry points.
//!
//! `generate_keypair` draws `d ‖ z` and `encapsulate` draws `m` from the
//! caller's RNG, so a scripted RNG reproduces the ACVP answers byte-for-byte
//! without any deterministic API. Fixtures:
//!
//! * `ml-kem-upstream/ml-kem-768/keygen.json` (FIPS 203 keyGen sample)
//! * `ml-kem-upstream/ml-kem-768/encapdecap.json` (FIPS 203 encapDecap sample)
//! * `ml-kem-upstream/ml-kem-768/encapdecap-tr1.json` (FIPS203-tr1, untrimmed,
//!   including the §7.2 / §7.3 key-check groups whose `testPassed=false` rows
//!   must be rejected by the key constructors)

mod common;

use common::{read_fixture, unhex, ScriptedRng};
use metamui_crypto::mlkem768::{self, Ciphertext, DecapsulationKey, EncapsulationKey};
use metamui_crypto::Error;
use serde_json::Value;

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("field {k}"))
}

#[test]
fn keygen_reproduces_acvp_sample() {
    let doc: Value = serde_json::from_str(&read_fixture("ml-kem-upstream/ml-kem-768/keygen.json")).unwrap();
    let tvs = doc["test_vectors"].as_array().unwrap();
    assert!(!tvs.is_empty());
    for tv in tvs {
        let mut seed = unhex(s(tv, "d"));
        seed.extend_from_slice(&unhex(s(tv, "z")));
        let mut rng = ScriptedRng::new(seed);
        let kp = mlkem768::generate_keypair(&mut rng).unwrap();
        assert!(rng.exhausted(), "keygen must draw exactly d ‖ z");
        assert_eq!(&kp.encapsulation_key.as_bytes()[..], &unhex(s(tv, "ek"))[..], "ek tc{}", tv["tcId"]);
        assert_eq!(&kp.decapsulation_key.as_bytes()[..], &unhex(s(tv, "dk"))[..], "dk tc{}", tv["tcId"]);
    }
    eprintln!("PASS ml-kem-768 keygen: {} ACVP records reproduced through generate_keypair", tvs.len());
}

fn run_encap_decap(rel: &str) -> (usize, usize) {
    let doc: Value = serde_json::from_str(&read_fixture(rel)).unwrap();
    let enc: Vec<&Value> = match &doc["encapsulation"] {
        Value::Array(a) => a.iter().collect(),
        Value::Object(o) => o["test_vectors"].as_array().unwrap().iter().collect(),
        _ => panic!("encapsulation shape"),
    };
    for tv in &enc {
        let ek = EncapsulationKey::from_bytes(&unhex(s(tv, "ek"))).unwrap();
        let mut rng = ScriptedRng::new(unhex(s(tv, "m")));
        let (ct, ss) = mlkem768::encapsulate(&ek, &mut rng).unwrap();
        assert!(rng.exhausted(), "encapsulate must draw exactly m");
        assert_eq!(&ct.as_bytes()[..], &unhex(s(tv, "c"))[..], "c tc{}", tv["tcId"]);
        assert_eq!(&ss.as_bytes()[..], &unhex(s(tv, "k"))[..], "k tc{}", tv["tcId"]);
    }
    let mut n_dec = 0;
    match &doc["decapsulation"] {
        Value::Object(o) => {
            let dk = DecapsulationKey::from_bytes(&unhex(o["dk"].as_str().unwrap())).unwrap();
            for tv in o["test_vectors"].as_array().unwrap() {
                let ct = Ciphertext::from_bytes(&unhex(s(tv, "c"))).unwrap();
                let ss = mlkem768::decapsulate(&dk, &ct).unwrap();
                assert_eq!(&ss.as_bytes()[..], &unhex(s(tv, "k"))[..], "k tc{}", tv["tcId"]);
                n_dec += 1;
            }
        }
        Value::Array(a) => {
            for tv in a {
                // tr1 rows carry (d, z) → dk; reproduce dk through keygen first.
                let mut seed = unhex(s(tv, "d"));
                seed.extend_from_slice(&unhex(s(tv, "z")));
                let kp = mlkem768::generate_keypair(&mut ScriptedRng::new(seed)).unwrap();
                assert_eq!(&kp.decapsulation_key.as_bytes()[..], &unhex(s(tv, "dk"))[..], "dk tc{}", tv["tcId"]);
                let ct = Ciphertext::from_bytes(&unhex(s(tv, "c"))).unwrap();
                let ss = mlkem768::decapsulate(&kp.decapsulation_key, &ct).unwrap();
                assert_eq!(&ss.as_bytes()[..], &unhex(s(tv, "k"))[..], "k tc{} ({})", tv["tcId"], tv["reason"]);
                n_dec += 1;
            }
        }
        _ => panic!("decapsulation shape"),
    }
    (enc.len(), n_dec)
}

#[test]
fn encap_decap_reproduces_acvp_sample() {
    let (e, d) = run_encap_decap("ml-kem-upstream/ml-kem-768/encapdecap.json");
    eprintln!("PASS ml-kem-768 encapDecap sample: {e} encaps + {d} decaps reproduced");
}

#[test]
fn encap_decap_reproduces_acvp_tr1_and_key_checks_reject() {
    let (e, d) = run_encap_decap("ml-kem-upstream/ml-kem-768/encapdecap-tr1.json");
    let doc: Value = serde_json::from_str(&read_fixture("ml-kem-upstream/ml-kem-768/encapdecap-tr1.json")).unwrap();
    let (mut ek_ok, mut ek_bad, mut dk_ok, mut dk_bad) = (0, 0, 0, 0);
    for tv in doc["encapsulationKeyCheck"].as_array().unwrap() {
        let r = EncapsulationKey::from_bytes(&unhex(s(tv, "ek")));
        match (tv["testPassed"].as_bool().unwrap(), r) {
            (true, Ok(_)) => ek_ok += 1,
            (false, Err(Error::MalformedKey { .. })) => ek_bad += 1,
            (want, got) => panic!("ek check tc{}: want pass={want}, got {got:?} ({})", tv["tcId"], tv["reason"]),
        }
    }
    for tv in doc["decapsulationKeyCheck"].as_array().unwrap() {
        let r = DecapsulationKey::from_bytes(&unhex(s(tv, "dk")));
        match (tv["testPassed"].as_bool().unwrap(), r) {
            (true, Ok(_)) => dk_ok += 1,
            (false, Err(Error::MalformedKey { .. })) => dk_bad += 1,
            (want, got) => panic!("dk check tc{}: want pass={want}, got {got:?} ({})", tv["tcId"], tv["reason"]),
        }
    }
    assert!(ek_bad > 0 && dk_bad > 0, "the fixture must contain rejection rows");
    eprintln!("PASS ml-kem-768 tr1: {e} encaps + {d} decaps reproduced; ek checks {ek_ok} accepted/{ek_bad} rejected; dk checks {dk_ok} accepted/{dk_bad} rejected");
}
