//! ML-KEM genuine-upstream conformance gate.
//!
//! Reproduces the NIST FIPS 203 ACVP vectors vendored (and trimmed) at
//! `test-vectors/ml-kem-upstream/` byte-for-byte, through the in-tree public
//! API's native `(d, z)` / `m` interface. Mirrors the AIMer/Falcon/HQC gates.
//!
//! `encapdecap-tr1.json` (NIST ACVP revision FIPS203-tr1) adds the seed-format
//! decapsulation groups (d, z → dk; implicit-rejection ciphertexts included)
//! and the §7.2 / §7.3 key-check groups, which the `*_tr1` tests replay.
//!
//! Three tiers:
//!   (a) file absent           → SKIP loudly (suite stays green);
//!   (b) self-generated marker → FAIL (anti-circularity guard);
//!   (c) genuine FIPS 203      → reproduce EVERY record or panic.
//!
//! Unlike the circular `test-vectors/ml-kem/nist-kat.json` (which only proves
//! the bindings agree with each other under MetaMUI's in-house seed
//! convention), these vectors are NIST-authoritative — passing them proves
//! genuine FIPS 203 byte-equality.

use serde_json::Value;
use std::path::PathBuf;

/// Why a missing vector file fails instead of skipping.
const KAT_ABSENCE_NOTE: &str = "The vectors are tracked in this repo, so their absence is a broken checkout, not an environment quirk — and a green run that verified nothing is exactly what this gate exists to prevent.";

/// Phrase that marks a self-generated (circular) vector file. A genuine
/// upstream file must NOT contain it.
const SELFGEN_MARKER: &str = "MetaMUI cross-language consensus";

fn upstream_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // metamui-crypto-rust
    p.pop(); // repo root
    p.push("test-vectors/ml-kem-upstream");
    p
}

/// Load a `ml-kem-upstream/<variant>/<file>` JSON applying the three-tier
/// discipline. Panics if the file is absent — see KAT_ABSENCE_NOTE.
fn load_gate(variant: &str, file: &str, label: &str) -> Value {
    let path = upstream_dir().join(variant).join(file);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            panic!(
                "{label}: genuine-upstream KAT not readable at {} ({e}). \
                 See test-vectors/ml-kem-upstream/README.md. {KAT_ABSENCE_NOTE}",
                path.display()
            );
        }
    };
    // (b) anti-circularity: reject a self-generated file masquerading as upstream.
    assert!(
        !content.contains(SELFGEN_MARKER),
        "{label}: {} carries the self-generated marker ('{}'), not genuine NIST ACVP. \
         Verifying against it would be circular.",
        path.display(),
        SELFGEN_MARKER
    );
    let v: Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("{label}: parse {}: {}", path.display(), e));
    // (c) genuine marker: NIST FIPS 203 standard tag must be present.
    assert_eq!(
        v["standard"].as_str(),
        Some("FIPS 203"),
        "{label}: {} is missing the FIPS 203 standard tag",
        path.display()
    );
    v
}

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
fn arr32(s: &str) -> [u8; 32] {
    let b = unhex(s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    a
}

// =============================================================================
// ML-KEM-512
// =============================================================================
#[cfg(feature = "mlkem512")]
#[test]
fn mlkem512_upstream_gate() {
    use metamui_mlkem::mlkem512::{
        decapsulate, encapsulate_deterministic, generate_keypair_from_dz, Ciphertext, PublicKey,
        SecretKey,
    };
    let label = "ML-KEM-512";
    let kg = load_gate("ml-kem-512", "keygen.json", label);
    let mut n = 0;
    for tv in kg["test_vectors"].as_array().unwrap() {
        let (pk, sk) = generate_keypair_from_dz(&arr32(tv["d"].as_str().unwrap()), &arr32(tv["z"].as_str().unwrap())).unwrap();
        assert_eq!(pk.as_bytes(), &unhex(tv["ek"].as_str().unwrap())[..], "{label} keygen ek tc{}", tv["tcId"]);
        assert_eq!(sk.as_bytes(), &unhex(tv["dk"].as_str().unwrap())[..], "{label} keygen dk tc{}", tv["tcId"]);
        n += 1;
    }
    let ed = load_gate("ml-kem-512", "encapdecap.json", label);
    for tv in ed["encapsulation"]["test_vectors"].as_array().unwrap() {
        let pk = PublicKey::from_bytes(&unhex(tv["ek"].as_str().unwrap())).unwrap();
        let (ct, ss) = encapsulate_deterministic(&pk, &arr32(tv["m"].as_str().unwrap())).unwrap();
        assert_eq!(ct.as_bytes(), &unhex(tv["c"].as_str().unwrap())[..], "{label} encaps c tc{}", tv["tcId"]);
        assert_eq!(ss.as_bytes(), &unhex(tv["k"].as_str().unwrap())[..], "{label} encaps k tc{}", tv["tcId"]);
    }
    let sk = SecretKey::from_bytes(&unhex(ed["decapsulation"]["dk"].as_str().unwrap())).unwrap();
    for tv in ed["decapsulation"]["test_vectors"].as_array().unwrap() {
        let ct = Ciphertext::from_bytes(&unhex(tv["c"].as_str().unwrap())).unwrap();
        let ss = decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss.as_bytes(), &unhex(tv["k"].as_str().unwrap())[..], "{label} decaps k tc{}", tv["tcId"]);
    }
    eprintln!("PASS {label}: {n} keygen + encaps/decaps records reproduced byte-exact");
}

// =============================================================================
// ML-KEM-768
// =============================================================================
#[cfg(feature = "mlkem768")]
#[test]
fn mlkem768_upstream_gate() {
    use metamui_mlkem::mlkem768::{
        decapsulate, encapsulate_deterministic, generate_keypair_from_dz, Ciphertext, PrivateKey,
        PublicKey,
    };
    let label = "ML-KEM-768";
    let kg = load_gate("ml-kem-768", "keygen.json", label);
    let mut n = 0;
    for tv in kg["test_vectors"].as_array().unwrap() {
        let kp = generate_keypair_from_dz(&arr32(tv["d"].as_str().unwrap()), &arr32(tv["z"].as_str().unwrap())).unwrap();
        assert_eq!(&kp.public_key.as_bytes()[..], &unhex(tv["ek"].as_str().unwrap())[..], "{label} keygen ek tc{}", tv["tcId"]);
        assert_eq!(&kp.private_key.as_bytes()[..], &unhex(tv["dk"].as_str().unwrap())[..], "{label} keygen dk tc{}", tv["tcId"]);
        n += 1;
    }
    let ed = load_gate("ml-kem-768", "encapdecap.json", label);
    for tv in ed["encapsulation"]["test_vectors"].as_array().unwrap() {
        let pk = PublicKey::from_slice(&unhex(tv["ek"].as_str().unwrap())).unwrap();
        let (ct, ss) = encapsulate_deterministic(&pk, &arr32(tv["m"].as_str().unwrap())).unwrap();
        assert_eq!(&ct.as_bytes()[..], &unhex(tv["c"].as_str().unwrap())[..], "{label} encaps c tc{}", tv["tcId"]);
        assert_eq!(&ss.as_bytes()[..], &unhex(tv["k"].as_str().unwrap())[..], "{label} encaps k tc{}", tv["tcId"]);
    }
    let sk = PrivateKey::from_slice(&unhex(ed["decapsulation"]["dk"].as_str().unwrap())).unwrap();
    for tv in ed["decapsulation"]["test_vectors"].as_array().unwrap() {
        let ct = Ciphertext::from_slice(&unhex(tv["c"].as_str().unwrap())).unwrap();
        let ss = decapsulate(&sk, &ct).unwrap();
        assert_eq!(&ss.as_bytes()[..], &unhex(tv["k"].as_str().unwrap())[..], "{label} decaps k tc{}", tv["tcId"]);
    }
    eprintln!("PASS {label}: {n} keygen + encaps/decaps records reproduced byte-exact");
}

// =============================================================================
// ML-KEM-1024
// =============================================================================
#[cfg(feature = "mlkem1024")]
#[test]
fn mlkem1024_upstream_gate() {
    use metamui_mlkem::mlkem1024::{
        decapsulate, encapsulate_deterministic, generate_keypair_from_dz, Ciphertext, PublicKey,
        SecretKey,
    };
    let label = "ML-KEM-1024";
    let kg = load_gate("ml-kem-1024", "keygen.json", label);
    let mut n = 0;
    for tv in kg["test_vectors"].as_array().unwrap() {
        let (pk, sk) = generate_keypair_from_dz(&arr32(tv["d"].as_str().unwrap()), &arr32(tv["z"].as_str().unwrap())).unwrap();
        assert_eq!(pk.as_bytes(), &unhex(tv["ek"].as_str().unwrap())[..], "{label} keygen ek tc{}", tv["tcId"]);
        assert_eq!(sk.as_bytes(), &unhex(tv["dk"].as_str().unwrap())[..], "{label} keygen dk tc{}", tv["tcId"]);
        n += 1;
    }
    let ed = load_gate("ml-kem-1024", "encapdecap.json", label);
    for tv in ed["encapsulation"]["test_vectors"].as_array().unwrap() {
        let pk = PublicKey::from_bytes(&unhex(tv["ek"].as_str().unwrap())).unwrap();
        let (ct, ss) = encapsulate_deterministic(&pk, &arr32(tv["m"].as_str().unwrap())).unwrap();
        assert_eq!(ct.as_bytes(), &unhex(tv["c"].as_str().unwrap())[..], "{label} encaps c tc{}", tv["tcId"]);
        assert_eq!(ss.as_bytes(), &unhex(tv["k"].as_str().unwrap())[..], "{label} encaps k tc{}", tv["tcId"]);
    }
    let sk = SecretKey::from_bytes(&unhex(ed["decapsulation"]["dk"].as_str().unwrap())).unwrap();
    for tv in ed["decapsulation"]["test_vectors"].as_array().unwrap() {
        let ct = Ciphertext::from_bytes(&unhex(tv["c"].as_str().unwrap())).unwrap();
        let ss = decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss.as_bytes(), &unhex(tv["k"].as_str().unwrap())[..], "{label} decaps k tc{}", tv["tcId"]);
    }
    eprintln!("PASS {label}: {n} keygen + encaps/decaps records reproduced byte-exact");
}

#[cfg(feature = "mlkem512")]
#[test]
fn mlkem512_upstream_gate_tr1() {
    use metamui_mlkem::mlkem512::{
        decapsulate, encapsulate_deterministic, generate_keypair_from_dz, validate_decapsulation_key,
        validate_encapsulation_key, Ciphertext, PublicKey, SecretKey,
    };
    let label = "ML-KEM-512 tr1";
    let f = load_gate("ml-kem-512", "encapdecap-tr1.json", label);
    assert_eq!(f["revision"].as_str(), Some("FIPS203-tr1"), "{label}: revision tag");
    let mut n = 0;
    for tv in f["encapsulation"].as_array().unwrap() {
        let pk = PublicKey::from_bytes(&unhex(tv["ek"].as_str().unwrap())).unwrap();
        let (ct, ss) = encapsulate_deterministic(&pk, &arr32(tv["m"].as_str().unwrap())).unwrap();
        assert_eq!(&ct.as_bytes()[..], &unhex(tv["c"].as_str().unwrap())[..], "{label} encaps c tc{}", tv["tcId"]);
        assert_eq!(&ss.as_bytes()[..], &unhex(tv["k"].as_str().unwrap())[..], "{label} encaps k tc{}", tv["tcId"]);
        n += 1;
    }
    for tv in f["decapsulation"].as_array().unwrap() {
        let kp = generate_keypair_from_dz(&arr32(tv["d"].as_str().unwrap()), &arr32(tv["z"].as_str().unwrap())).unwrap();
        let (pk, sk) = kp;
        assert_eq!(&pk.as_bytes()[..], &unhex(tv["ek"].as_str().unwrap())[..], "{label} decaps ek tc{}", tv["tcId"]);
        assert_eq!(&sk.as_bytes()[..], &unhex(tv["dk"].as_str().unwrap())[..], "{label} decaps dk tc{}", tv["tcId"]);
        let ct = Ciphertext::from_bytes(&unhex(tv["c"].as_str().unwrap())).unwrap();
        let ss = decapsulate(&sk, &ct).unwrap();
        assert_eq!(&ss.as_bytes()[..], &unhex(tv["k"].as_str().unwrap())[..], "{label} decaps k tc{} ({})", tv["tcId"], tv["reason"]);
        n += 1;
    }
    for tv in f["encapsulationKeyCheck"].as_array().unwrap() {
        let want = tv["testPassed"].as_bool().unwrap();
        assert_eq!(validate_encapsulation_key(&unhex(tv["ek"].as_str().unwrap())), want, "{label} ekCheck tc{} ({})", tv["tcId"], tv["reason"]);
        n += 1;
    }
    for tv in f["decapsulationKeyCheck"].as_array().unwrap() {
        let want = tv["testPassed"].as_bool().unwrap();
        assert_eq!(validate_decapsulation_key(&unhex(tv["dk"].as_str().unwrap())), want, "{label} dkCheck tc{} ({})", tv["tcId"], tv["reason"]);
        n += 1;
    }
    // #323: the same key-check rows through the public encapsulate/decapsulate, which
    // must apply FIPS 203 §7.2/§7.3 themselves — a caller who never calls validate_*
    // is refused the same keys.
    let mut through_api = 0;
    for tv in f["encapsulationKeyCheck"].as_array().unwrap() {
        let want = tv["testPassed"].as_bool().unwrap();
        let pk = PublicKey::from_bytes(&unhex(tv["ek"].as_str().unwrap())).unwrap();
        let got = encapsulate_deterministic(&pk, &[0u8; 32]).is_ok();
        assert_eq!(got, want, "{label} encapsulate refuses ek tc{} ({})", tv["tcId"], tv["reason"]);
        through_api += 1;
    }
    for tv in f["decapsulationKeyCheck"].as_array().unwrap() {
        let want = tv["testPassed"].as_bool().unwrap();
        let sk = SecretKey::from_bytes(&unhex(tv["dk"].as_str().unwrap())).unwrap();
        let ct = Ciphertext::from_bytes(&[0u8; 768]).unwrap();
        let got = decapsulate(&sk, &ct).is_ok();
        assert_eq!(got, want, "{label} decapsulate refuses dk tc{} ({})", tv["tcId"], tv["reason"]);
        through_api += 1;
    }
    assert_eq!(through_api, 20, "{label}: 10 ek + 10 dk key-check rows through the public API");
    eprintln!("PASS {label}: {n} encaps/decaps/key-check records reproduced");
}

#[cfg(feature = "mlkem768")]
#[test]
fn mlkem768_upstream_gate_tr1() {
    use metamui_mlkem::mlkem768::{
        decapsulate, encapsulate_deterministic, generate_keypair_from_dz, validate_decapsulation_key,
        validate_encapsulation_key, Ciphertext, PrivateKey, PublicKey,
    };
    let label = "ML-KEM-768 tr1";
    let f = load_gate("ml-kem-768", "encapdecap-tr1.json", label);
    assert_eq!(f["revision"].as_str(), Some("FIPS203-tr1"), "{label}: revision tag");
    let mut n = 0;
    for tv in f["encapsulation"].as_array().unwrap() {
        let pk = PublicKey::from_slice(&unhex(tv["ek"].as_str().unwrap())).unwrap();
        let (ct, ss) = encapsulate_deterministic(&pk, &arr32(tv["m"].as_str().unwrap())).unwrap();
        assert_eq!(&ct.as_bytes()[..], &unhex(tv["c"].as_str().unwrap())[..], "{label} encaps c tc{}", tv["tcId"]);
        assert_eq!(&ss.as_bytes()[..], &unhex(tv["k"].as_str().unwrap())[..], "{label} encaps k tc{}", tv["tcId"]);
        n += 1;
    }
    for tv in f["decapsulation"].as_array().unwrap() {
        let kp = generate_keypair_from_dz(&arr32(tv["d"].as_str().unwrap()), &arr32(tv["z"].as_str().unwrap())).unwrap();
        let (pk, sk) = (kp.public_key, kp.private_key);
        assert_eq!(&pk.as_bytes()[..], &unhex(tv["ek"].as_str().unwrap())[..], "{label} decaps ek tc{}", tv["tcId"]);
        assert_eq!(&sk.as_bytes()[..], &unhex(tv["dk"].as_str().unwrap())[..], "{label} decaps dk tc{}", tv["tcId"]);
        let ct = Ciphertext::from_slice(&unhex(tv["c"].as_str().unwrap())).unwrap();
        let ss = decapsulate(&sk, &ct).unwrap();
        assert_eq!(&ss.as_bytes()[..], &unhex(tv["k"].as_str().unwrap())[..], "{label} decaps k tc{} ({})", tv["tcId"], tv["reason"]);
        n += 1;
    }
    for tv in f["encapsulationKeyCheck"].as_array().unwrap() {
        let want = tv["testPassed"].as_bool().unwrap();
        assert_eq!(validate_encapsulation_key(&unhex(tv["ek"].as_str().unwrap())), want, "{label} ekCheck tc{} ({})", tv["tcId"], tv["reason"]);
        n += 1;
    }
    for tv in f["decapsulationKeyCheck"].as_array().unwrap() {
        let want = tv["testPassed"].as_bool().unwrap();
        assert_eq!(validate_decapsulation_key(&unhex(tv["dk"].as_str().unwrap())), want, "{label} dkCheck tc{} ({})", tv["tcId"], tv["reason"]);
        n += 1;
    }
    // #323: the same key-check rows through the public encapsulate/decapsulate, which
    // must apply FIPS 203 §7.2/§7.3 themselves — a caller who never calls validate_*
    // is refused the same keys.
    let mut through_api = 0;
    for tv in f["encapsulationKeyCheck"].as_array().unwrap() {
        let want = tv["testPassed"].as_bool().unwrap();
        let pk = PublicKey::from_slice(&unhex(tv["ek"].as_str().unwrap())).unwrap();
        let got = encapsulate_deterministic(&pk, &[0u8; 32]).is_ok();
        assert_eq!(got, want, "{label} encapsulate refuses ek tc{} ({})", tv["tcId"], tv["reason"]);
        through_api += 1;
    }
    for tv in f["decapsulationKeyCheck"].as_array().unwrap() {
        let want = tv["testPassed"].as_bool().unwrap();
        let sk = PrivateKey::from_slice(&unhex(tv["dk"].as_str().unwrap())).unwrap();
        let ct = Ciphertext::from_slice(&[0u8; 1088]).unwrap();
        let got = decapsulate(&sk, &ct).is_ok();
        assert_eq!(got, want, "{label} decapsulate refuses dk tc{} ({})", tv["tcId"], tv["reason"]);
        through_api += 1;
    }
    assert_eq!(through_api, 20, "{label}: 10 ek + 10 dk key-check rows through the public API");
    eprintln!("PASS {label}: {n} encaps/decaps/key-check records reproduced");
}

#[cfg(feature = "mlkem1024")]
#[test]
fn mlkem1024_upstream_gate_tr1() {
    use metamui_mlkem::mlkem1024::{
        decapsulate, encapsulate_deterministic, generate_keypair_from_dz, validate_decapsulation_key,
        validate_encapsulation_key, Ciphertext, PublicKey, SecretKey,
    };
    let label = "ML-KEM-1024 tr1";
    let f = load_gate("ml-kem-1024", "encapdecap-tr1.json", label);
    assert_eq!(f["revision"].as_str(), Some("FIPS203-tr1"), "{label}: revision tag");
    let mut n = 0;
    for tv in f["encapsulation"].as_array().unwrap() {
        let pk = PublicKey::from_bytes(&unhex(tv["ek"].as_str().unwrap())).unwrap();
        let (ct, ss) = encapsulate_deterministic(&pk, &arr32(tv["m"].as_str().unwrap())).unwrap();
        assert_eq!(&ct.as_bytes()[..], &unhex(tv["c"].as_str().unwrap())[..], "{label} encaps c tc{}", tv["tcId"]);
        assert_eq!(&ss.as_bytes()[..], &unhex(tv["k"].as_str().unwrap())[..], "{label} encaps k tc{}", tv["tcId"]);
        n += 1;
    }
    for tv in f["decapsulation"].as_array().unwrap() {
        let kp = generate_keypair_from_dz(&arr32(tv["d"].as_str().unwrap()), &arr32(tv["z"].as_str().unwrap())).unwrap();
        let (pk, sk) = kp;
        assert_eq!(&pk.as_bytes()[..], &unhex(tv["ek"].as_str().unwrap())[..], "{label} decaps ek tc{}", tv["tcId"]);
        assert_eq!(&sk.as_bytes()[..], &unhex(tv["dk"].as_str().unwrap())[..], "{label} decaps dk tc{}", tv["tcId"]);
        let ct = Ciphertext::from_bytes(&unhex(tv["c"].as_str().unwrap())).unwrap();
        let ss = decapsulate(&sk, &ct).unwrap();
        assert_eq!(&ss.as_bytes()[..], &unhex(tv["k"].as_str().unwrap())[..], "{label} decaps k tc{} ({})", tv["tcId"], tv["reason"]);
        n += 1;
    }
    for tv in f["encapsulationKeyCheck"].as_array().unwrap() {
        let want = tv["testPassed"].as_bool().unwrap();
        assert_eq!(validate_encapsulation_key(&unhex(tv["ek"].as_str().unwrap())), want, "{label} ekCheck tc{} ({})", tv["tcId"], tv["reason"]);
        n += 1;
    }
    for tv in f["decapsulationKeyCheck"].as_array().unwrap() {
        let want = tv["testPassed"].as_bool().unwrap();
        assert_eq!(validate_decapsulation_key(&unhex(tv["dk"].as_str().unwrap())), want, "{label} dkCheck tc{} ({})", tv["tcId"], tv["reason"]);
        n += 1;
    }
    // #323: the same key-check rows through the public encapsulate/decapsulate, which
    // must apply FIPS 203 §7.2/§7.3 themselves — a caller who never calls validate_*
    // is refused the same keys.
    let mut through_api = 0;
    for tv in f["encapsulationKeyCheck"].as_array().unwrap() {
        let want = tv["testPassed"].as_bool().unwrap();
        let pk = PublicKey::from_bytes(&unhex(tv["ek"].as_str().unwrap())).unwrap();
        let got = encapsulate_deterministic(&pk, &[0u8; 32]).is_ok();
        assert_eq!(got, want, "{label} encapsulate refuses ek tc{} ({})", tv["tcId"], tv["reason"]);
        through_api += 1;
    }
    for tv in f["decapsulationKeyCheck"].as_array().unwrap() {
        let want = tv["testPassed"].as_bool().unwrap();
        let sk = SecretKey::from_bytes(&unhex(tv["dk"].as_str().unwrap())).unwrap();
        let ct = Ciphertext::from_bytes(&[0u8; 1568]).unwrap();
        let got = decapsulate(&sk, &ct).is_ok();
        assert_eq!(got, want, "{label} decapsulate refuses dk tc{} ({})", tv["tcId"], tv["reason"]);
        through_api += 1;
    }
    assert_eq!(through_api, 20, "{label}: 10 ek + 10 dk key-check rows through the public API");
    eprintln!("PASS {label}: {n} encaps/decaps/key-check records reproduced");
}
