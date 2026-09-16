//! NIST FIPS 203 ACVP byte-equality tests for ML-KEM — Finding #28 closure.
//!
//! Source: `test-vectors/ml-kem/acvp-fips203/*.json` — vendored from
//! GiacomoPope/kyber-py @ 897923667b2fa80afcf910fc8c1825dddf54a97d.
//!
//! These tests exercise the **in-tree MetaMUI ML-KEM** public API
//! (`metamui_mlkem::mlkem{512,768,1024}`) against genuine NIST FIPS 203 final
//! ACVP vectors, end-to-end through the variant wrapper modules:
//!   - keyGen:    (d, z)            -> (ek, dk)   byte-equal
//!   - encaps:    (ek, m)           -> (c,  K)    byte-equal
//!   - decaps:    (dk, c)           ->  K         byte-equal
//!
//! As of the Finding #28 in-tree FIPS 203 port (spurious-NTT removal in
//! `src/{kem,indcpa}.rs`, t̂/ŝ packed in the NTT domain), all three parameter
//! sets reproduce the ACVP vectors byte-for-byte from MetaMUI's own code — no
//! third-party `fips203` crate involved. See
//! `test-vectors/ml-kem/acvp-fips203/README.md` for the audit trail.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // metamui-crypto-rust
    p.pop(); // repo root
    p
}

fn load_acvp(filename: &str) -> Value {
    let path = workspace_root()
        .join("test-vectors/ml-kem/acvp-fips203")
        .join(filename);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {}", path.display(), e));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("could not parse {}: {}", path.display(), e))
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(cleaned.len() % 2 == 0, "odd hex length: {}", cleaned.len());
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("bad hex"))
        .collect()
}

fn hex_to_array32(hex: &str) -> [u8; 32] {
    let bytes = hex_to_bytes(hex);
    assert_eq!(bytes.len(), 32, "expected 32-byte hex, got {}", bytes.len());
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

// =============================================================================
// ML-KEM-512
// =============================================================================

#[cfg(feature = "mlkem512")]
mod mlkem512 {
    use super::*;
    use metamui_mlkem::mlkem512::{
        decapsulate, encapsulate_deterministic, generate_keypair_from_dz, Ciphertext, PublicKey,
        SecretKey,
    };

    #[test]
    fn acvp_keygen_byte_equality() {
        let data = load_acvp("ml-kem-512-keygen-acvp.json");
        for tv in data["test_vectors"].as_array().unwrap() {
            let tc = tv["tcId"].as_u64().unwrap();
            let d = hex_to_array32(tv["d"].as_str().unwrap());
            let z = hex_to_array32(tv["z"].as_str().unwrap());
            let (pk, sk) = generate_keypair_from_dz(&d, &z).unwrap();
            assert_eq!(pk.as_bytes(), &hex_to_bytes(tv["ek"].as_str().unwrap())[..], "tc{tc} ek");
            assert_eq!(sk.as_bytes(), &hex_to_bytes(tv["dk"].as_str().unwrap())[..], "tc{tc} dk");
        }
    }

    #[test]
    fn acvp_encaps_byte_equality() {
        let data = load_acvp("ml-kem-512-encapdecap-acvp.json");
        for tv in data["encapsulation"]["test_vectors"].as_array().unwrap() {
            let tc = tv["tcId"].as_u64().unwrap();
            let pk = PublicKey::from_bytes(&hex_to_bytes(tv["ek"].as_str().unwrap())).unwrap();
            let m = hex_to_array32(tv["m"].as_str().unwrap());
            let (ct, ss) = encapsulate_deterministic(&pk, &m).unwrap();
            assert_eq!(ct.as_bytes(), &hex_to_bytes(tv["c"].as_str().unwrap())[..], "tc{tc} c");
            assert_eq!(ss.as_bytes(), &hex_to_bytes(tv["k"].as_str().unwrap())[..], "tc{tc} k");
        }
    }

    #[test]
    fn acvp_decaps_byte_equality() {
        let data = load_acvp("ml-kem-512-encapdecap-acvp.json");
        let sk = SecretKey::from_bytes(&hex_to_bytes(data["decapsulation"]["dk"].as_str().unwrap()))
            .unwrap();
        for tv in data["decapsulation"]["test_vectors"].as_array().unwrap() {
            let tc = tv["tcId"].as_u64().unwrap();
            let ct = Ciphertext::from_bytes(&hex_to_bytes(tv["c"].as_str().unwrap())).unwrap();
            let ss = decapsulate(&sk, &ct).unwrap();
            assert_eq!(ss.as_bytes(), &hex_to_bytes(tv["k"].as_str().unwrap())[..], "tc{tc} k");
        }
    }
}

// =============================================================================
// ML-KEM-768
// =============================================================================

#[cfg(feature = "mlkem768")]
mod mlkem768 {
    use super::*;
    use metamui_mlkem::mlkem768::{
        decapsulate, encapsulate_deterministic, generate_keypair_from_dz, Ciphertext, PrivateKey,
        PublicKey,
    };

    #[test]
    fn acvp_keygen_byte_equality() {
        let data = load_acvp("ml-kem-768-keygen-acvp.json");
        for tv in data["test_vectors"].as_array().unwrap() {
            let tc = tv["tcId"].as_u64().unwrap();
            let d = hex_to_array32(tv["d"].as_str().unwrap());
            let z = hex_to_array32(tv["z"].as_str().unwrap());
            let kp = generate_keypair_from_dz(&d, &z).unwrap();
            assert_eq!(&kp.public_key.as_bytes()[..], &hex_to_bytes(tv["ek"].as_str().unwrap())[..], "tc{tc} ek");
            assert_eq!(&kp.private_key.as_bytes()[..], &hex_to_bytes(tv["dk"].as_str().unwrap())[..], "tc{tc} dk");
        }
    }

    #[test]
    fn acvp_encaps_byte_equality() {
        let data = load_acvp("ml-kem-768-encapdecap-acvp.json");
        for tv in data["encapsulation"]["test_vectors"].as_array().unwrap() {
            let tc = tv["tcId"].as_u64().unwrap();
            let pk = PublicKey::from_slice(&hex_to_bytes(tv["ek"].as_str().unwrap())).unwrap();
            let m = hex_to_array32(tv["m"].as_str().unwrap());
            let (ct, ss) = encapsulate_deterministic(&pk, &m).unwrap();
            assert_eq!(&ct.as_bytes()[..], &hex_to_bytes(tv["c"].as_str().unwrap())[..], "tc{tc} c");
            assert_eq!(&ss.as_bytes()[..], &hex_to_bytes(tv["k"].as_str().unwrap())[..], "tc{tc} k");
        }
    }

    #[test]
    fn acvp_decaps_byte_equality() {
        let data = load_acvp("ml-kem-768-encapdecap-acvp.json");
        let sk = PrivateKey::from_slice(&hex_to_bytes(data["decapsulation"]["dk"].as_str().unwrap()))
            .unwrap();
        for tv in data["decapsulation"]["test_vectors"].as_array().unwrap() {
            let tc = tv["tcId"].as_u64().unwrap();
            let ct = Ciphertext::from_slice(&hex_to_bytes(tv["c"].as_str().unwrap())).unwrap();
            let ss = decapsulate(&sk, &ct).unwrap();
            assert_eq!(&ss.as_bytes()[..], &hex_to_bytes(tv["k"].as_str().unwrap())[..], "tc{tc} k");
        }
    }
}

// =============================================================================
// ML-KEM-1024
// =============================================================================

#[cfg(feature = "mlkem1024")]
mod mlkem1024 {
    use super::*;
    use metamui_mlkem::mlkem1024::{
        decapsulate, encapsulate_deterministic, generate_keypair_from_dz, Ciphertext, PublicKey,
        SecretKey,
    };

    #[test]
    fn acvp_keygen_byte_equality() {
        let data = load_acvp("ml-kem-1024-keygen-acvp.json");
        for tv in data["test_vectors"].as_array().unwrap() {
            let tc = tv["tcId"].as_u64().unwrap();
            let d = hex_to_array32(tv["d"].as_str().unwrap());
            let z = hex_to_array32(tv["z"].as_str().unwrap());
            let (pk, sk) = generate_keypair_from_dz(&d, &z).unwrap();
            assert_eq!(pk.as_bytes(), &hex_to_bytes(tv["ek"].as_str().unwrap())[..], "tc{tc} ek");
            assert_eq!(sk.as_bytes(), &hex_to_bytes(tv["dk"].as_str().unwrap())[..], "tc{tc} dk");
        }
    }

    #[test]
    fn acvp_encaps_byte_equality() {
        let data = load_acvp("ml-kem-1024-encapdecap-acvp.json");
        for tv in data["encapsulation"]["test_vectors"].as_array().unwrap() {
            let tc = tv["tcId"].as_u64().unwrap();
            let pk = PublicKey::from_bytes(&hex_to_bytes(tv["ek"].as_str().unwrap())).unwrap();
            let m = hex_to_array32(tv["m"].as_str().unwrap());
            let (ct, ss) = encapsulate_deterministic(&pk, &m).unwrap();
            assert_eq!(ct.as_bytes(), &hex_to_bytes(tv["c"].as_str().unwrap())[..], "tc{tc} c");
            assert_eq!(ss.as_bytes(), &hex_to_bytes(tv["k"].as_str().unwrap())[..], "tc{tc} k");
        }
    }

    #[test]
    fn acvp_decaps_byte_equality() {
        let data = load_acvp("ml-kem-1024-encapdecap-acvp.json");
        let sk = SecretKey::from_bytes(&hex_to_bytes(data["decapsulation"]["dk"].as_str().unwrap()))
            .unwrap();
        for tv in data["decapsulation"]["test_vectors"].as_array().unwrap() {
            let tc = tv["tcId"].as_u64().unwrap();
            let ct = Ciphertext::from_bytes(&hex_to_bytes(tv["c"].as_str().unwrap())).unwrap();
            let ss = decapsulate(&sk, &ct).unwrap();
            assert_eq!(ss.as_bytes(), &hex_to_bytes(tv["k"].as_str().unwrap())[..], "tc{tc} k");
        }
    }
}
