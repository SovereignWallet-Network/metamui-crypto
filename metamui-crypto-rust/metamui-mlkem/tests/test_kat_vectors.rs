// The KAT-vector helpers in this file (`vectors_path`, `NistKatFile`,
// `NistKatVector`, `hex_decode`, `FixedSeedRng`) are only exercised by
// tests gated behind `#[cfg(all(feature = "mlkem512", "mlkem768",
// "mlkem1024"))]`. Under the default feature set only `mlkem768` is on,
// which leaves the scaffolding present but unused. Rather than
// gate each helper individually on the same cfg, silence dead-code
// for the whole file.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Require standard features to compile all types
#[cfg(all(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
use metamui_mlkem::{mlkem512, mlkem768, mlkem1024, Kem};
#[cfg(all(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
use std::fs;
use rand_chacha::ChaCha20Rng;
use ::rand::{SeedableRng, RngCore, CryptoRng};

/// Resolve a path relative to the test-vectors/ml-kem directory.
fn vectors_path(relative: &str) -> PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for prefix in &["../..", "../../.."] {
        let path = manifest.join(prefix).join("test-vectors/ml-kem").join(relative);
        if path.exists() {
            return path;
        }
    }
    panic!(
        "Test vector file not found: {}. Searched from {:?}",
        relative, manifest
    );
}

#[derive(Debug, Deserialize, Serialize)]
struct NistKatFile {
    description: String,
    version: String,
    generated: String,
    vectors: Vec<NistKatVector>,
}

#[derive(Debug, Deserialize, Serialize)]
struct NistKatVector {
    variant: String,
    description: String,
    seed: String,
    expected_pk_length: usize,
    expected_sk_length: usize,
    expected_ct_length: usize,
    expected_ss_length: usize,
    notes: String,
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("Invalid hex string")
}

// A deterministic RNG wrapper to produce deterministic keypairs and encapsulation.
struct FixedSeedRng {
    seed: [u8; 32],
}

impl FixedSeedRng {
    fn new(seed: &[u8]) -> Self {
        let mut s = [0u8; 32];
        s.copy_from_slice(seed);
        Self { seed: s }
    }
}

impl RngCore for FixedSeedRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Very simplistic counter-based approach using ChaCha20Rng for filling bytes deterministically
        let mut rng = ChaCha20Rng::from_seed(self.seed);
        rng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedSeedRng {}


#[test]
#[cfg(all(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
fn test_mlkem_nist_kat_vectors() {
    let path = vectors_path("nist-kat.json");
    let data = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Unable to read ML-KEM test vectors at {:?}: {}", path, e));
    let test_file: NistKatFile = serde_json::from_str(&data)
        .expect("Unable to parse ML-KEM test vectors");
    
    for vector in test_file.vectors {
        let seed = hex_decode(&vector.seed);
        assert_eq!(seed.len(), 32);

        let mut rng = FixedSeedRng::new(&seed);
        let mut rng_enc = FixedSeedRng::new(&seed); // Provide same seed for encap phase

        match vector.variant.as_str() {
            "ML-KEM-512" => {
                let (pk, sk) = <mlkem512::MLKem512 as Kem>::generate_keypair(&mut rng)
                    .expect("ML-KEM-512 keygen failed");
                assert_eq!(pk.as_ref().len(), vector.expected_pk_length);
                assert_eq!(sk.as_ref().len(), vector.expected_sk_length);
                
                let (ct, ss1) = <mlkem512::MLKem512 as Kem>::encapsulate(&pk, &mut rng_enc)
                    .expect("ML-KEM-512 encap failed");
                assert_eq!(ct.as_ref().len(), vector.expected_ct_length);
                assert_eq!(ss1.as_ref().len(), vector.expected_ss_length);

                let ss2 = <mlkem512::MLKem512 as Kem>::decapsulate(&sk, &ct)
                    .expect("ML-KEM-512 decap failed");
                assert_eq!(ss1.as_ref(), ss2.as_ref());
                println!("ML-KEM-512 validated length & decapsulation");
            },
            "ML-KEM-768" => {
                // ML-KEM-768 exposes free functions returning a KeyPair (it
                // does not implement the generic `Kem` trait that 512/1024 do).
                let kp = mlkem768::generate_keypair(&mut rng)
                    .expect("ML-KEM-768 keygen failed");
                assert_eq!(kp.public_key.as_bytes().len(), vector.expected_pk_length);
                assert_eq!(kp.private_key.as_bytes().len(), vector.expected_sk_length);

                let (ct, ss1) = mlkem768::encapsulate(&kp.public_key, &mut rng_enc)
                    .expect("ML-KEM-768 encap failed");
                assert_eq!(ct.as_bytes().len(), vector.expected_ct_length);
                assert_eq!(ss1.as_bytes().len(), vector.expected_ss_length);

                let ss2 = mlkem768::decapsulate(&kp.private_key, &ct)
                    .expect("ML-KEM-768 decap failed");
                assert_eq!(ss1.as_bytes(), ss2.as_bytes());
                println!("ML-KEM-768 validated length & decapsulation");
            },
            "ML-KEM-1024" => {
                let (pk, sk) = <mlkem1024::MLKem1024 as Kem>::generate_keypair(&mut rng)
                    .expect("ML-KEM-1024 keygen failed");
                assert_eq!(pk.as_ref().len(), vector.expected_pk_length);
                assert_eq!(sk.as_ref().len(), vector.expected_sk_length);
                
                let (ct, ss1) = <mlkem1024::MLKem1024 as Kem>::encapsulate(&pk, &mut rng_enc)
                    .expect("ML-KEM-1024 encap failed");
                assert_eq!(ct.as_ref().len(), vector.expected_ct_length);
                assert_eq!(ss1.as_ref().len(), vector.expected_ss_length);

                let ss2 = <mlkem1024::MLKem1024 as Kem>::decapsulate(&sk, &ct)
                    .expect("ML-KEM-1024 decap failed");
                assert_eq!(ss1.as_ref(), ss2.as_ref());
                println!("ML-KEM-1024 validated length & decapsulation");
            },
            _ => panic!("Unknown ML-KEM variant: {}", vector.variant),
        }
    }
}
