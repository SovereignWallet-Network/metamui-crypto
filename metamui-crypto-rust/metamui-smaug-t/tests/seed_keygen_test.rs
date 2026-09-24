//! Deterministic key generation through the public `SmaugT` facade.
//!
//! `keygen_from_seed` is the cross-binding convention shared with the Python,
//! Go, Java, Kotlin, C# and TypeScript ports: the same 32-byte seed must give
//! the same keypair everywhere. It is deliberately *not* the NIST KAT DRBG —
//! that path is `SmaugTV1::keygen_internal`, exercised by
//! `v1_2_0_full_kat_byte_equality.rs` against the reference vectors.
//!
//! Before 2026-09 this file drove `backend::ReferenceBackend` directly, which
//! routed to the 2023 draft core. The property is the same; the algorithm
//! underneath it is now the v1.1.1 standard.

use metamui_smaug_t::{SecurityLevel, SmaugT};

const LEVELS: [SecurityLevel; 4] = [
    SecurityLevel::Level1,
    SecurityLevel::Level3,
    SecurityLevel::Level5,
    SecurityLevel::LevelT,
];

#[test]
fn seed_keygen_is_deterministic() {
    let seed = [0x42u8; 32];
    for level in LEVELS {
        let kem = SmaugT::new(level).expect("construct");
        let (pk1, sk1) = kem.keygen_from_seed(&seed).expect("keygen 1");
        let (pk2, sk2) = kem.keygen_from_seed(&seed).expect("keygen 2");
        assert_eq!(pk1.as_bytes(), pk2.as_bytes(), "{level:?}: public key not reproducible");
        assert_eq!(sk1.as_bytes(), sk2.as_bytes(), "{level:?}: secret key not reproducible");
    }
}

#[test]
fn distinct_seeds_give_distinct_keys() {
    for level in LEVELS {
        let kem = SmaugT::new(level).expect("construct");
        let (pk_a, _) = kem.keygen_from_seed(&[0x01u8; 32]).expect("keygen a");
        let (pk_b, _) = kem.keygen_from_seed(&[0x02u8; 32]).expect("keygen b");
        assert_ne!(pk_a.as_bytes(), pk_b.as_bytes(), "{level:?}: seed ignored");
    }
}

#[test]
fn seeded_keys_round_trip() {
    let seed = [0x7fu8; 32];
    for level in LEVELS {
        let kem = SmaugT::new(level).expect("construct");
        let (pk, sk) = kem.keygen_from_seed(&seed).expect("keygen");
        let (ct, ss_a) = kem.encapsulate(&pk).expect("encapsulate");
        // NIST argument order: (secret_key, ciphertext). The secret key
        // embeds the public key, so no third argument.
        let ss_b = kem.decapsulate(&sk, &ct).expect("decapsulate");
        assert_eq!(ss_a, ss_b, "{level:?}: shared secret mismatch");
    }
}
