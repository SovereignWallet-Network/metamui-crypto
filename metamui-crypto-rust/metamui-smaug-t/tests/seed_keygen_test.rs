//! Deterministic key generation through the public `SmaugT` facade.
//!
//! `keygen_from_seed` expands the seed as `SHAKE-256(seed)` → `d ‖ inner_seed`,
//! the convention of the C binding's `metamui_smaugt_keypair_from_seed` (which
//! Python calls) and of C#'s `GenerateKeyPair(seed)`. This file used to claim
//! Go, Java, Kotlin and TypeScript shared it too; they do not (Go and Java use
//! the seed verbatim as the IND-CPA seed with a fresh `d`, Kotlin splits the
//! SHAKE output as `inner_seed ‖ d`, TypeScript uses the seed bytes directly).
//! It is deliberately *not* the NIST KAT DRBG — that path is
//! `SmaugTV1::keygen_internal`, exercised by
//! `v1_2_0_full_kat_byte_equality.rs` against the reference vectors.
//!
//! Before 2026-09 this file drove `backend::ReferenceBackend` directly, which
//! routed to the 2023 draft core. The property is the same; the algorithm
//! underneath it is now the v1.2.0 standard.

use metamui_smaug_t::smaug_v1_2_0::hash::{sha3_256, shake256};
use metamui_smaug_t::{SecurityLevel, SmaugT, SmaugTV1, SmaugV1Error, SmaugV1Mode};

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

/// The expansion is exactly `SHAKE-256(seed)[..32] = d`,
/// `SHAKE-256(seed)[32..64] = inner_seed`, fed to `keygen_internal`.
#[test]
fn seed_expansion_is_shake256_d_then_inner_seed() {
    let seed = b"any length is accepted";
    for mode in [SmaugV1Mode::Mode1, SmaugV1Mode::Mode3, SmaugV1Mode::Mode5, SmaugV1Mode::ModeT] {
        let kem = SmaugTV1::new(mode);
        let mut buf = [0u8; 64];
        shake256(&mut buf, seed);
        let d: [u8; 32] = buf[..32].try_into().unwrap();
        let inner: [u8; 32] = buf[32..].try_into().unwrap();
        assert_eq!(kem.keygen_from_seed(seed).unwrap(), kem.keygen_internal(&d, &inner), "{mode:?}");
    }
}

/// SHA3-256 of the keypair the C binding returns for `[0x42; 32]`, read
/// through the Python binding (`SmaugTV1(level).keygen_from_seed`, which calls
/// `metamui_smaugt_keypair_from_seed`). Pins the claim that Rust and C agree.
#[test]
fn seeded_keys_match_the_c_binding() {
    const C_DIGESTS: [(SecurityLevel, &str, &str); 3] = [
        (
            SecurityLevel::Level1,
            "a2ab2a24463eb3361fa7ca19f19ab0cbe4f62639bf6272399ebe67e03d0e85a0",
            "b1abdfd98cc92d15430f804e87f1a3733f892a2d2524cf0f0ffeade75ed7fdb8",
        ),
        (
            SecurityLevel::Level3,
            "10099a9cfa48456fd70f9fca57e93fab804374451eec4475cd412bac34e2bbbc",
            "761057c9875fe2dfb3a20fa33d9b165cfb74d512e62ef2789a346e0ef714e81b",
        ),
        (
            SecurityLevel::Level5,
            "da5aa693592f60d2e3745d1c08e6f5dd9e743d8b424cd1516e155eea5586534f",
            "e6b2660110c79daf84a0d493e1a167b8e9a57ec37de6470d243c2940eb4bef64",
        ),
    ];
    for (level, pk_digest, sk_digest) in C_DIGESTS {
        let (pk, sk) = SmaugT::new(level).unwrap().keygen_from_seed(&[0x42u8; 32]).unwrap();
        let mut h = [0u8; 32];
        sha3_256(&mut h, pk.as_bytes());
        assert_eq!(hex::encode(h), pk_digest, "{level:?}: public key differs from the C binding");
        sha3_256(&mut h, sk.as_bytes());
        assert_eq!(hex::encode(h), sk_digest, "{level:?}: secret key differs from the C binding");
    }
}

/// An empty seed expanded to one fixed keypair anyone can recompute. The C
/// and Python bindings refuse it; so does this one now.
#[test]
fn empty_seed_is_refused() {
    for mode in [SmaugV1Mode::Mode1, SmaugV1Mode::Mode3, SmaugV1Mode::Mode5, SmaugV1Mode::ModeT] {
        assert_eq!(SmaugTV1::new(mode).keygen_from_seed(&[]).unwrap_err(), SmaugV1Error::EmptySeed, "{mode:?}");
    }
}
