//! The v1.1.1 size table, asserted through the public API.
//!
//! These lengths are the cross-binding wire contract — ten language bindings
//! agree on them, and a consumer that sizes a buffer from a published constant
//! gets a wrong buffer if they drift (a defect class seen in a downstream
//! consumer). The
//! numbers come from the CryptoLab reference, not from this implementation.
//!
//! Before 2026-09 this file asserted the 2023 draft core's parameters.

use metamui_smaug_t::{SecurityLevel, SmaugT, SmaugTV1, SmaugV1Mode};

/// (level, public key, secret key, ciphertext)
const SIZES: [(SecurityLevel, usize, usize, usize); 3] = [
    (SecurityLevel::Level1, 672, 832, 672),
    (SecurityLevel::Level3, 1088, 1312, 992),
    (SecurityLevel::Level5, 1440, 1728, 1376),
];

#[test]
fn size_table_matches_the_reference() {
    for (level, pk, sk, ct) in SIZES {
        let kem = SmaugT::new(level).expect("construct");
        assert_eq!(kem.public_key_size(), pk, "{level:?}: public key size");
        assert_eq!(kem.secret_key_size(), sk, "{level:?}: secret key size");
        assert_eq!(kem.ciphertext_size(), ct, "{level:?}: ciphertext size");
    }
}

#[test]
fn produced_material_matches_the_advertised_sizes() {
    for (level, pk_len, sk_len, ct_len) in SIZES {
        let kem = SmaugT::new(level).expect("construct");
        let (pk, sk) = kem.keygen().expect("keygen");
        assert_eq!(pk.as_bytes().len(), pk_len, "{level:?}: public key bytes");
        assert_eq!(sk.as_bytes().len(), sk_len, "{level:?}: secret key bytes");
        let (ct, ss) = kem.encapsulate(&pk).expect("encapsulate");
        assert_eq!(ct.as_bytes().len(), ct_len, "{level:?}: ciphertext bytes");
        assert_eq!(ss.as_bytes().len(), 32, "{level:?}: shared secret bytes");
    }
}

#[test]
fn the_facade_and_the_reference_api_agree() {
    // `SmaugT` must be a facade, not a second implementation: for every level
    // the two surfaces must report identical sizes.
    for (level, mode) in [
        (SecurityLevel::Level1, SmaugV1Mode::Mode1),
        (SecurityLevel::Level3, SmaugV1Mode::Mode3),
        (SecurityLevel::Level5, SmaugV1Mode::Mode5),
        (SecurityLevel::LevelT, SmaugV1Mode::ModeT),
    ] {
        let facade = SmaugT::new(level).expect("construct");
        let direct = SmaugTV1::new(mode);
        assert_eq!(facade.public_key_size(), direct.public_key_bytes(), "{level:?}");
        assert_eq!(facade.secret_key_size(), direct.secret_key_bytes(), "{level:?}");
        assert_eq!(facade.ciphertext_size(), direct.ciphertext_bytes(), "{level:?}");
    }
}

#[test]
fn timer_is_not_reachable_from_a_number() {
    // TiMER is not a NIST level; `from_level` must refuse to produce it so it
    // cannot be selected by an off-by-one or a parsed config value.
    assert!(SmaugTV1::from_level(1).is_some());
    assert!(SmaugTV1::from_level(3).is_some());
    assert!(SmaugTV1::from_level(5).is_some());
    for n in [0u8, 2, 4, 6, 7, 255] {
        assert!(SmaugTV1::from_level(n).is_none(), "level {n} must not resolve");
    }
}
