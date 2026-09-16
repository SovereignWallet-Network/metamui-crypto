use metamui_falcon512::constants::N;
use metamui_falcon512::error::Falcon512Error;
use metamui_falcon512::extended_key::ExtendedPrivateKey;
use metamui_falcon512::poly::Poly;
use metamui_falcon512::sign_extended::verify_extended;
use metamui_falcon512::PublicKey;

#[test]
fn test_extended_private_key_from_basic_fails_closed() {
    let poly = Poly::zero(N);

    let result = ExtendedPrivateKey::from_basic(poly.clone(), poly.clone(), poly.clone(), poly);

    assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
}

#[test]
fn test_extended_private_key_from_bytes_fails_closed() {
    let bytes = vec![0u8; N * 8];

    let result = ExtendedPrivateKey::from_bytes(&bytes);

    assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
}

#[test]
fn test_extended_verification_fails_closed() {
    let public_key = PublicKey { h: Poly::zero(N) };

    let result = verify_extended(b"message", &[0x39], &public_key);

    assert!(matches!(result, Err(Falcon512Error::NotImplemented)));
}
