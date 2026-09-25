//! SP 800-90A Rev. 1 §10.2.1 input-length rules for CTR_DRBG without a
//! derivation function (review finding M-20). Table 3 caps both
//! max_personalization_string_length and max_additional_input_length at
//! seedlen (48 bytes for AES-256); §10.2.1.3.1 / §10.2.1.4.1 / §10.2.1.5.1
//! zero-pad shorter inputs to seedlen, and §4 defines Null as the empty string.
//! The ACVP gate only exercises exactly-48-byte inputs.

use metamui_aes_ctr_drbg::{AesCtrDrbg, AesCtrDrbgError, SEEDLEN};

const SEED: [u8; SEEDLEN] = [0x5a; SEEDLEN];

fn out_of(d: &mut AesCtrDrbg, ai: Option<&[u8]>) -> [u8; 64] {
    let mut o = [0u8; 64];
    d.generate(&mut o, ai).unwrap();
    o
}

#[test]
fn personalization_longer_than_seedlen_is_refused() {
    // Used to be truncated to 48 bytes silently, so a 49-byte string
    // instantiated the same state as its 48-byte prefix.
    let r = AesCtrDrbg::new(&SEED, Some(&[0xA5; SEEDLEN + 1]));
    assert!(matches!(r, Err(AesCtrDrbgError::InvalidRequest(_))));
    assert!(AesCtrDrbg::new(&SEED, Some(&[0xA5; SEEDLEN])).is_ok());
}

#[test]
fn reseed_additional_input_longer_than_seedlen_is_refused() {
    let mut d = AesCtrDrbg::new(&SEED, None).unwrap();
    let r = d.reseed(&SEED, Some(&[0xA5; SEEDLEN + 1]));
    assert!(matches!(r, Err(AesCtrDrbgError::InvalidRequest(_))));
    // A refused reseed leaves the state as it was.
    let mut fresh = AesCtrDrbg::new(&SEED, None).unwrap();
    assert_eq!(out_of(&mut d, None), out_of(&mut fresh, None));
}

#[test]
fn generate_additional_input_longer_than_seedlen_is_refused() {
    let mut d = AesCtrDrbg::new(&SEED, None).unwrap();
    let mut o = [0u8; 16];
    let r = d.generate(&mut o, Some(&[0xA5; SEEDLEN + 1]));
    assert!(matches!(r, Err(AesCtrDrbgError::InvalidRequest(_))));
}

#[test]
fn empty_additional_input_is_null() {
    let mut a = AesCtrDrbg::new(&SEED, Some(&[])).unwrap();
    let mut b = AesCtrDrbg::new(&SEED, None).unwrap();
    a.reseed(&SEED, Some(&[])).unwrap();
    b.reseed(&SEED, None).unwrap();
    assert_eq!(out_of(&mut a, Some(&[])), out_of(&mut b, None));
    assert_eq!(out_of(&mut a, Some(&[])), out_of(&mut b, None));
}

#[test]
fn short_inputs_are_zero_padded_to_seedlen() {
    let short = [0xC3u8; 20];
    let mut padded = [0u8; SEEDLEN];
    padded[..short.len()].copy_from_slice(&short);

    let mut a = AesCtrDrbg::new(&SEED, Some(&short)).unwrap();
    let mut b = AesCtrDrbg::new(&SEED, Some(&padded)).unwrap();
    a.reseed(&SEED, Some(&short)).unwrap();
    b.reseed(&SEED, Some(&padded)).unwrap();
    assert_eq!(out_of(&mut a, Some(&short)), out_of(&mut b, Some(&padded)));
    assert_eq!(out_of(&mut a, Some(&short)), out_of(&mut b, Some(&padded)));
}
