//! Falcon-512 upstream KAT replayed through the facade.
//!
//! * `test-vectors/falcon-upstream/falcon512/falcon512-KAT.rsp` — the NIST
//!   Round-3 submission's own answer file (compressed profile). Every record's
//!   public key and secret key must parse, every upstream signature must
//!   verify through `verify_compressed`, a tampered one must not, and the
//!   upstream secret key must sign a message that the upstream public key
//!   verifies.
//! * `test-vectors/falcon-upstream/falcon-padded-512/falcon-padded-512-KAT.rsp`
//!   — PQClean's `falcon-padded-512` answer file, same checks through the
//!   padded profile.
//!
//! The NIST signed-message framing is `len(2) ‖ nonce(40) ‖ msg ‖ 0x29 ‖ GR`
//! for the compressed file and `sig(666) ‖ msg` for the padded one; the
//! re-framing here mirrors the backend's own upstream gates.

mod common;

use common::{field, parse_rsp, read_fixture, seeded_rng, unhex};
use metamui_crypto::falcon512::{
    self, CompressedSignature, PaddedSignature, PublicKey, SecretKey, NONCE_BYTES, PADDED_SIGNATURE_BYTES,
};
use metamui_crypto::Error;

const COMPRESSED: &str = "falcon-upstream/falcon512/falcon512-KAT.rsp";
const PADDED: &str = "falcon-upstream/falcon-padded-512/falcon-padded-512-KAT.rsp";

/// Split a NIST `sm` into `(message, compressed signature in our framing)`.
fn reframe_compressed(sm: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sig_len = ((sm[0] as usize) << 8) | sm[1] as usize;
    let nonce = &sm[2..2 + NONCE_BYTES];
    let msg = &sm[2 + NONCE_BYTES..sm.len() - sig_len];
    let esig = &sm[sm.len() - sig_len..];
    assert_eq!(esig[0], 0x29, "upstream esig header");
    let mut sig = Vec::with_capacity(1 + NONCE_BYTES + esig.len() - 1);
    sig.push(falcon512::SIGNATURE_HEADER);
    sig.extend_from_slice(nonce);
    sig.extend_from_slice(&esig[1..]);
    (msg.to_vec(), sig)
}

#[test]
fn compressed_profile_reproduces_upstream_verify_and_signs_with_upstream_keys() {
    let records = parse_rsp(&read_fixture(COMPRESSED));
    assert!(!records.is_empty(), "no records in {COMPRESSED}");
    let mut rng = seeded_rng(0x5a);
    for (i, rec) in records.iter().enumerate() {
        let pk = PublicKey::from_bytes(&unhex(field(rec, "pk"))).unwrap_or_else(|e| panic!("record {i}: pk: {e}"));
        let sk = SecretKey::from_bytes(&unhex(field(rec, "sk"))).unwrap_or_else(|e| panic!("record {i}: sk: {e}"));
        let (msg, sig_bytes) = reframe_compressed(&unhex(field(rec, "sm")));
        assert_eq!(msg, unhex(field(rec, "msg")), "record {i}: message framing");

        let sig = CompressedSignature::from_bytes(&sig_bytes).unwrap_or_else(|e| panic!("record {i}: sig: {e}"));
        falcon512::verify_compressed(&pk, &msg, &sig).unwrap_or_else(|e| panic!("record {i}: upstream signature rejected: {e}"));

        // Tamper one Golomb-Rice byte: must be rejected, with no reason leaked.
        let mut t = sig_bytes.clone();
        t[1 + NONCE_BYTES + 3] ^= 0x01;
        let t = CompressedSignature::from_bytes(&t).unwrap();
        assert_eq!(falcon512::verify_compressed(&pk, &msg, &t), Err(Error::InvalidSignature), "record {i}: tampered accepted");

        // A trailing byte is not part of the profile.
        let mut extra = sig_bytes.clone();
        extra.push(0x00);
        match CompressedSignature::from_bytes(&extra) {
            Ok(s) => assert_eq!(falcon512::verify_compressed(&pk, &msg, &s), Err(Error::InvalidSignature), "record {i}: trailing byte accepted"),
            Err(Error::InvalidLength { .. }) => {}
            Err(e) => panic!("record {i}: unexpected {e}"),
        }

        // The upstream secret key signs; the upstream public key verifies.
        let ours = falcon512::sign_compressed(&sk, &msg, &mut rng).unwrap_or_else(|e| panic!("record {i}: sign: {e}"));
        falcon512::verify_compressed(&pk, &msg, &ours).unwrap_or_else(|e| panic!("record {i}: own signature rejected: {e}"));
        assert_ne!(ours.as_bytes(), &sig_bytes[..], "record {i}: signature must depend on the RNG stream");
    }
    eprintln!("PASS falcon-512.r3-compressed: {} upstream records verified, tampered rejected, upstream sk signs", records.len());
}

#[test]
fn padded_profile_reproduces_upstream_verify_and_signs_with_upstream_keys() {
    let records = parse_rsp(&read_fixture(PADDED));
    assert!(!records.is_empty(), "no records in {PADDED}");
    let mut rng = seeded_rng(0xa5);
    for (i, rec) in records.iter().enumerate() {
        let pk = PublicKey::from_bytes(&unhex(field(rec, "pk"))).unwrap_or_else(|e| panic!("record {i}: pk: {e}"));
        let sk = SecretKey::from_bytes(&unhex(field(rec, "sk"))).unwrap_or_else(|e| panic!("record {i}: sk: {e}"));
        let sm = unhex(field(rec, "sm"));
        let (sig_bytes, msg) = sm.split_at(PADDED_SIGNATURE_BYTES);
        assert_eq!(msg, &unhex(field(rec, "msg"))[..], "record {i}: message framing");

        let sig = PaddedSignature::from_bytes(sig_bytes).unwrap_or_else(|e| panic!("record {i}: sig: {e}"));
        falcon512::verify_padded(&pk, msg, &sig).unwrap_or_else(|e| panic!("record {i}: upstream signature rejected: {e}"));

        // Tamper one payload byte → rejected.
        let mut t = sig_bytes.to_vec();
        t[1 + NONCE_BYTES + 3] ^= 0x01;
        assert_eq!(falcon512::verify_padded(&pk, msg, &PaddedSignature::from_bytes(&t).unwrap()), Err(Error::InvalidSignature));

        // Non-zero padding byte → rejected (the upstream verifier's rule).
        let mut p = sig_bytes.to_vec();
        p[PADDED_SIGNATURE_BYTES - 1] = 0x01;
        assert_eq!(falcon512::verify_padded(&pk, msg, &PaddedSignature::from_bytes(&p).unwrap()), Err(Error::InvalidSignature), "record {i}: non-zero padding accepted");

        let ours = falcon512::sign_padded(&sk, msg, &mut rng).unwrap_or_else(|e| panic!("record {i}: sign: {e}"));
        assert_eq!(ours.as_bytes().len(), PADDED_SIGNATURE_BYTES);
        falcon512::verify_padded(&pk, msg, &ours).unwrap_or_else(|e| panic!("record {i}: own signature rejected: {e}"));
    }
    eprintln!("PASS falcon-512.r3-padded: {} upstream records verified, tampered and non-zero padding rejected, upstream sk signs", records.len());
}

#[test]
fn profiles_do_not_cross_verify() {
    // A compressed signature never verifies as padded and vice versa: the
    // types differ, so this is checked at the byte level on purpose.
    let records = parse_rsp(&read_fixture(PADDED));
    let rec = &records[0];
    let pk = PublicKey::from_bytes(&unhex(field(rec, "pk"))).unwrap();
    let sm = unhex(field(rec, "sm"));
    let (sig_bytes, msg) = sm.split_at(PADDED_SIGNATURE_BYTES);
    // The padded bytes are a syntactically valid compressed signature (0x39
    // header, ≤ 752 bytes) but carry zero padding the compressed verifier
    // must treat as trailing garbage.
    let as_compressed = CompressedSignature::from_bytes(sig_bytes).unwrap();
    assert_eq!(falcon512::verify_compressed(&pk, msg, &as_compressed), Err(Error::InvalidSignature));
}
