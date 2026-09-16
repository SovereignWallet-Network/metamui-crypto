//! Verify reference Falcon-512 signatures in both MetaMUI wire encodings with
//! nothing but the public crate and public fixtures.
//!
//! The fixtures are the algorithm authors' own answer files, not anything a
//! MetaMUI system produced: the NIST Round-3 `falcon512-KAT.rsp` (the
//! *compressed* encoding, `0x39 ‖ nonce(40) ‖ compressed s2`, 617–752 bytes)
//! and PQClean's `falcon-padded-512-KAT.rsp` (the *padded* encoding, exactly
//! 666 bytes). An independent party can run this against a released
//! `metamui-crypto` and the same two files to confirm that the crate
//! verifies the documented formats, without any key, node or chain state.
//!
//!     cargo run --release --example verify_reference_signature -- \
//!         test-vectors/falcon-upstream/falcon512/falcon512-KAT.rsp \
//!         test-vectors/falcon-upstream/falcon-padded-512/falcon-padded-512-KAT.rsp
//!
//! Exit code 0 only when every record of both files verifies and every
//! tampered copy is rejected.
use metamui_crypto::falcon512::{self, CompressedSignature, PaddedSignature, PublicKey, NONCE_BYTES};
use std::{env, fs, process};

/// One `count = …` block of a NIST `.rsp` file.
fn records(text: &str) -> Vec<Vec<(String, String)>> {
    let mut out: Vec<Vec<(String, String)>> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some((k, v)) = line.split_once('=') {
            let (k, v) = (k.trim().to_string(), v.trim().to_string());
            if k == "count" { out.push(Vec::new()); }
            if let Some(rec) = out.last_mut() { rec.push((k, v)); }
        }
    }
    out
}

fn field<'a>(rec: &'a [(String, String)], name: &str) -> &'a str {
    rec.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).unwrap_or_else(|| { eprintln!("missing field {name}"); process::exit(2) })
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

/// NIST signed message → (message, signature in the compressed wire encoding).
fn reframe_compressed(sm: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sig_len = ((sm[0] as usize) << 8) | sm[1] as usize;
    let nonce = &sm[2..2 + NONCE_BYTES];
    let msg = &sm[2 + NONCE_BYTES..sm.len() - sig_len];
    let esig = &sm[sm.len() - sig_len..];
    let mut sig = vec![falcon512::SIGNATURE_HEADER];
    sig.extend_from_slice(nonce);
    sig.extend_from_slice(&esig[1..]);
    (msg.to_vec(), sig)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 { eprintln!("usage: verify_reference_signature <falcon512-KAT.rsp> <falcon-padded-512-KAT.rsp>"); process::exit(2); }
    let (mut ok, mut rejected) = (0usize, 0usize);
    for rec in records(&fs::read_to_string(&args[1]).expect("read compressed KAT")) {
        let pk = PublicKey::from_bytes(&unhex(field(&rec, "pk"))).expect("public key");
        let (msg, sig_bytes) = reframe_compressed(&unhex(field(&rec, "sm")));
        let sig = CompressedSignature::from_bytes(&sig_bytes).expect("compressed signature");
        falcon512::verify_compressed(&pk, &msg, &sig).expect("compressed signature must verify");
        let mut bad = msg.clone(); bad[0] ^= 1;
        assert!(falcon512::verify_compressed(&pk, &bad, &sig).is_err(), "tampered message must be rejected");
        ok += 1; rejected += 1;
    }
    for rec in records(&fs::read_to_string(&args[2]).expect("read padded KAT")) {
        let pk = PublicKey::from_bytes(&unhex(field(&rec, "pk"))).expect("public key");
        let sm = unhex(field(&rec, "sm"));
        let (sig_bytes, msg) = sm.split_at(falcon512::PADDED_SIGNATURE_BYTES);
        let sig = PaddedSignature::from_bytes(sig_bytes).expect("padded signature");
        falcon512::verify_padded(&pk, msg, &sig).expect("padded signature must verify");
        let mut bad = sig_bytes.to_vec(); bad[100] ^= 1;
        let tampered = PaddedSignature::from_bytes(&bad).expect("same length parses");
        assert!(falcon512::verify_padded(&pk, msg, &tampered).is_err(), "tampered signature must be rejected");
        ok += 1; rejected += 1;
    }
    println!("verified {ok} reference signatures (compressed + padded), rejected {rejected} tampered copies");
}
