//! Generate deterministic portable SLH-DSA vectors for cross-language conformance.

use metamui_slhdsa::params::{Parameters, SlhDsa128f, SlhDsa128s, SlhDsa192f, SlhDsa192s, SlhDsa256f, SlhDsa256s};
use metamui_slhdsa::{signing, slh_keygen_from_seeds, verification};
use serde_json::{json, Value};

fn seeded_bytes(len: usize, start: u8) -> Vec<u8> {
    (0..len).map(|i| start.wrapping_add(i as u8)).collect()
}

fn make_case<P: Parameters>(parameter_set: &str, message: &[u8], context: &[u8]) -> Value {
    let sk_seed = seeded_bytes(P::N, 0x10);
    let sk_prf = seeded_bytes(P::N, 0x40);
    let pk_seed = seeded_bytes(P::N, 0x80);

    let (public_key, secret_key) =
        slh_keygen_from_seeds::<P>(&sk_seed, &sk_prf, &pk_seed).expect("keygen must succeed");

    let signature = signing::slh_sign_deterministic::<P>(
        &sk_seed, &sk_prf, &pk_seed, &public_key[P::N..], message, context,
    )
    .expect("sign must succeed");

    let pk_seed = &public_key[..P::N];
    let pk_root = &public_key[P::N..];
    verification::slh_verify::<P>(pk_seed, pk_root, message, context, &signature)
        .expect("signature must verify");

    json!({
        "parameter_set": parameter_set,
        "message": hex::encode(message),
        "context": hex::encode(context),
        "sk_seed": hex::encode(sk_seed),
        "sk_prf": hex::encode(sk_prf),
        "pk_seed": hex::encode(pk_seed),
        "public_key": hex::encode(public_key),
        "secret_key": hex::encode(secret_key),
        "signature": hex::encode(signature),
        "signature_len": P::SIG_BYTES
    })
}

fn main() {
    let context = b"metamui-slhdsa-portable-v1";
    let message = b"MetaMUI SLH-DSA portable deterministic vector";

    let vectors = vec![
        make_case::<SlhDsa128s>("SLH-DSA-SHAKE-128s", message, context),
        make_case::<SlhDsa128f>("SLH-DSA-SHAKE-128f", message, context),
        make_case::<SlhDsa192s>("SLH-DSA-SHAKE-192s", message, context),
        make_case::<SlhDsa192f>("SLH-DSA-SHAKE-192f", message, context),
        make_case::<SlhDsa256s>("SLH-DSA-SHAKE-256s", message, context),
        make_case::<SlhDsa256f>("SLH-DSA-SHAKE-256f", message, context),
    ];

    let output = json!({
        "name": "SLH-DSA Portable Deterministic Vectors",
        "version": "1.0.0",
        "source": "metamui-slhdsa canonical Rust implementation",
        "notes": [
            "Deterministic vectors for cross-language conformance.",
            "Signatures generated with empty randomization and fixed seeds."
        ],
        "vectors": vectors
    });

    println!("{}", serde_json::to_string_pretty(&output).expect("json serialization"));
}
