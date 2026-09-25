// Argon2 (RFC 9106) known-answer gates driven from the shared JSON vectors.
//
// 1. test-vectors/argon2/argon2-cffi-kat.json — authoritative libargon2 KAT
//    (argon2-cffi 25.1.0 `hash_secret_raw`): no secret / associated data.
// 2. test-vectors/argon2/argon2-test-vectors.json — RFC 9106 §4 vectors
//    (with secret + ad), PHC reference and cross-language vectors.
//
// PANICS (never skips) if a file is missing and asserts the exact number of
// vectors each carries.
use metamui_argon2::{
    argon2_hash, fill_memory_blocks, finalize, initialize, Argon2Type, Context, Instance,
};
use serde::Deserialize;
use std::fs;

fn read(file: &str) -> String {
    let path = format!(
        "{}/../../test-vectors/argon2/{}",
        env!("CARGO_MANIFEST_DIR"),
        file
    );
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Argon2 vector file missing ({path}): {e}"))
}

fn variant(name: &str) -> Argon2Type {
    match name.to_ascii_lowercase().as_str() {
        "argon2d" => Argon2Type::Argon2d,
        "argon2i" => Argon2Type::Argon2i,
        "argon2id" => Argon2Type::Argon2id,
        other => panic!("unknown Argon2 variant {other:?}"),
    }
}

// ---------------------------------------------------------------- cffi KAT

#[derive(Deserialize)]
struct CffiCase {
    label: String,
    variant: String,
    argon2_type: u32,
    password: String,
    salt: String,
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    tag_length: usize,
    version: u32,
    expected_tag: String,
}

#[derive(Deserialize)]
struct CffiFile {
    algorithm: String,
    argon2_version_constant: u32,
    test_vectors: Vec<CffiCase>,
}

#[test]
fn argon2_cffi_kat() {
    let file: CffiFile =
        serde_json::from_str(&read("argon2-cffi-kat.json")).expect("malformed cffi KAT JSON");
    assert_eq!(file.algorithm, "Argon2");
    assert_eq!(file.argon2_version_constant, 0x13);

    let mut count = 0;
    for tv in &file.test_vectors {
        let ty = Argon2Type::from_u32(tv.argon2_type)
            .unwrap_or_else(|| panic!("{}: bad argon2_type {}", tv.label, tv.argon2_type));
        assert_eq!(ty, variant(&tv.variant), "{}: variant/type disagree", tv.label);
        let password = hex::decode(&tv.password).expect("password hex");
        let salt = hex::decode(&tv.salt).expect("salt hex");
        let expected = hex::decode(&tv.expected_tag).expect("expected_tag hex");
        assert_eq!(expected.len(), tv.tag_length, "{}: tag_length disagrees", tv.label);

        let got = argon2_hash(
            &password,
            &salt,
            tv.time_cost,
            tv.memory_cost,
            tv.parallelism,
            tv.tag_length,
            ty,
            tv.version,
        )
        .unwrap_or_else(|e| panic!("{}: argon2_hash failed: {e}", tv.label));
        assert_eq!(got, expected, "Argon2 cffi KAT mismatch at {}", tv.label);
        count += 1;
    }
    assert_eq!(count, 14, "expected 14 argon2-cffi vectors, got {count}");
    println!("Argon2 cffi KAT: {count} vectors passed");
}

// ------------------------------------------------- cross-language vectors

#[derive(Deserialize)]
struct XlCase {
    name: String,
    variant: String,
    version: String,
    password_hex: String,
    salt_hex: String,
    #[serde(default)]
    secret_hex: String,
    #[serde(default)]
    ad_hex: String,
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
    hash_length: u32,
    expected_hash: String,
}

#[derive(Deserialize)]
struct XlFile {
    rfc: String,
    test_vectors: Vec<XlCase>,
}

#[test]
fn argon2_cross_language_vectors() {
    let file: XlFile = serde_json::from_str(&read("argon2-test-vectors.json"))
        .expect("malformed argon2-test-vectors JSON");
    assert_eq!(file.rfc, "RFC 9106");

    let mut count = 0;
    for tv in &file.test_vectors {
        let version = u32::from_str_radix(tv.version.trim_start_matches("0x"), 16)
            .unwrap_or_else(|_| panic!("{}: bad version {:?}", tv.name, tv.version));
        let password = hex::decode(&tv.password_hex).expect("password hex");
        let salt = hex::decode(&tv.salt_hex).expect("salt hex");
        let secret = hex::decode(&tv.secret_hex).expect("secret hex");
        let ad = hex::decode(&tv.ad_hex).expect("ad hex");
        let expected = hex::decode(&tv.expected_hash).expect("expected_hash hex");
        assert_eq!(expected.len() as u32, tv.hash_length, "{}: hash_length disagrees", tv.name);

        // The one-shot `argon2_hash` has no secret/ad parameters; drive the
        // three-phase core directly so the RFC 9106 §4 vectors (K and X set)
        // are exercised too.
        let context = Context::new(
            &password,
            &salt,
            tv.hash_length,
            tv.iterations,
            tv.memory_kb,
            tv.parallelism,
            variant(&tv.variant),
        )
        .with_secret(&secret)
        .with_ad(&ad)
        .with_version(version);
        let mut instance =
            Instance::new(&context).unwrap_or_else(|e| panic!("{}: Instance::new: {e}", tv.name));
        initialize(&context, &mut instance)
            .unwrap_or_else(|e| panic!("{}: initialize: {e}", tv.name));
        fill_memory_blocks(&mut instance)
            .unwrap_or_else(|e| panic!("{}: fill_memory_blocks: {e}", tv.name));
        let got = finalize(&context, &instance)
            .unwrap_or_else(|e| panic!("{}: finalize: {e}", tv.name));

        assert_eq!(got, expected, "Argon2 mismatch at {:?}", tv.name);
        count += 1;
    }
    assert_eq!(count, 13, "expected 13 argon2-test-vectors entries, got {count}");
    println!("Argon2 cross-language vectors: {count} passed");
}
