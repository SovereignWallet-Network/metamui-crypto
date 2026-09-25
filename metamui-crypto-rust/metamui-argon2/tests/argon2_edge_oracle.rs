// Argon2 parameter edges against test-vectors/argon2/argon2-edge-oracle.json
// (tools/argon2-edge-oracle-gen: argon2-cffi — the reference C — generates,
// golang.org/x/crypto/argon2 cross-checks the Argon2i/id cases).
//
// Every earlier vector used m a multiple of 4p, so RFC 9106's m' = 4p·⌊m/4p⌋
// was never exercised, and nothing checked the §3.1 bounds. The valid cases
// run through both entry points (argon2_hash when there is no K/X, the
// Context pipeline always); the invalid ones must be refused by both.
use metamui_argon2::{argon2_hash, fill_memory_blocks, finalize, initialize, Argon2Type, Context, Instance};
use serde_json::Value;
use std::fs;

fn load() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/argon2/argon2-edge-oracle.json");
    let data = fs::read_to_string(path).unwrap_or_else(|e| panic!("Argon2 vector file missing ({path}): {e}"));
    serde_json::from_str(&data).unwrap()
}

fn hx(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}

fn num(v: &Value, k: &str) -> u32 {
    v[k].as_u64().unwrap() as u32
}

fn variant(v: &Value) -> Argon2Type {
    match v["type"].as_str().unwrap() {
        "argon2d" => Argon2Type::Argon2d,
        "argon2i" => Argon2Type::Argon2i,
        "argon2id" => Argon2Type::Argon2id,
        other => panic!("unknown type {other}"),
    }
}

fn via_context(v: &Value) -> Result<Vec<u8>, String> {
    let ctx = Context::new(&hx(v, "password"), &hx(v, "salt"), num(v, "tag_len"), num(v, "t"), num(v, "m"), num(v, "p"), variant(v))
        .with_secret(&hx(v, "secret"))
        .with_ad(&hx(v, "ad"))
        .with_version(num(v, "version"));
    let mut inst = Instance::new(&ctx).map_err(|e| e.to_string())?;
    initialize(&ctx, &mut inst)?;
    fill_memory_blocks(&mut inst)?;
    finalize(&ctx, &inst)
}

fn via_hash(v: &Value) -> Result<Vec<u8>, String> {
    argon2_hash(&hx(v, "password"), &hx(v, "salt"), num(v, "t"), num(v, "m"), num(v, "p"), num(v, "tag_len") as usize, variant(v), num(v, "version"))
}

#[test]
fn valid_edges_match_the_reference() {
    let doc = load();
    let cases = doc["valid"].as_array().unwrap();
    assert_eq!(cases.len(), doc["valid_count"].as_u64().unwrap() as usize);
    for v in cases {
        let id = v["tcId"].as_u64().unwrap();
        let want = v["tag"].as_str().unwrap();
        let got = via_context(v).unwrap_or_else(|e| panic!("tcId {id}: {e}"));
        assert_eq!(hex::encode(got), want, "tcId {id} (Context, {} m={} p={})", v["type"], v["m"], v["p"]);
        if v["secret"].as_str().unwrap().is_empty() && v["ad"].as_str().unwrap().is_empty() {
            let got = via_hash(v).unwrap_or_else(|e| panic!("tcId {id}: {e}"));
            assert_eq!(hex::encode(got), want, "tcId {id} (argon2_hash)");
        }
    }
}

#[test]
fn invalid_parameters_are_refused() {
    let doc = load();
    let cases = doc["invalid"].as_array().unwrap();
    assert_eq!(cases.len(), doc["invalid_count"].as_u64().unwrap() as usize);
    for v in cases {
        let id = v["tcId"].as_u64().unwrap();
        assert!(via_hash(v).is_err(), "tcId {id} ({}) accepted by argon2_hash", v["comment"]);
        assert!(via_context(v).is_err(), "tcId {id} ({}) accepted by the Context pipeline", v["comment"]);
    }
}

#[test]
fn m_not_a_multiple_of_4p_still_depends_on_the_password() {
    let a = argon2_hash(b"a", b"saltsalt", 1, 10, 1, 32, Argon2Type::Argon2id, 0x13).unwrap();
    let b = argon2_hash(b"b", b"saltsalt", 1, 10, 1, 32, Argon2Type::Argon2id, 0x13).unwrap();
    assert_ne!(a, b);
}
