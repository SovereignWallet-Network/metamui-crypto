// Argon2 version 0x10 against test-vectors/argon2/argon2-v10-oracle.json
// (tools/argon2-edge-oracle-gen/gen_v10.py: argon2-cffi, the reference C).
// 0x10 overwrites blocks on the second and later passes where 0x13 XORs, and
// H0 hashes the version; every earlier vector was 0x13. This crate takes the
// version through argon2_hash and Context::with_version, so both are pinned.
use metamui_argon2::{argon2_hash, fill_memory_blocks, finalize, initialize, Argon2Type, Context, Instance};
use serde_json::Value;
use std::fs;

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

#[test]
fn version_0x10_matches_the_reference() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/argon2/argon2-v10-oracle.json");
    let data = fs::read_to_string(path).unwrap_or_else(|e| panic!("Argon2 vector file missing ({path}): {e}"));
    let doc: Value = serde_json::from_str(&data).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), doc["count"].as_u64().unwrap() as usize);
    for v in cases {
        let id = v["tcId"].as_u64().unwrap();
        assert_eq!(num(v, "version"), 0x10);
        let (pw, salt) = (hx(v, "password"), hx(v, "salt"));
        let got = argon2_hash(&pw, &salt, num(v, "t"), num(v, "m"), num(v, "p"), num(v, "tag_len") as usize, variant(v), 0x10)
            .unwrap_or_else(|e| panic!("tcId {id}: {e}"));
        assert_eq!(hex::encode(&got), v["tag"].as_str().unwrap(), "tcId {id} (argon2_hash)");

        let ctx = Context::new(&pw, &salt, num(v, "tag_len"), num(v, "t"), num(v, "m"), num(v, "p"), variant(v)).with_version(0x10);
        let mut inst = Instance::new(&ctx).unwrap();
        initialize(&ctx, &mut inst).unwrap();
        fill_memory_blocks(&mut inst).unwrap();
        assert_eq!(hex::encode(finalize(&ctx, &inst).unwrap()), v["tag"].as_str().unwrap(), "tcId {id} (Context)");

        let v13 = argon2_hash(&pw, &salt, num(v, "t"), num(v, "m"), num(v, "p"), num(v, "tag_len") as usize, variant(v), 0x13).unwrap();
        assert_eq!(hex::encode(v13), v["tag_v13"].as_str().unwrap(), "tcId {id} (0x13 control)");
    }
}
