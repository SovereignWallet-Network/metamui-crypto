// BLAKE3 official-vector conformance gate.
//
// Source: test-vectors/blake3/blake3-official-vectors.json (verbatim from
// the BLAKE3-team repository). Input: [i % 251 for i in 0..input_len].
//
// Every one of the 35 cases is checked in four modes:
//   1. plain hash, 32-byte digest
//   2. plain hash, full 131-byte XOF output
//   3. keyed hash, full 131-byte output
//   4. derive_key, full 131-byte output
// plus odd-sized streaming splits. The 131-byte comparisons prove the XOF
// extension bytes — the 2026-06 audit found the previous XOF/derive paths
// were homemade constructions that matched no real BLAKE3 implementation.
//
// The second test runs the same 35 cases through the paths that dispatch on
// `metamui_blake3::backend` — `hash_many`, `batch::batch_hash`,
// `parallel::hash` and `parallel::hash_keyed` — so a backend installed
// before this gate is measured by it, and the tree merge of `parallel` is
// proven on every chunk count the vectors cover (up to 100).
//
// PANICS (never skips) if the vector file is missing: a silent skip here
// previously let non-conformant code stay green.
use serde::Deserialize;
use std::fs;

use metamui_blake3::blake3::{self, Blake3Hasher};
use metamui_blake3::{batch, parallel};

const OUT_LEN: usize = 131;

#[derive(Deserialize)]
struct Case {
    input_len: usize,
    hash: String,
    keyed_hash: String,
    derive_key: String,
}

#[derive(Deserialize)]
struct VectorFile {
    key: String,
    context_string: String,
    cases: Vec<Case>,
}

fn make_input(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn load_vectors() -> VectorFile {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/blake3/blake3-official-vectors.json"
    );
    let data = fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "BLAKE3 official vector file missing ({path}): {e} — restore \
             test-vectors/blake3/ before trusting this build"
        )
    });
    serde_json::from_str(&data).expect("malformed BLAKE3 vector JSON")
}

#[test]
fn blake3_kat_official_all_modes() {
    let file = load_vectors();
    assert_eq!(file.cases.len(), 35, "expected the full official case set");

    let mut key = [0u8; 32];
    key.copy_from_slice(file.key.as_bytes());

    for case in &file.cases {
        let input = make_input(case.input_len);
        let exp_hash = hex::decode(&case.hash).unwrap();
        let exp_keyed = hex::decode(&case.keyed_hash).unwrap();
        let exp_derive = hex::decode(&case.derive_key).unwrap();
        assert_eq!(exp_hash.len(), OUT_LEN);

        // 1. plain hash, 32-byte digest
        let got = blake3::native_blake3(&input);
        assert_eq!(&got[..], &exp_hash[..32],
                   "hash-32 mismatch at input_len={}", case.input_len);

        // 2. plain hash, full XOF output
        let mut hasher = Blake3Hasher::new();
        hasher.update(&input);
        assert_eq!(hasher.finalize_len(OUT_LEN), exp_hash,
                   "XOF-131 mismatch at input_len={}", case.input_len);

        // 3. keyed hash, full output
        let mut keyed = Blake3Hasher::new_keyed(&key);
        keyed.update(&input);
        assert_eq!(keyed.finalize_len(OUT_LEN), exp_keyed,
                   "keyed mismatch at input_len={}", case.input_len);
        let got_keyed32 = blake3::native_blake3_keyed(&key, &input);
        assert_eq!(&got_keyed32[..], &exp_keyed[..32],
                   "keyed-32 one-shot mismatch at input_len={}", case.input_len);

        // 4. derive_key, full output
        let mut derive = Blake3Hasher::new_derive_key(&file.context_string);
        derive.update(&input);
        assert_eq!(derive.finalize_len(OUT_LEN), exp_derive,
                   "derive_key mismatch at input_len={}", case.input_len);
        let got_derive32 = blake3::native_blake3_derive_key(&file.context_string, &input);
        assert_eq!(&got_derive32[..], &exp_derive[..32],
                   "derive-32 one-shot mismatch at input_len={}", case.input_len);

        // Streaming split consistency (odd-sized update pieces).
        let mut streaming = Blake3Hasher::new();
        let mut off = 0usize;
        let mut piece = 1usize;
        while off < input.len() {
            let take = (piece % 97 + 1).min(input.len() - off);
            streaming.update(&input[off..off + take]);
            off += take;
            piece = piece * 3 + 1;
        }
        assert_eq!(streaming.finalize_len(OUT_LEN), exp_hash,
                   "streaming mismatch at input_len={}", case.input_len);
    }

    println!("BLAKE3: 35/35 official cases x {{hash, XOF-131, keyed, derive_key, streaming}}");
}

#[test]
fn blake3_kat_official_dispatching_paths() {
    let file = load_vectors();
    assert_eq!(file.cases.len(), 35, "expected the full official case set");
    let mut key = [0u8; 32];
    key.copy_from_slice(file.key.as_bytes());

    let inputs: Vec<Vec<u8>> = file.cases.iter().map(|c| make_input(c.input_len)).collect();
    let refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();

    // hash_many: every case in one call through the backend.
    let many = metamui_blake3::hash_many(&refs);
    let batched = batch::batch_hash(&refs).expect("35 messages");
    for (i, case) in file.cases.iter().enumerate() {
        let exp_hash = hex::decode(&case.hash).unwrap();
        let exp_keyed = hex::decode(&case.keyed_hash).unwrap();
        assert_eq!(many[i].as_bytes(), &exp_hash[..32],
                   "hash_many mismatch at input_len={}", case.input_len);
        assert_eq!(&batched[i].as_bytes()[..], &exp_hash[..32],
                   "batch_hash mismatch at input_len={}", case.input_len);
        assert_eq!(&parallel::hash(&inputs[i])[..], &exp_hash[..32],
                   "parallel::hash mismatch at input_len={}", case.input_len);
        assert_eq!(&parallel::hash_keyed(&inputs[i], &key)[..], &exp_keyed[..32],
                   "parallel::hash_keyed mismatch at input_len={}", case.input_len);
    }
    println!("BLAKE3: 35/35 official cases x {{hash_many, batch_hash, parallel, parallel keyed}} via backend `{}`",
             metamui_blake3::backend::backend().name);
}
