// SHAKE-128 / SHAKE-256 NIST ACVP bit-oriented gate.
//
// Source: test-vectors/sha-3/shake128-acvp.json and
//         test-vectors/sha-3/shake256-acvp.json (NIST ACVP-Server gen-val
//         sample vectors, revision 1.0, AFT; `outLen` in bits).
//
// Every case is bit-oriented (len 1..5). The ACVP `msg` hex carries the
// trailing partial byte's valid bits TOP-aligned (positions 8-rem..7), read
// least-significant first; the crate's `hash_bits` takes the FIPS 202
// Appendix B.1 form (valid bits in the LOW positions), so the byte is
// shifted down by `8 - rem` first. This is the only convention reproducing
// all ten outputs (MSB-first reproduces only the len-1 and some len-4/5
// cases, plain LSB-first none).
//
// PANICS (never skips) if a file is missing; asserts exact counts.
use metamui_shake::{Shake128, Shake256};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct Case {
    #[serde(rename = "tcId")]
    tc_id: u32,
    msg: String,
    len: usize,
    #[serde(rename = "outLen")]
    out_len: usize,
    md: String,
}

#[derive(Deserialize)]
struct Group {
    tests: Vec<Case>,
}

#[derive(Deserialize)]
struct VectorFile {
    algorithm: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<Group>,
}

fn load(file: &str) -> VectorFile {
    let path = format!(
        "{}/../../test-vectors/sha-3/{}",
        env!("CARGO_MANIFEST_DIR"),
        file
    );
    let data = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("SHAKE ACVP vector file missing ({path}): {e}"));
    serde_json::from_str(&data).expect("malformed SHAKE ACVP JSON")
}

/// ACVP top-aligned partial byte -> FIPS 202 low-aligned partial byte.
fn acvp_to_fips_bits(msg_hex: &str, bit_len: usize) -> Vec<u8> {
    let mut bytes = hex::decode(msg_hex).expect("msg hex");
    let full = bit_len / 8;
    let rem = bit_len % 8;
    assert_eq!(bytes.len(), full + usize::from(rem > 0), "msg length disagrees with len");
    if rem > 0 {
        bytes[full] >>= 8 - rem;
    }
    bytes
}

fn run(file: &str, algorithm: &str, xof: fn(&[u8], usize, usize) -> Vec<u8>) -> usize {
    let vf = load(file);
    assert_eq!(vf.algorithm, algorithm, "{file}: unexpected algorithm header");
    let mut count = 0;
    for group in &vf.test_groups {
        for tv in &group.tests {
            assert_eq!(tv.out_len % 8, 0, "{file} tc {}: outLen must be whole bytes", tv.tc_id);
            let msg = acvp_to_fips_bits(&tv.msg, tv.len);
            let got = hex::encode(xof(&msg, tv.len, tv.out_len / 8));
            assert_eq!(got, tv.md.to_lowercase(), "{file} tc {} (len {})", tv.tc_id, tv.len);
            count += 1;
        }
    }
    println!("{algorithm} ACVP: {count} bit-oriented vectors passed");
    count
}

#[test]
fn shake128_acvp_bit_kat() {
    let n = run("shake128-acvp.json", "SHAKE-128", Shake128::hash_bits);
    assert_eq!(n, 5, "expected 5 SHAKE-128 ACVP vectors, got {n}");
}

#[test]
fn shake256_acvp_bit_kat() {
    let n = run("shake256-acvp.json", "SHAKE-256", Shake256::hash_bits);
    assert_eq!(n, 5, "expected 5 SHAKE-256 ACVP vectors, got {n}");
}

/// `hash_bits` with a whole-byte length must equal the byte API — the
/// bit path's padding collapses to the ordinary 0x1F ‖ 0* ‖ 0x80 when
/// `bits == 0`, including when the pad byte lands on a rate boundary.
#[test]
fn shake_hash_bits_byte_aligned_equals_byte_api() {
    let mut checked = 0;
    for len in [0usize, 1, 135, 136, 137, 167, 168, 169, 300] {
        let msg: Vec<u8> = (0..len).map(|i| (i * 53 + 7) as u8).collect();
        assert_eq!(Shake128::hash_bits(&msg, len * 8, 64), Shake128::hash(&msg, 64), "shake128 len {len}");
        assert_eq!(Shake256::hash_bits(&msg, len * 8, 64), Shake256::hash(&msg, 64), "shake256 len {len}");
        checked += 1;
    }
    assert_eq!(checked, 9);
}
