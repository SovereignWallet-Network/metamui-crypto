// SHA3-256 / SHA3-512 NIST ACVP bit-oriented gate.
//
// Source: test-vectors/sha-3/sha3-256-acvp.json and
//         test-vectors/sha-3/sha3-512-acvp.json (NIST ACVP-Server
//         gen-val sample vectors, revision 2.0, AFT).
//
// Every case is bit-oriented (`len % 8 != 0` for all but one). The ACVP
// `msg` field is a hex string in which whole bytes are ordinary Keccak
// input bytes and the trailing partial byte carries its `len % 8` valid
// bits TOP-aligned (bit positions 8-rem..7), read least-significant first.
// The crate's `hash_bits` takes the FIPS 202 Appendix B.1 form instead —
// valid bits in the LOW positions — so the partial byte is shifted down by
// `8 - rem` before hashing. The empirical proof of this reading is that it
// is the only convention reproducing all 9 digests; MSB-first and
// plain LSB-first each reproduce a subset.
//
// A bit-level reference (bit vector -> pad10*1 -> Keccak-f) also checks
// `hash_bits` at rate boundaries the ACVP samples do not reach.
//
// PANICS (never skips) if a file is missing; asserts exact counts.
use metamui_sha3::keccak::keccak_f;
use metamui_sha3::{Sha3_256, Sha3_512};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct Case {
    #[serde(rename = "tcId")]
    tc_id: u32,
    msg: String,
    len: usize,
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
        .unwrap_or_else(|e| panic!("SHA-3 ACVP vector file missing ({path}): {e}"));
    serde_json::from_str(&data).expect("malformed SHA-3 ACVP JSON")
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

fn run(file: &str, algorithm: &str, hash: fn(&[u8], usize) -> Vec<u8>) -> usize {
    let vf = load(file);
    assert_eq!(vf.algorithm, algorithm, "{file}: unexpected algorithm header");
    let mut count = 0;
    let mut sub_byte = 0;
    for group in &vf.test_groups {
        for tv in &group.tests {
            let msg = acvp_to_fips_bits(&tv.msg, tv.len);
            let got = hex::encode(hash(&msg, tv.len));
            assert_eq!(got, tv.md.to_lowercase(), "{file} tc {} (len {})", tv.tc_id, tv.len);
            count += 1;
            if tv.len % 8 != 0 {
                sub_byte += 1;
            }
        }
    }
    println!("{algorithm} ACVP: {count} vectors passed ({sub_byte} bit-oriented)");
    count
}

#[test]
fn sha3_256_acvp_bit_kat() {
    let n = run("sha3-256-acvp.json", "SHA3-256", |m, bits| {
        Sha3_256::hash_bits(m, bits).to_vec()
    });
    assert_eq!(n, 5, "expected 5 SHA3-256 ACVP vectors, got {n}");
}

#[test]
fn sha3_512_acvp_bit_kat() {
    let n = run("sha3-512-acvp.json", "SHA3-512", |m, bits| {
        Sha3_512::hash_bits(m, bits).to_vec()
    });
    assert_eq!(n, 4, "expected 4 SHA3-512 ACVP vectors, got {n}");
}

// ------------------------------------------------------------ reference

/// Bit-level SHA-3 reference: message bits (FIPS 202 order) ‖ 01 ‖ pad10*1,
/// absorbed `rate` bytes at a time, one squeeze.
fn reference_sha3(msg: &[u8], bit_len: usize, rate: usize, out_len: usize) -> Vec<u8> {
    let mut bits: Vec<u8> = (0..bit_len).map(|i| (msg[i / 8] >> (i % 8)) & 1).collect();
    bits.extend_from_slice(&[0, 1]); // SHA-3 domain suffix
    bits.push(1); // pad10*1 leading 1
    while bits.len() % (rate * 8) != rate * 8 - 1 {
        bits.push(0);
    }
    bits.push(1); // pad10*1 closing 1
    let mut data = vec![0u8; bits.len() / 8];
    for (i, b) in bits.iter().enumerate() {
        data[i / 8] |= b << (i % 8);
    }
    let mut state = [0u64; 25];
    for block in data.chunks_exact(rate) {
        for (i, word) in block.chunks_exact(8).enumerate() {
            state[i] ^= u64::from_le_bytes(word.try_into().unwrap());
        }
        keccak_f(&mut state);
    }
    let mut out = Vec::with_capacity(out_len);
    for w in state.iter() {
        out.extend_from_slice(&w.to_le_bytes());
        if out.len() >= out_len {
            break;
        }
    }
    out.truncate(out_len);
    out
}

/// Every partial-byte length at every rate-boundary position (the leading
/// pad bit landing exactly on the last bit of a block, or one byte before,
/// or spilling into the next byte) must agree with the reference.
#[test]
fn sha3_hash_bits_matches_bit_level_reference_at_rate_boundaries() {
    let mut checked = 0;
    for (rate, out_len) in [(Sha3_256::RATE, 32usize), (Sha3_512::RATE, 64usize)] {
        for full_bytes in [0usize, 1, rate - 2, rate - 1, rate, rate + 1, 2 * rate - 1] {
            for rem in 0..8usize {
                let bit_len = full_bytes * 8 + rem;
                let msg: Vec<u8> = (0..full_bytes + 1).map(|i| (i * 37 + 11) as u8).collect();
                let want = reference_sha3(&msg, bit_len, rate, out_len);
                let got = if out_len == 32 {
                    Sha3_256::hash_bits(&msg, bit_len).to_vec()
                } else {
                    Sha3_512::hash_bits(&msg, bit_len).to_vec()
                };
                assert_eq!(got, want, "rate {rate}: full_bytes {full_bytes} rem {rem}");
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 2 * 7 * 8);
}
