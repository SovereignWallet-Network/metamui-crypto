//! Genuine-upstream gate for cSHAKE128/256 and KMAC128/256 (NIST SP 800-185)
//! against the NIST ACVP cSHAKE-128/-256 1.0 and KMAC-128/-256 1.0 vector
//! sets vendored under `test-vectors/sp800-185/` by
//! `tools/classical-vectors-gen/acvp_sp800185_to_json.py`.
//!
//! Every AFT record is replayed bit-exactly (messages, keys and outputs are
//! mostly NOT byte-aligned in these sets); every KMAC MVT record is checked
//! with `verify` and must agree with ACVP's `testPassed`. A missing file
//! FAILS the test — the vectors are tracked in this repository.

use metamui_shake::{Cshake128, Cshake256, Kmac128, Kmac256};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize)]
struct File {
    algorithm: String,
    total_tests: usize,
    test_groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Group {
    test_type: String,
    #[serde(default)]
    xof: bool,
    tests: Vec<Test>,
}

#[derive(Deserialize)]
struct Test {
    tc_id: u32,
    customization_hex: String,
    #[serde(default)]
    function_name_hex: String,
    msg: String,
    msg_bits: usize,
    #[serde(default)]
    out_bits: usize,
    #[serde(default)]
    md: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    key_bits: usize,
    #[serde(default)]
    mac: String,
    #[serde(default)]
    mac_bits: usize,
    #[serde(default)]
    test_passed: Option<bool>,
}

fn load(name: &str) -> File {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "test-vectors", "sp800-185", name].iter().collect();
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("ACVP vector file missing: {} ({e})", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// ACVP writes a partial byte top-aligned (valid bits in the HIGH positions);
/// FIPS 202 `h2b` wants them low. Same adapter as the SHA-3/SHAKE ACVP gates.
fn acvp_to_h2b(mut bytes: Vec<u8>, bits: usize) -> Vec<u8> {
    let rem = bits % 8;
    if rem != 0 {
        let last = bits / 8;
        bytes[last] >>= 8 - rem;
    }
    bytes.truncate(bits.div_ceil(8));
    bytes
}

/// The inverse for outputs: the sponge's low-aligned final bits, moved to the
/// high positions ACVP prints them in.
fn h2b_to_acvp(mut bytes: Vec<u8>, bits: usize) -> Vec<u8> {
    let rem = bits % 8;
    if rem != 0 {
        let last = bytes.len() - 1;
        bytes[last] <<= 8 - rem;
    }
    bytes
}

fn cshake_gate(name: &str, f: fn(&[u8], usize, usize, &[u8], &[u8]) -> Vec<u8>) {
    let file = load(name);
    let mut n = 0;
    for g in &file.test_groups {
        assert_eq!(g.test_type, "AFT");
        for t in &g.tests {
            let msg = acvp_to_h2b(hex(&t.msg), t.msg_bits);
            let got = h2b_to_acvp(f(&msg, t.msg_bits, t.out_bits, &hex(&t.function_name_hex), &hex(&t.customization_hex)), t.out_bits);
            assert_eq!(
                got,
                hex(&t.md),
                "{} tcId {} (msg {} bits, out {} bits, N {:?}, S {} B)",
                file.algorithm, t.tc_id, t.msg_bits, t.out_bits, t.function_name_hex, t.customization_hex.len() / 2
            );
            n += 1;
        }
    }
    assert_eq!(n, file.total_tests);
    assert!(n >= 100, "{}: expected the 100-record AFT group, got {n}", file.algorithm);
    println!("{}: {n}/{n} ACVP AFT records bit-exact", file.algorithm);
}

#[test]
fn cshake128_acvp() {
    cshake_gate("cshake128-acvp.json", Cshake128::hash_bits);
}

#[test]
fn cshake256_acvp() {
    cshake_gate("cshake256-acvp.json", Cshake256::hash_bits);
}

fn kmac_gate<const RATE: usize>(name: &str) {
    let file = load(name);
    let (mut aft, mut mvt, mut rejected) = (0, 0, 0);
    for g in &file.test_groups {
        for t in &g.tests {
            // Keys are MSB-first bit strings (no adapter, see Kmac::new_bits);
            // messages follow the h2b rule like every other ACVP SHA-3 input.
            let key = hex(&t.key);
            let msg = acvp_to_h2b(hex(&t.msg), t.msg_bits);
            let cust = hex(&t.customization_hex);
            let mut k = metamui_shake::kmac::Kmac::<RATE>::new_bits(&key, t.key_bits, &cust);
            k.update_bits(&msg, t.msg_bits);
            let got = if g.xof { k.finalize_xof().read_bits(t.mac_bits) } else { k.finalize_bits(t.mac_bits) };
            let got = h2b_to_acvp(got, t.mac_bits);
            let expected = hex(&t.mac);
            match g.test_type.as_str() {
                "AFT" => {
                    assert_eq!(
                        got, expected,
                        "{} tcId {} (key {} bits, msg {} bits, mac {} bits, xof {})",
                        file.algorithm, t.tc_id, t.key_bits, t.msg_bits, t.mac_bits, g.xof
                    );
                    aft += 1;
                }
                "MVT" => {
                    let want = t.test_passed.expect("MVT record without test_passed");
                    assert_eq!(
                        got == expected,
                        want,
                        "{} tcId {}: verification verdict differs from ACVP",
                        file.algorithm, t.tc_id
                    );
                    if !want {
                        rejected += 1;
                    }
                    mvt += 1;
                }
                other => panic!("unexpected test type {other}"),
            }
        }
    }
    assert_eq!(aft + mvt, file.total_tests);
    assert!(aft >= 400 && mvt >= 400, "{}: expected 4 AFT + 4 MVT groups of 100, got {aft}/{mvt}", file.algorithm);
    assert!(rejected > 0, "MVT groups must contain tampered tags");
    println!("{}: {aft} AFT bit-exact, {mvt} MVT verdicts agree ({rejected} tampered rejected)", file.algorithm);
}

#[test]
fn kmac128_acvp() {
    kmac_gate::<168>("kmac128-acvp.json");
}

#[test]
fn kmac256_acvp() {
    kmac_gate::<136>("kmac256-acvp.json");
}

/// The SP 800-185 §A sample values, the ones every implementer checks first.
#[test]
fn sp800_185_published_samples() {
    let key: Vec<u8> = (0x40u8..=0x5F).collect();
    let data4 = [0x00u8, 0x01, 0x02, 0x03];
    // KMAC128 sample #1: S = "", L = 256.
    assert_eq!(
        hex::encode_upper(Kmac128::mac(&key, &data4, 32, b"")),
        "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E"
    );
    // KMAC128 sample #2: S = "My Tagged Application".
    assert_eq!(
        hex::encode_upper(Kmac128::mac(&key, &data4, 32, b"My Tagged Application")),
        "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5"
    );
    // KMAC256 sample #4: L = 512, S = "My Tagged Application".
    assert_eq!(
        hex::encode_upper(Kmac256::mac(&key, &data4, 64, b"My Tagged Application")),
        "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"
    );
    // cSHAKE128 sample #1: N = "", S = "Email Signature", L = 256.
    assert_eq!(
        hex::encode_upper(Cshake128::hash(&data4, 32, b"", b"Email Signature")),
        "C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5"
    );
    // cSHAKE256 sample #3: L = 512.
    assert_eq!(
        hex::encode_upper(Cshake256::hash(&data4, 64, b"", b"Email Signature")),
        "D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD164020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C"
    );
}
