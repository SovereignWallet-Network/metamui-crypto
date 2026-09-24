//! Cross-verification tests for `metamui_smaug_t::pack_ring`
//! against the upstream SMAUG-T v1.1.1 C reference implementation.
//!
//! Fixtures captured 2026-05-22 from the v1.1.1 reference
//! (`cryptoLabInc/SMAUG-T @ v1.1.1`, built with `-DSMAUGT_CONFIG_MODE`
//! for each of `SMAUGT_MODE{1,3,5,T}`) live in
//! `test-vectors/smaug-t/v1.1.1-packring/`.
//!
//! Each fixture file follows the `key=hex` format used by the level-6
//! ground-truth fixtures elsewhere in the audit. For each q value
//! exercised by the mode, we record:
//!
//!   - the input polynomial (256 i16 coefficients as little-endian
//!     hex, 1024 chars)
//!   - the packed output bytes
//!   - the round-tripped polynomial (after unpack)
//!
//! The Rust port must reproduce the packed bytes byte-for-byte and
//! must round-trip the polynomial to the same coefficient set the C
//! reference recovers (which may differ from the input due to bit
//! masking — e.g., `pack_R2_3` keeps only 3 bits per coefficient).

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use metamui_smaug_t::smaug_v1_2_0::pack_ring::{
    pack_r2_10, pack_r2_11, pack_r2_3, pack_r2_4, pack_r2_5, pack_r2_7, pack_r2_8, pack_r2_9,
    unpack_r2_10, unpack_r2_11, unpack_r2_3, unpack_r2_4, unpack_r2_5, unpack_r2_7, unpack_r2_8,
    unpack_r2_9,
};
use metamui_smaug_t::smaug_v1_2_0::poly_types::Poly;

const LWE_N: usize = 256;

fn fixtures_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.join("test-vectors/smaug-t/v1.1.1-packring")
}

fn load_fixture(filename: &str) -> HashMap<String, String> {
    let path = fixtures_root().join(filename);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("could not read fixture {}: {}", path.display(), e)
    });
    let mut map = HashMap::new();
    for line in raw.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

fn poly_from_hex(hex: &str) -> Poly {
    assert_eq!(hex.len(), LWE_N * 4, "poly hex must be 4 chars per coeff x256");
    let mut p = Poly { coeffs: [0i16; LWE_N] };
    for i in 0..LWE_N {
        let lo = u8::from_str_radix(&hex[i * 4..i * 4 + 2], 16).unwrap();
        let hi = u8::from_str_radix(&hex[i * 4 + 2..i * 4 + 4], 16).unwrap();
        p.coeffs[i] = ((lo as u16) | ((hi as u16) << 8)) as i16;
    }
    p
}

fn poly_to_hex(p: &Poly) -> String {
    let mut s = String::with_capacity(LWE_N * 4);
    for &c in &p.coeffs {
        let u = c as u16;
        s.push_str(&format!("{:02x}{:02x}", u & 0xff, (u >> 8) & 0xff));
    }
    s
}

fn bytes_to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// Generic per-mode harness: for each q-value in the fixture, decode
/// the input polynomial, run our pack, compare against the fixture's
/// packed bytes, then run our unpack and compare against the round-trip
/// polynomial recorded in the fixture.
fn check_pack_unpack<PackFn, UnpackFn>(
    fixture: &HashMap<String, String>,
    label: &str,
    pack_fn: PackFn,
    unpack_fn: UnpackFn,
    out_len: usize,
    seed_label: &str,
) where
    PackFn: Fn(&mut [u8], &Poly),
    UnpackFn: Fn(&mut Poly, &[u8]),
{
    let input_key = format!("{}_input{}_seed_{}", label, "", seed_label).replace("R2_", "R2_");
    // Some labels use "_aligned" suffix between "input" and "seed"
    let input_key_aligned = format!("{}_input_aligned_seed_{}", label, seed_label);
    let input_hex = fixture
        .get(&input_key)
        .or_else(|| fixture.get(&input_key_aligned))
        .unwrap_or_else(|| panic!("fixture missing input for {} (tried {} and {})",
            label, input_key, input_key_aligned));

    let p = poly_from_hex(input_hex);

    // Pack
    let mut packed = vec![0u8; out_len];
    pack_fn(&mut packed, &p);
    let packed_hex = bytes_to_hex(&packed);

    // The packed key may be plain or "_from_aligned"
    let pk_key = format!("{}_packed", label);
    let pk_key_aligned = format!("{}_packed_from_aligned", label);
    let want_packed = fixture
        .get(&pk_key)
        .or_else(|| fixture.get(&pk_key_aligned))
        .unwrap_or_else(|| panic!("fixture missing packed bytes for {}", label));
    assert_eq!(
        &packed_hex, want_packed,
        "{}: packed bytes diverged from C reference",
        label
    );

    // Round-trip via our unpack
    let mut rt = Poly { coeffs: [0i16; LWE_N] };
    unpack_fn(&mut rt, &packed);
    let rt_hex = poly_to_hex(&rt);

    let rt_key = format!("{}_unpacked_roundtrip", label);
    let want_rt = fixture
        .get(&rt_key)
        .unwrap_or_else(|| panic!("fixture missing round-trip for {}", label));
    assert_eq!(
        &rt_hex, want_rt,
        "{}: round-trip diverged from C reference",
        label
    );
}

#[test]
fn pack_ring_mode1_byte_equal_to_c_ref() {
    // mode1: K=2, LOG_Q=10, LOG_P=8, LOG_P_PRIME=5
    let f = load_fixture("mode1.txt");
    check_pack_unpack(&f, "R2_10", pack_r2_10, unpack_r2_10, 320, "A1B2C3D4");
    check_pack_unpack(&f, "R2_8", pack_r2_8, unpack_r2_8, 256, "12345678");
    check_pack_unpack(&f, "R2_5", pack_r2_5, unpack_r2_5, 160, "DEADBEEF");
}

#[test]
fn pack_ring_mode3_byte_equal_to_c_ref() {
    // mode3: K=3, LOG_Q=11, LOG_P=9, LOG_P_PRIME=4
    let f = load_fixture("mode3.txt");
    check_pack_unpack(&f, "R2_11", pack_r2_11, unpack_r2_11, 352, "A1B2C3D4");
    check_pack_unpack(&f, "R2_9", pack_r2_9, unpack_r2_9, 288, "12345678");
    check_pack_unpack(&f, "R2_4", pack_r2_4, unpack_r2_4, 128, "DEADBEEF");
}

#[test]
fn pack_ring_mode5_byte_equal_to_c_ref() {
    // mode5: K=4, LOG_Q=11, LOG_P=9, LOG_P_PRIME=7
    let f = load_fixture("mode5.txt");
    check_pack_unpack(&f, "R2_11", pack_r2_11, unpack_r2_11, 352, "A1B2C3D4");
    check_pack_unpack(&f, "R2_9", pack_r2_9, unpack_r2_9, 288, "12345678");
    check_pack_unpack(&f, "R2_7", pack_r2_7, unpack_r2_7, 224, "DEADBEEF");
}

#[test]
fn pack_ring_modet_byte_equal_to_c_ref() {
    // modet (TiMER): K=2, LOG_Q=10, LOG_P=8, LOG_P_PRIME=3
    let f = load_fixture("modet.txt");
    check_pack_unpack(&f, "R2_10", pack_r2_10, unpack_r2_10, 320, "A1B2C3D4");
    check_pack_unpack(&f, "R2_8", pack_r2_8, unpack_r2_8, 256, "12345678");
    check_pack_unpack(&f, "R2_3", pack_r2_3, unpack_r2_3, 96, "DEADBEEF");
}
