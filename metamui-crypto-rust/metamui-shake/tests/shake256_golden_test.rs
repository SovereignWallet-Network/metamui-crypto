//! SHAKE-256 Comprehensive Golden Vector Tests
//!
//! Verifies the custom Rust Keccak-f[1600] / SHAKE-256 implementation against
//! golden vectors generated from Python hashlib.shake_256 (OpenSSL backend).
//!
//! Covers:
//!   - NIST FIPS 202 standard vectors (Group A)
//!   - Rate boundary tests (Group B)
//!   - XOF streaming correctness (Group C)
//!   - Falcon-specific nonce||message hashes (Group D)
//!
//! Copyright (c) 2025 Sovereign Wallet Co., Ltd. All Rights Reserved.

use metamui_shake::shake256::Shake256;
use std::fs;

/// Load the golden vectors JSON file. Panics (never skips) if missing so a
/// dropped/renamed vector file surfaces as a hard failure rather than a silent
/// no-op pass. Path is resolved relative to the crate manifest, matching the
/// `falcon/` copy the other bindings consume.
fn load_vectors_json() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/falcon/shake256_comprehensive.json"
    );
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Cannot read shake256_comprehensive.json ({path}): {e}"))
}

/// Decode a hex string to bytes.
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    if hex.is_empty() {
        return Vec::new();
    }
    hex::decode(hex).unwrap_or_else(|e| panic!("Invalid hex: {} ({})", &hex[..hex.len().min(20)], e))
}

/// Encode bytes to lowercase hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Simple JSON value extractor for string fields.
fn extract_string<'a>(json: &'a str, key: &str) -> &'a str {
    let pattern = format!("\"{}\"", key);
    let idx = json.find(&pattern).unwrap_or_else(|| panic!("Key '{}' not found", key));
    let after = &json[idx + pattern.len()..];
    let colon = after.find(':').unwrap();
    let after_colon = &after[colon + 1..];
    let quote_start = after_colon.find('"').unwrap();
    let value_start = &after_colon[quote_start + 1..];
    let quote_end = value_start.find('"').unwrap();
    &value_start[..quote_end]
}

/// Simple JSON value extractor for integer fields.
fn extract_int(json: &str, key: &str) -> usize {
    let pattern = format!("\"{}\"", key);
    let idx = json.find(&pattern).unwrap_or_else(|| panic!("Key '{}' not found", key));
    let after = &json[idx + pattern.len()..];
    let colon = after.find(':').unwrap();
    let value_str = after[colon + 1..].trim_start();
    let end = value_str.find(|c: char| !c.is_ascii_digit()).unwrap_or(value_str.len());
    value_str[..end].parse().unwrap()
}

/// Extract all basic vectors (Groups A, B) from a JSON group array.
fn extract_basic_vectors(json: &str, group_key: &str) -> Vec<(String, String, usize, String)> {
    let group_start = json.find(&format!("\"{}\"", group_key))
        .unwrap_or_else(|| panic!("Group '{}' not found", group_key));
    let array_start = json[group_start..].find('[').unwrap() + group_start;

    // Find matching ']' — count brackets
    let mut depth = 0;
    let mut array_end = array_start;
    for (i, c) in json[array_start..].char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    array_end = array_start + i;
                    break;
                }
            }
            _ => {}
        }
    }

    let array_content = &json[array_start + 1..array_end];
    let mut vectors = Vec::new();

    // Split on vector boundaries
    for block in array_content.split("\"id\":").skip(1) {
        let block = format!("\"id\":{}", block);
        let id = extract_string(&block, "id");
        let input_hex = extract_string(&block, "input_hex");
        let output_len = extract_int(&block, "output_len");
        let output_hex = extract_string(&block, "output_hex");
        vectors.push((id.to_string(), input_hex.to_string(), output_len, output_hex.to_string()));
    }
    vectors
}

// ==== Group A: NIST FIPS 202 Standard ====

#[test]
fn test_shake256_golden_group_a() {
    let json = load_vectors_json();
    let vectors = extract_basic_vectors(&json, "group_a_nist_fips202");
    assert!(!vectors.is_empty(), "Group A should have vectors");

    println!("Group A: {} NIST FIPS 202 vectors", vectors.len());

    for (id, input_hex, output_len, expected_hex) in &vectors {
        let input = hex_to_bytes(input_hex);
        let result = Shake256::hash(&input, *output_len);
        let got = bytes_to_hex(&result);
        assert_eq!(&got, expected_hex,
            "Vector {}: NIST FIPS 202 mismatch\n  got:  {}\n  want: {}",
            id, &got[..got.len().min(64)], &expected_hex[..expected_hex.len().min(64)]);
        println!("  {}: PASS", id);
    }
}

// ==== Group B: Rate Boundary Tests ====

#[test]
fn test_shake256_golden_group_b() {
    let json = load_vectors_json();
    let vectors = extract_basic_vectors(&json, "group_b_rate_boundary");
    assert!(!vectors.is_empty(), "Group B should have vectors");

    println!("Group B: {} rate boundary vectors", vectors.len());

    for (id, input_hex, output_len, expected_hex) in &vectors {
        let input = hex_to_bytes(input_hex);
        let result = Shake256::hash(&input, *output_len);
        let got = bytes_to_hex(&result);
        assert_eq!(&got, expected_hex, "Vector {}: rate boundary mismatch", id);
        println!("  {}: PASS", id);
    }
}

// ==== Group C: XOF Streaming ====

#[test]
fn test_shake256_golden_group_c1_prefix() {
    // C.1 input: "streaming test input"
    let input = hex_to_bytes("73747265616d696e67207465737420696e707574");

    let full_64 = Shake256::hash(&input, 64);
    let short_32 = Shake256::hash(&input, 32);
    assert_eq!(&full_64[..32], &short_32[..],
        "C.1: XOF prefix property violated — first 32 bytes of 64-byte output != 32-byte output");
    println!("  C.1: prefix property — PASS");
}

#[test]
fn test_shake256_golden_group_c2_incremental_squeeze() {
    let input = hex_to_bytes("73747265616d696e67207465737420696e707574");
    let expected = "8e9e6db6b5f582f17de2425f0ac78c7830e0ff7a4189bfab9aedddfaa4ebbcd4627d5ce9cdcdf493d3622d786e7cc7de2d6787f6d353ebcf98c73429a0e53879";

    // Full output
    let full = Shake256::hash(&input, 64);
    assert_eq!(bytes_to_hex(&full), expected, "C.2: full output mismatch");

    // Incremental 1-byte reads
    let mut shake = Shake256::new();
    shake.update(&input).unwrap();
    let mut reader = shake.finalize_xof();
    let mut incremental = Vec::new();
    for _ in 0..64 {
        let byte = reader.read(1);
        incremental.extend_from_slice(&byte);
    }
    assert_eq!(bytes_to_hex(&incremental), expected,
        "C.2: incremental 1-byte squeeze mismatch");
    println!("  C.2: incremental squeeze — PASS");
}

#[test]
fn test_shake256_golden_group_c3_incremental_absorb() {
    // absorb("abc") == absorb("a") + absorb("bc")
    let expected = "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739";

    let full = Shake256::hash(b"abc", 32);
    assert_eq!(bytes_to_hex(&full), expected, "C.3: full absorb mismatch");

    // Incremental absorb
    let mut shake = Shake256::new();
    shake.update(b"a").unwrap();
    shake.update(b"bc").unwrap();
    let mut reader = shake.finalize_xof();
    let inc = reader.read(32);
    assert_eq!(bytes_to_hex(&inc), expected, "C.3: incremental absorb mismatch");
    println!("  C.3: incremental absorb — PASS");
}

#[test]
fn test_shake256_golden_group_c4_squeeze_boundary() {
    let input = hex_to_bytes("626f756e646172792074657374"); // "boundary test"
    let expected = "830d691e6cccc6955b07899074099aba3438c8b4c38dd842e945fa777db6e93ee8534525e0bf3328677b84498143f1877ae1f3aee35c29db24a48e176e69afbd37d0f75c7bc60324afaf1b220ddcc4801c4c6b5c3e89a13b5d85f8952bd1a0c5be209b1dcb1a969c242db736a216fa9a65fe6fcd210477b541bd29579bf1ae4a168dbce7b72b480bb1b6a4bd";

    let result = Shake256::hash(&input, 140);
    assert_eq!(bytes_to_hex(&result), expected,
        "C.4: squeeze boundary output mismatch");
    println!("  C.4: squeeze boundary — PASS");
}

// ==== Group D: Falcon-Specific ====

#[test]
fn test_shake256_golden_group_d() {
    let json = load_vectors_json();

    let group_start = json.find("\"group_d_falcon_specific\"")
        .expect("group_d_falcon_specific not found");
    let array_start = json[group_start..].find('[').unwrap() + group_start;

    let mut depth = 0;
    let mut array_end = array_start;
    for (i, c) in json[array_start..].char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 { array_end = array_start + i; break; }
            }
            _ => {}
        }
    }

    let array_content = &json[array_start + 1..array_end];
    let mut count = 0;

    for block in array_content.split("\"id\":").skip(1) {
        let block = format!("\"id\":{}", block);
        let id = extract_string(&block, "id");
        let nonce_hex = extract_string(&block, "nonce_hex");
        let message_hex = extract_string(&block, "message_hex");
        let output_len = extract_int(&block, "output_len");
        let output_hex = extract_string(&block, "output_hex");

        let nonce = hex_to_bytes(nonce_hex);
        let message = hex_to_bytes(message_hex);

        // Concatenate nonce || message
        let mut input = nonce;
        input.extend_from_slice(&message);

        let result = Shake256::hash(&input, output_len);
        let got = bytes_to_hex(&result);
        assert_eq!(got, output_hex,
            "Vector {}: Falcon-specific mismatch (first 64)\n  got:  {}\n  want: {}",
            id, &got[..64], &output_hex[..64]);
        println!("  {}: PASS", id);
        count += 1;
    }
    assert!(count >= 4, "Should have at least 4 Falcon-specific vectors, found {}", count);
    println!("Group D: {}/{} Falcon-specific vectors passed", count, count);
}
