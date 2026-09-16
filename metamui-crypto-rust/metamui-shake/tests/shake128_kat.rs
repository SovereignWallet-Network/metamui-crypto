// KAT vectors for SHAKE-128 -- NIST FIPS 202
// Embedded byte-aligned vectors from FIPS 202 Appendix A
// (All NIST ACVP vectors are bit-oriented; these are the byte-aligned standard test cases.)

#[test]
fn shake128_kat_fips202() {
    // FIPS 202 Appendix A — SHAKE-128 byte-aligned vectors (output_len = 32 bytes)
    let vectors: &[(&[u8], &str)] = &[
        (
            b"",
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        ),
        (
            b"abc",
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "1a96182b50fb8c7e74e0a707788f55e98209b8d91fade8f32f8dd5cff7bf21f5",
        ),
    ];
    for (i, (msg, expected_hex)) in vectors.iter().enumerate() {
        let got = metamui_shake::shake128::shake128(msg, 32);
        let got_hex = hex::encode(&got);
        assert_eq!(
            got_hex, *expected_hex,
            "SHAKE-128 KAT failed at vector index {i}"
        );
    }
    println!("SHAKE-128: {} FIPS 202 KAT vectors passed", vectors.len());
    assert!(vectors.len() > 0, "No vectors tested — check for corrupted test vector data");
}
