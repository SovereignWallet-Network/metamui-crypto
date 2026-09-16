// KAT vectors for SHAKE-256 -- NIST FIPS 202
// Embedded byte-aligned vectors from FIPS 202 Appendix A
// (All NIST ACVP vectors are bit-oriented; these are the byte-aligned standard test cases.)

use metamui_shake::Shake256;

#[test]
fn shake256_kat_fips202() {
    // FIPS 202 Appendix A — SHAKE-256 byte-aligned vectors (output_len = 32 bytes)
    let vectors: &[(&[u8], &str)] = &[
        (
            b"",
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
        ),
        (
            b"abc",
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e3329",
        ),
    ];
    for (i, (msg, expected_hex)) in vectors.iter().enumerate() {
        let got = Shake256::hash(msg, 32);
        let got_hex = hex::encode(&got);
        assert_eq!(
            got_hex, *expected_hex,
            "SHAKE-256 KAT failed at vector index {i}"
        );
    }
    println!("SHAKE-256: {} FIPS 202 KAT vectors passed", vectors.len());
    assert!(vectors.len() > 0, "No vectors tested — check for corrupted test vector data");
}
