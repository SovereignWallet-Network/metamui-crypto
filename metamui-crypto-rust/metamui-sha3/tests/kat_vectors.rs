// KAT vectors for SHA3-256 and SHA3-512 -- NIST FIPS 202
// Embedded byte-aligned vectors from FIPS 202 Appendix B
// (All NIST ACVP vectors are bit-oriented; these are the byte-aligned standard test cases.)

#[test]
fn sha3_256_kat_fips202() {
    // FIPS 202 Appendix B.1 — SHA3-256 byte-aligned vectors
    let vectors: &[(&[u8], &str)] = &[
        (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
        ),
    ];
    for (i, (msg, expected_hex)) in vectors.iter().enumerate() {
        let got = metamui_sha3::sha3_256(msg);
        let got_hex = hex::encode(got);
        assert_eq!(
            got_hex, *expected_hex,
            "SHA3-256 KAT failed at vector index {i}"
        );
    }
    println!("SHA3-256: {} FIPS 202 KAT vectors passed", vectors.len());
    assert!(vectors.len() > 0, "No vectors tested — check for corrupted test vector data");
}

#[test]
fn sha3_512_kat_fips202() {
    // FIPS 202 Appendix B.2 — SHA3-512 byte-aligned vectors
    let vectors: &[(&[u8], &str)] = &[
        (
            b"",
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        ),
        (
            b"abc",
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
        ),
    ];
    for (i, (msg, expected_hex)) in vectors.iter().enumerate() {
        let got = metamui_sha3::sha3_512(msg);
        let got_hex = hex::encode(got);
        assert_eq!(
            got_hex, *expected_hex,
            "SHA3-512 KAT failed at vector index {i}"
        );
    }
    println!("SHA3-512: {} FIPS 202 KAT vectors passed", vectors.len());
    assert!(vectors.len() > 0, "No vectors tested — check for corrupted test vector data");
}
