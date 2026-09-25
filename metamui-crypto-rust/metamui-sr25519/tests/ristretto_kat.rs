//! Ristretto255 encoding KAT — RFC 9496 Appendix A.
//!
//! These vectors are the small multiples of the basepoint:
//!     0·B, 1·B, 2·B, …, 15·B.
//! Any Ristretto255 implementation must reproduce them exactly.
//!
//! The test is kept **separate from** the compliance KAT
//! (`kat_schnorrkel.rs`) so that a regression in the encoder surfaces
//! at the lowest reasonable level before any Sr25519 signing path
//! runs.

use metamui_sr25519::native::ristretto::RistrettoPoint;

/// RFC 9496 Appendix A — encoding of k·B for k = 0..=15.
const APPENDIX_A_MULTIPLES: [&str; 16] = [
    // 0·B = identity
    "0000000000000000000000000000000000000000000000000000000000000000",
    // 1·B
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
    // 2·B
    "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
    // 3·B
    "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
    // 4·B
    "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
    // 5·B
    "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
    // 6·B
    "f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403",
    // 7·B
    "44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
    // 8·B
    "903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c",
    // 9·B
    "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
    // 10·B
    "20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f",
    // 11·B
    "bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
    // 12·B
    "e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460",
    // 13·B
    "aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
    // 14·B
    "46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e",
    // 15·B
    "e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
];

fn hex_decode_32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("valid hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

#[test]
fn rfc9496_appendix_a_basepoint_multiples_encode_correctly() {
    let b = RistrettoPoint::base_point();
    let identity = RistrettoPoint::identity();

    // k·B computed by repeated addition (not scalar_mul, to avoid
    // conflating bugs — this is the most direct possible check).
    let mut p = identity;
    for k in 0..=15usize {
        let expected = hex_decode_32(APPENDIX_A_MULTIPLES[k]);
        let got = p.compress();
        assert_eq!(
            got, expected,
            "Ristretto encoding mismatch at k={k}\n  expected: {}\n  got:      {}",
            APPENDIX_A_MULTIPLES[k],
            hex::encode(got)
        );

        // Round-trip: decode then re-encode must be stable.
        let redecoded = RistrettoPoint::decompress(&got)
            .unwrap_or_else(|| panic!("k={k}: decode failed for own encoding"));
        assert_eq!(
            redecoded.compress(),
            got,
            "k={k}: decode→encode round-trip drift"
        );

        p = p.add(&b);
    }
}

#[test]
fn rejects_non_canonical_encoding() {
    // s-value = p (the field prime). This is a non-canonical
    // representation of zero and must be rejected.
    //
    // p (little-endian) = ed ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
    //                     ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 7f
    let p_bytes: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ];
    assert!(
        RistrettoPoint::decompress(&p_bytes).is_none(),
        "non-canonical s=p must be rejected"
    );
}

#[test]
fn rejects_negative_s() {
    // s with low bit set → is_negative → reject.
    let mut bytes = hex_decode_32(APPENDIX_A_MULTIPLES[1]); // 1·B
    bytes[0] |= 0x01; // flip low bit
    assert!(
        RistrettoPoint::decompress(&bytes).is_none(),
        "negative s must be rejected"
    );
}
