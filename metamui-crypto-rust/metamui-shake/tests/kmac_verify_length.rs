//! KMAC verify takes the MAC length from the caller, not from the tag.
//!
//! `verify` used to compute KMAC with L = 8·|expected|, so the empty tag
//! verified for every key and message, and a 1-byte tag was a 2⁻⁸ guess.
//! The first test is that forgery; it passed before the fix.

use metamui_shake::{Kmac128, Kmac256, KMAC_MIN_TAG_BYTES};

const KEY: [u8; 32] = [0x40; 32];

#[test]
fn empty_and_short_tags_no_longer_verify() {
    let msg = b"any message at all";
    assert!(!Kmac128::verify(&KEY, msg, b"", &[], 32));
    assert!(!Kmac256::verify(&KEY, msg, b"", &[], 64));

    // A genuine tag truncated to one byte, or recomputed at L = 8, is not a
    // 32-byte tag.
    let one = Kmac128::mac(&KEY, msg, 1, b"");
    assert!(!Kmac128::verify(&KEY, msg, b"", &one, 32));
    let full = Kmac128::mac(&KEY, msg, 32, b"");
    assert!(!Kmac128::verify(&KEY, msg, b"", &full[..1], 32));
}

#[test]
fn tag_of_the_stated_length_verifies_and_others_do_not() {
    let msg = b"m";
    for len in [KMAC_MIN_TAG_BYTES, 16, 32, 64] {
        let tag = Kmac256::mac(&KEY, msg, len, b"S");
        assert!(Kmac256::verify(&KEY, msg, b"S", &tag, len), "len {len}");
        // Same tag, other stated length: the length is bound into KMAC.
        assert!(!Kmac256::verify(&KEY, msg, b"S", &tag, len + 1), "len {len}+1");
        let mut bad = tag.clone();
        bad[len - 1] ^= 1;
        assert!(!Kmac256::verify(&KEY, msg, b"S", &bad, len), "tampered, len {len}");
    }
}

#[test]
#[should_panic(expected = "below the SP 800-185 minimum")]
fn a_mac_length_under_32_bits_is_refused() {
    let tag = Kmac128::mac(&KEY, b"m", 3, b"");
    Kmac128::verify(&KEY, b"m", b"", &tag, 3);
}

#[test]
#[should_panic(expected = "below the SP 800-185 minimum")]
fn a_zero_mac_length_is_refused() {
    Kmac128::verify(&KEY, b"m", b"", &[], 0);
}
