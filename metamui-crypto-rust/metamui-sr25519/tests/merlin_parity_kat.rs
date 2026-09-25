//! Merlin transcript byte-for-byte parity with the reference
//! `merlin` 3.0.0 crate. Any drift here cascades into
//! `kat_schnorrkel.rs` Axes B/C — fail this test first before
//! debugging those.
//!
//! The parity surface tested:
//!   1. `new(label)` initialization (must begin with STROBE-128
//!      `"Merlin v1.0"` + `append_message("dom-sep", label)`).
//!   2. `append_message(label, message)` — `meta-ad(label) ||
//!      meta-ad(LE32(len(message)), more=true) || ad(message)`.
//!   3. `challenge_bytes(label, dest)` — `meta-ad(label) ||
//!      meta-ad(LE32(len(dest)), more=true) || prf(dest)`.
//!
//! Each test case clones both transcripts through the exact same
//! script and compares the final challenge bytes.

use merlin::Transcript as RefTranscript;
use metamui_sr25519::merlin::MerlinTranscript as OurTranscript;

/// Fixed scripts that stress label/message length boundaries.
fn scripts() -> Vec<(&'static str, &'static [u8], Vec<(&'static [u8], Vec<u8>)>, &'static [u8], usize)> {
    vec![
        (
            "empty-then-challenge",
            b"test-proto",
            vec![],
            b"c",
            32,
        ),
        (
            "short label + short message",
            b"SigningContext",
            vec![(b"", b"substrate".to_vec()), (b"sign-bytes", b"hello".to_vec())],
            b"sign:c",
            64,
        ),
        (
            "message larger than STROBE rate (166 bytes)",
            b"SigningContext",
            vec![
                (b"", b"substrate".to_vec()),
                (b"sign-bytes", vec![0xaau8; 200]), // > rate R=166
            ],
            b"sign:c",
            64,
        ),
        (
            "message much larger than rate (1024 bytes)",
            b"SigningContext",
            vec![
                (b"", b"substrate".to_vec()),
                (b"sign-bytes", vec![0xcc; 1024]),
            ],
            b"sign:c",
            64,
        ),
        (
            "multiple messages + 32-byte challenge",
            b"SchnorrRistrettoHDKD",
            vec![
                (b"sign-bytes", b"".to_vec()),
                (b"chain-code", vec![0u8; 32]),
                (b"secret-key", vec![1u8; 32]),
            ],
            b"HDKD-hard",
            32,
        ),
        (
            "challenge request larger than rate",
            b"SigningContext",
            vec![(b"", b"substrate".to_vec()), (b"sign-bytes", b"x".to_vec())],
            b"sign:c",
            200, // > rate R=166
        ),
    ]
}

#[test]
fn our_merlin_matches_reference_byte_for_byte() {
    for (name, proto_label, messages, challenge_label, challenge_len) in scripts() {
        // Reference transcript. merlin 3.0.0 requires `&'static [u8]`
        // labels, which is fine for our fixed test inputs.
        let mut reference = RefTranscript::new(proto_label);
        let mut ours = OurTranscript::new(proto_label);

        for (label, msg) in &messages {
            reference.append_message(label, msg);
            ours.append_message(label, msg);
        }

        let mut ref_bytes = vec![0u8; challenge_len];
        let mut our_bytes = vec![0u8; challenge_len];
        reference.challenge_bytes(challenge_label, &mut ref_bytes);
        ours.challenge_bytes(challenge_label, &mut our_bytes);

        assert_eq!(
            our_bytes, ref_bytes,
            "\nscript '{}' diverged from reference Merlin\n  reference: {}\n  ours:      {}\n  (challenge_label={:?}, len={})",
            name,
            hex::encode(&ref_bytes),
            hex::encode(&our_bytes),
            core::str::from_utf8(challenge_label).unwrap_or("<bin>"),
            challenge_len,
        );
    }
}
