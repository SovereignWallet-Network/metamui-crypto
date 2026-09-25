//! Poly1305 against the RFC 8439 vectors: `test-vectors/chacha20/rfc8439-vectors.json`,
//! section `poly1305_mac` (§2.5.2 and Appendix A.3), through the one-shot API, the
//! streaming hasher split at every block boundary, and the 26-bit-limb
//! implementation behind the `optimized` feature. PANICS (never skips) if the
//! vector file is missing.
use serde::Deserialize;
use std::fs;

use metamui_poly1305::{poly1305_mac, poly1305_verify, Poly1305, TAG_SIZE};

/// RFC 8439 gives the §2.5.2 and A.3 cases in two shapes: a 32-byte
/// `one_time_key` with a hex `message` (or `message_ascii`), or the key as
/// its `r` and `s` halves. Both are the same function.
#[derive(Deserialize)]
struct Raw {
    tc_id: u32,
    one_time_key: Option<String>,
    r: Option<String>,
    s: Option<String>,
    message: Option<String>,
    message_ascii: Option<String>,
    tag: String,
}

struct Case {
    tc_id: u32,
    key: Vec<u8>,
    msg: Vec<u8>,
    tag: Vec<u8>,
}

impl Raw {
    fn resolve(self) -> Case {
        let key = match (self.one_time_key, self.r, self.s) {
            (Some(k), _, _) => unhex(&k),
            (None, Some(r), Some(s)) => [unhex(&r), unhex(&s)].concat(),
            _ => panic!("tc_id={}: neither one_time_key nor r+s", self.tc_id),
        };
        let msg = match (self.message, self.message_ascii) {
            (Some(m), _) => unhex(&m),
            (None, Some(a)) => a.into_bytes(),
            _ => panic!("tc_id={}: no message", self.tc_id),
        };
        assert_eq!(key.len(), 32, "tc_id={}", self.tc_id);
        Case { tc_id: self.tc_id, key, msg, tag: unhex(&self.tag) }
    }
}

#[derive(Deserialize)]
struct Section {
    test_vectors: Vec<Raw>,
}

#[derive(Deserialize)]
struct File {
    poly1305_mac: Section,
}

fn cases() -> Vec<Case> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/chacha20/rfc8439-vectors.json"
    );
    let data = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("vector file missing ({path}): {e}"));
    let file: File = serde_json::from_str(&data).expect("malformed vector JSON");
    let cases: Vec<Case> = file.poly1305_mac.test_vectors.into_iter().map(Raw::resolve).collect();
    assert!(cases.len() >= 11, "expected the 11 RFC 8439 poly1305_mac cases, found {}", cases.len());
    cases
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("hex")
}

#[test]
fn one_shot_mac_and_verify() {
    for c in cases() {
        let (key, msg, expected) = (&c.key, &c.msg, &c.tag);
        assert_eq!(expected.len(), TAG_SIZE, "tc_id={}", c.tc_id);
        let tag = poly1305_mac(msg, key).unwrap();
        assert_eq!(tag.as_slice(), expected.as_slice(), "poly1305_mac tc_id={}", c.tc_id);
        assert!(poly1305_verify(msg, key, &tag).unwrap(), "verify tc_id={}", c.tc_id);
        let mut wrong = tag;
        wrong[0] ^= 1;
        assert!(!poly1305_verify(msg, key, &wrong).unwrap(), "a flipped tag verified, tc_id={}", c.tc_id);
    }
}

#[test]
fn streaming_split_at_every_block_boundary() {
    for c in cases() {
        let (key, msg, expected) = (&c.key, &c.msg, &c.tag);
        let splits: Vec<usize> = (0..=msg.len()).filter(|i| i % 16 == 0 || *i == msg.len()).collect();
        for &at in &splits {
            let mut p = Poly1305::new(key).unwrap();
            p.update(&msg[..at]).unwrap();
            p.update(&msg[at..]).unwrap();
            let tag = p.finalize().unwrap();
            assert_eq!(tag.as_slice(), expected.as_slice(), "streaming split at {at}, tc_id={}", c.tc_id);
        }
        // and one byte at a time
        let mut p = Poly1305::new(key).unwrap();
        for b in msg {
            p.update(core::slice::from_ref(b)).unwrap();
        }
        assert_eq!(p.finalize().unwrap().as_slice(), expected.as_slice(), "byte-wise, tc_id={}", c.tc_id);
    }
}

#[cfg(feature = "optimized")]
#[test]
fn limb_implementation_matches() {
    use metamui_poly1305::{poly1305_mac_optimized, Poly1305Optimized};
    for c in cases() {
        let (key, msg, expected) = (&c.key, &c.msg, &c.tag);
        let tag = poly1305_mac_optimized(msg, key).unwrap();
        assert_eq!(tag.as_slice(), expected.as_slice(), "poly1305_mac_optimized tc_id={}", c.tc_id);
        let mut p = Poly1305Optimized::new(key).unwrap();
        for chunk in msg.chunks(7) {
            p.update(chunk).unwrap();
        }
        assert_eq!(p.finalize().unwrap().as_slice(), expected.as_slice(), "Poly1305Optimized tc_id={}", c.tc_id);
    }
}
