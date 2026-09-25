//! Genuine-upstream gate for every NIST SP 800-232 function in this crate.
//!
//! Replays, in full, the four LWC KAT files the Ascon authors ship with their
//! reference implementation, vendored unmodified under
//! `test-vectors/ascon-upstream/` by `tools/ascon-upstream-gen/genrun.sh`
//! (which rebuilds the reference's own genkat and refuses to vendor unless the
//! output is byte-identical to the shipped file). A missing file is a broken
//! checkout, not a skip: the test FAILS.
//!
//! Beyond the one-shot answers, the streaming APIs are exercised on every
//! record by splitting the input at a moving offset and the XOF output at a
//! moving offset, so a buffering bug at any block boundary is caught by the
//! same oracle.

use metamui_ascon::{AsconAead, AsconAead128, AsconCxof128, AsconHash256, AsconXof128};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

fn oracle(rel: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "test-vectors", "ascon-upstream", rel]
        .iter()
        .collect();
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "genuine-upstream oracle missing: {} ({e}); run tools/ascon-upstream-gen/genrun.sh",
            path.display()
        )
    })
}

/// Parse an LWC KAT file into records of `field -> bytes`.
fn records(text: &str) -> Vec<BTreeMap<String, Vec<u8>>> {
    let mut out = Vec::new();
    let mut cur: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let (k, v) = line.split_once('=').expect("KAT line without '='");
        let (k, v) = (k.trim(), v.trim());
        if k == "Count" {
            cur.insert(k.to_string(), v.parse::<u64>().unwrap().to_be_bytes().to_vec());
        } else {
            cur.insert(k.to_string(), hex::decode(v).expect("KAT hex"));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn count(r: &BTreeMap<String, Vec<u8>>) -> u64 {
    u64::from_be_bytes(r["Count"].as_slice().try_into().unwrap())
}

#[test]
fn ascon_aead128_upstream_kat() {
    let recs = records(&oracle("aead128/LWC_AEAD_KAT_128_128.txt"));
    assert_eq!(recs.len(), 1089, "AEAD128 oracle must hold 33 × 33 records");
    for r in &recs {
        let key: [u8; 16] = r["Key"].as_slice().try_into().unwrap();
        let nonce: [u8; 16] = r["Nonce"].as_slice().try_into().unwrap();
        let (pt, ad, ct_tag) = (&r["PT"], &r["AD"], &r["CT"]);
        let (ct, tag) = ct_tag.split_at(ct_tag.len() - 16);
        let tag: [u8; 16] = tag.try_into().unwrap();
        let cipher = AsconAead128::new(key);
        let (got_ct, got_tag) = cipher.encrypt(&nonce, pt, ad).unwrap();
        assert_eq!(got_ct.as_slice(), ct, "AEAD128 ciphertext, Count = {}", count(r));
        assert_eq!(got_tag, tag, "AEAD128 tag, Count = {}", count(r));
        let dec = cipher.decrypt(&nonce, ct, &tag, ad).unwrap();
        assert_eq!(dec.as_slice(), pt.as_slice(), "AEAD128 decrypt, Count = {}", count(r));
        // A flipped tag bit must be rejected.
        let mut bad = tag;
        bad[0] ^= 0x80;
        assert!(cipher.decrypt(&nonce, ct, &bad, ad).is_err(), "AEAD128 forged tag accepted, Count = {}", count(r));
    }
    println!("Ascon-AEAD128 upstream gate: {}/{} records byte-exact", recs.len(), recs.len());
}

#[test]
fn ascon_hash256_upstream_kat() {
    let recs = records(&oracle("hash256/LWC_HASH_KAT_128_256.txt"));
    assert_eq!(recs.len(), 1025, "Hash256 oracle must hold Msg lengths 0..=1024");
    for r in &recs {
        let (msg, md) = (&r["Msg"], &r["MD"]);
        assert_eq!(AsconHash256::hash(msg).as_slice(), md.as_slice(), "Hash256, Count = {}", count(r));
        // Streaming: split at a moving offset.
        let split = (count(r) as usize * 7) % (msg.len() + 1);
        let mut h = AsconHash256::new();
        h.update(&msg[..split]).update(&msg[split..]);
        assert_eq!(h.finalize().as_slice(), md.as_slice(), "Hash256 streaming, Count = {}", count(r));
    }
    println!("Ascon-Hash256 upstream gate: {}/{} records byte-exact", recs.len(), recs.len());
}

#[test]
fn ascon_xof128_upstream_kat() {
    let recs = records(&oracle("xof128/LWC_XOF_KAT_128_512.txt"));
    assert_eq!(recs.len(), 1025, "XOF128 oracle must hold Msg lengths 0..=1024");
    for r in &recs {
        let (msg, md) = (&r["Msg"], &r["MD"]);
        assert_eq!(md.len(), 64);
        assert_eq!(AsconXof128::hash(msg, 64), *md, "XOF128, Count = {}", count(r));
        // Streaming absorb and split squeeze.
        let split = (count(r) as usize * 7) % (msg.len() + 1);
        let cut = (count(r) as usize * 5) % 65;
        let mut x = AsconXof128::new();
        x.update(&msg[..split]).update(&msg[split..]);
        let mut reader = x.finalize_xof();
        let mut got = reader.read(cut);
        got.extend_from_slice(&reader.read(64 - cut));
        assert_eq!(got, *md, "XOF128 streaming (split {split}, cut {cut}), Count = {}", count(r));
        // Shorter and longer outputs are prefixes of the same stream.
        assert_eq!(AsconXof128::hash(msg, 17), md[..17], "XOF128 prefix, Count = {}", count(r));
        assert_eq!(AsconXof128::hash(msg, 100)[..64], md[..], "XOF128 extension, Count = {}", count(r));
    }
    println!("Ascon-XOF128 upstream gate: {}/{} records byte-exact", recs.len(), recs.len());
}

#[test]
fn ascon_cxof128_upstream_kat() {
    let recs = records(&oracle("cxof128/LWC_CXOF_KAT_128_512.txt"));
    assert_eq!(recs.len(), 1089, "CXOF128 oracle must hold 33 Msg × 33 Z lengths");
    for r in &recs {
        let (msg, z, md) = (&r["Msg"], &r["Z"], &r["MD"]);
        assert_eq!(md.len(), 64);
        assert_eq!(AsconCxof128::hash(msg, z, 64).unwrap(), *md, "CXOF128, Count = {}", count(r));
        let split = (count(r) as usize * 7) % (msg.len() + 1);
        let cut = (count(r) as usize * 5) % 65;
        let mut x = AsconCxof128::new(z).unwrap();
        x.update(&msg[..split]).update(&msg[split..]);
        let mut reader = x.finalize_xof();
        let mut got = reader.read(cut);
        got.extend_from_slice(&reader.read(64 - cut));
        assert_eq!(got, *md, "CXOF128 streaming (split {split}, cut {cut}), Count = {}", count(r));
    }
    // Z = "" is CXOF with an empty customization, which is NOT XOF128.
    let empty_z = AsconCxof128::hash(b"", b"", 64).unwrap();
    assert_ne!(empty_z, AsconXof128::hash(b"", 64), "CXOF128(Z=\"\") must differ from XOF128");
    // The 2048-bit limit on Z is enforced, not truncated.
    assert!(AsconCxof128::new(&[0u8; 256]).is_ok());
    assert!(AsconCxof128::new(&[0u8; 257]).is_err());
    println!("Ascon-CXOF128 upstream gate: {}/{} records byte-exact", recs.len(), recs.len());
}
