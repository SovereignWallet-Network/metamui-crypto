//! Emit the flat Tier-B oracle for the other language bindings:
//! `test-vectors/falcon-upstream/flat/falcon-tierb.tsv`.
//!
//! Each row replays the NIST CTR_DRBG schedule of the official Round-3 KAT
//! generator for one record of `falcon512/falcon512-KAT.rsp` and writes the
//! derived random inputs next to the upstream answer bytes, so a binding can
//! attempt byte-exact keygen/sign without implementing the DRBG:
//!
//!   variant  count  kg_seed(48)  nonce(40)  sig_seed(48)  msg  pk  sk  esig
//!
//! `esig` is the upstream detached signature in `nist.c` framing
//! (`0x29 ‖ comp(s2)`); the nonce is separate. Run:
//!   cargo run -p metamui-falcon512 --release --example derive_tierb
use std::fmt::Write as _;
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/falcon-upstream");
    let rsp = std::fs::read_to_string(root.join("falcon512/falcon512-KAT.rsp")).expect("falcon512 KAT");
    let mut out = String::from("# Tier-B flat oracle derived from falcon512/falcon512-KAT.rsp (Round 3) by\n");
    out.push_str("# metamui-falcon512 examples/derive_tierb.rs: NIST CTR_DRBG (katrng.c, no DF) replay\n");
    out.push_str("# order = randombytes(kg_seed,48); randombytes(nonce,40); randombytes(sig_seed,48).\n");
    out.push_str("# keygen PRNG = SHAKE256(kg_seed); signing PRNG = SHAKE256(sig_seed). esig = 0x29 || comp(s2).\n");
    out.push_str("variant\tcount\tkg_seed\tnonce\tsig_seed\tmsg\tpk\tsk\tesig\n");

    let mut rec: std::collections::HashMap<&str, String> = Default::default();
    let mut count = 0usize;
    let mut flush = |rec: &mut std::collections::HashMap<&str, String>, out: &mut String| {
        if let (Some(seed), Some(pk), Some(sk), Some(sm)) = (rec.get("seed"), rec.get("pk"), rec.get("sk"), rec.get("sm")) {
            let seed: [u8; 48] = hex::decode(seed).unwrap().try_into().unwrap();
            let inputs = metamui_falcon512::kat_api::derive_kat_inputs(&seed).expect("DRBG");
            let sm = hex::decode(sm).unwrap();
            let sig_len = ((sm[0] as usize) << 8) | sm[1] as usize;
            let nonce = &sm[2..42];
            assert_eq!(nonce, &inputs.nonce[..], "DRBG replay must reproduce the upstream nonce");
            let msg = &sm[42..sm.len() - sig_len];
            let esig = &sm[sm.len() - sig_len..];
            let _ = writeln!(
                out,
                "falcon512\t{count}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                hex::encode(inputs.kg_seed),
                hex::encode(inputs.nonce),
                hex::encode(inputs.sig_seed),
                hex::encode(msg),
                pk,
                sk,
                hex::encode(esig)
            );
            count += 1;
        }
        rec.clear();
    };
    for line in rsp.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            flush(&mut rec, &mut out);
            continue;
        }
        if let Some((k, v)) = line.split_once(" = ") {
            rec.insert(match k { "seed" => "seed", "pk" => "pk", "sk" => "sk", "sm" => "sm", _ => continue }, v.to_string());
        }
    }
    flush(&mut rec, &mut out);
    let dir = root.join("flat");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("falcon-tierb.tsv");
    std::fs::write(&path, out).unwrap();
    println!("wrote {} ({count} records)", path.display());
}
