use std::env;
use std::fs;
use std::path::Path;

// Turn the BIP-39 English wordlist (src/mnemonic/wordlist/english.txt, a
// checked-in source file) into a Rust array in OUT_DIR. Build scripts must not
// write into the source tree: doing so broke read-only checkouts, `cargo
// package`, and forced consumers (the node's container build) to rsync
// the tree instead of mounting it read-only. The array is always generated —
// it is a few kilobytes — so the include site needs no feature gate.
fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let wordlist_path = Path::new(&manifest_dir).join("src/mnemonic/wordlist/english.txt");
    println!("cargo:rerun-if-changed=src/mnemonic/wordlist/english.txt");

    let content = fs::read_to_string(&wordlist_path).unwrap_or_else(|e| {
        panic!(
            "BIP-39 wordlist missing at {} ({e}); it is a checked-in source file, not a build artefact",
            wordlist_path.display()
        )
    });
    let words: Vec<&str> = content.lines().collect();
    assert_eq!(words.len(), 2048, "BIP-39 English wordlist must have 2048 words");

    let mut array = String::with_capacity(20_000);
    array.push('[');
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            array.push_str(", ");
        }
        assert!(w.chars().all(|c| c.is_ascii_lowercase()), "unexpected character in wordlist entry {i}: {w:?}");
        array.push('"');
        array.push_str(w);
        array.push('"');
    }
    array.push(']');

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    fs::write(Path::new(&out_dir).join("english_array.rs"), array).expect("write english_array.rs to OUT_DIR");
}
