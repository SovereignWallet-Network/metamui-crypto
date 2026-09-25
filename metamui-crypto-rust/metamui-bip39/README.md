# metamui-bip39

BIP-39 mnemonics in Rust: entropy to phrase, phrase to entropy with checksum
verification, and phrase to 64-byte seed (PBKDF2-HMAC-SHA512, 2048
rounds) over the in-tree `metamui-sha2` and `metamui-pbkdf2`, verified
against the Trezor reference vectors.

## What is implemented

| entry point | what it does |
|---|---|
| `Mnemonic::from_entropy(&[u8])` | 16, 20, 24, 28 or 32 bytes of entropy to a 12- to 24-word phrase |
| `Mnemonic::from_phrase(&str)` | parses and checks the checksum; `Error::InvalidChecksum` / `Error::InvalidWord` otherwise |
| `Mnemonic::to_seed(passphrase)` | the BIP-39 seed, `[u8; 64]` |
| `Mnemonic::{to_entropy, phrase, into_phrase, language}` | accessors |
| `Language` | only `English` is implemented; the other variants return `Error::UnsupportedLanguage` |

Entropy is the caller's: this crate has no random source and no seeded
generator.

## Usage

```rust
use metamui_bip39::Mnemonic;

let mnemonic = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
assert_eq!(mnemonic.phrase(),
           "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
let seed = mnemonic.to_seed("TREZOR");
assert_eq!(seed.len(), 64);
```

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | forwards `std` to `metamui-sha2` and `metamui-pbkdf2`; without it the crate is `no_std` + `alloc` |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection. `#![forbid(unsafe_code)]`.

## Tests

```
cargo test -p metamui-bip39 --release
```

* `tests/kat_trezor.rs` — `test-vectors/bip39/bip39-trezor-vectors.json`
  (python-mnemonic): entropy → phrase → seed, both directions, and the
  checksum rejection cases.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

**No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the code as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
