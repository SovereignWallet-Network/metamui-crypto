# metamui-deoxys

Deoxys-II-256-128 (CAESAR final portfolio, first choice for in-depth
security) in Rust: the Deoxys-BC-384 tweakable block cipher with the
three-part TWEAKEY schedule and the Deoxys-II nonce-misuse-resistant AEAD
mode, verified against the oasisprotocol reference vectors.

## What is implemented

| entry point | what it does |
|---|---|
| `DeoxysII::encrypt(key, nonce, plaintext, ad)` | ciphertext with the 16-byte tag appended |
| `DeoxysII::decrypt(key, nonce, ciphertext, ad)` | plaintext, or `Error::AuthenticationFailed` with nothing released |
| `DeoxysII::generate_key()`, `generate_nonce()` | from the operating system RNG (`std` feature) |
| `KEY_SIZE` = 32, `NONCE_SIZE` = 15, `TAG_SIZE` = 16 | the Deoxys-II-256-128 parameters |

## Usage

```rust
use metamui_deoxys::{DeoxysII, KEY_SIZE, NONCE_SIZE};

let key = [0x42u8; KEY_SIZE];
let nonce = [0x24u8; NONCE_SIZE];
let ciphertext = DeoxysII::encrypt(&key, &nonce, b"hello", b"aad").unwrap();
let plaintext = DeoxysII::decrypt(&key, &nonce, &ciphertext, b"aad").unwrap();
assert_eq!(plaintext, b"hello");
```

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | `generate_key` / `generate_nonce` through `rand`; without it the crate is `no_std` + `alloc` |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection. `#![forbid(unsafe_code)]`. The `deoxys` module is a re-export
of `DeoxysII` kept for older callers; there is no second implementation.

## Tests

```
cargo test -p metamui-deoxys --release
```

* `tests/kat_vectors.rs` — `test-vectors/deoxys/deoxys-oasisprotocol-vectors.json`:
  the oasisprotocol/deoxysii-rust known answers, encrypt and decrypt, plus
  tag-rejection cases.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The AES round function uses table lookups indexed by data-dependent bytes; that is the reference structure and is not claimed to be free of cache-timing effects. **No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the code as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
