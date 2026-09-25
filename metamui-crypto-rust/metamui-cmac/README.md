# metamui-cmac

AES-256 CMAC (NIST SP 800-38B) in Rust over the in-tree `metamui-aes-256`,
verified against the Wycheproof AES-CMAC vectors.

## What is implemented

| entry point | what it does |
|---|---|
| `Cmac::mac(key, data)` | one-shot 16-byte tag; the key is 32 bytes |
| `Cmac::verify(key, data, tag)` | constant-shape comparison of a candidate tag |
| `Cmac::new(key)`, `update`, `finalize` | streaming |

Subkeys and state are zeroed on drop.

## Usage

```rust
use metamui_cmac::Cmac;

let key = [0u8; 32];
let tag = Cmac::mac(&key, b"hello").unwrap();
assert!(Cmac::verify(&key, b"hello", &tag).unwrap());

let mut mac = Cmac::new(&key).unwrap();
mac.update(b"hel");
mac.update(b"lo");
assert_eq!(mac.finalize(), tag);
```

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | forwards `std` to the AES and utility crates; without it the crate is `no_std` + `alloc` |
| `native` | no | forwards `native` to `metamui-aes-256` (already its default); a no-op here |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection. `#![forbid(unsafe_code)]`.

## Tests

```
cargo test -p metamui-cmac --release
```

* `tests/kat_vectors.rs` — `test-vectors/cmac/aes-cmac-wycheproof.json`,
  the AES-256 groups of Wycheproof `aes_cmac_test.json`, valid and invalid
  cases.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

The AES core this crate is built on is the portable `metamui-aes-256`; see its README for what it does and does not claim. **No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the code as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
