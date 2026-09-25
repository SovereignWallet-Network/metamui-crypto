# metamui-pbkdf2

PBKDF2 (RFC 8018 §5.2) with HMAC-SHA256 and HMAC-SHA512 in Rust over the
in-tree `metamui-sha2`, verified against the RFC 7914 §11 vectors (RFC 6070's
parameters over HMAC-SHA256), plus the BIP-39 mnemonic-to-seed derivation.

## What is implemented

| entry point | what it does |
|---|---|
| `PBKDF2::pbkdf2_hmac_sha256(password, salt, iterations, key_length)` | derived key of any length |
| `PBKDF2::pbkdf2_hmac_sha512(password, salt, iterations, key_length)` | as above with HMAC-SHA512 |
| `PBKDF2::bip39_mnemonic_to_seed(mnemonic, passphrase)` | `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" ‖ passphrase, 2048, 64)` |

Zero iterations is `PBKDF2Error::InvalidIterations`. Intermediate blocks
are zeroed.

## Usage

```rust
use metamui_pbkdf2::PBKDF2;

let key = PBKDF2::pbkdf2_hmac_sha256(b"password", b"salt", 4096, 32).unwrap();
assert_eq!(key.len(), 32);
let seed = PBKDF2::bip39_mnemonic_to_seed(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "");
assert_eq!(seed.len(), 64);
```

## Features

| feature | default | what it does |
|---|---|---|
| `std` | yes | standard library; without it the crate is `no_std` + `alloc` |

Every code path in this crate is portable scalar Rust; there is no SIMD,
assembly or GPU path and no CPU-feature detection.

## Tests

```
cargo test -p metamui-pbkdf2 --release
```

* `tests/rfc6070_kat.rs` — `test-vectors/pbkdf2/rfc6070-vectors.json`: the
  HMAC-SHA256 section (the RFC 7914 §11 vectors, which are RFC 6070's
  parameters over SHA-256), through `pbkdf2_hmac_sha256`.

A missing vector file fails the run; nothing skips.

## What is and is not claimed

Iteration count, salt and key length are the caller's choice; this crate enforces no minimum beyond one iteration. **No timing or side-channel measurement has been made and no independent
audit has taken place**; treat the code as designed for constant time and
unmeasured. Fault and power attacks are out of scope. See `SECURITY.md`
at the root of the distribution for what a security report should contain.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE` at the root of the
distribution.
